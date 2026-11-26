"""Read-only layer verification for the bounded image inventory subprocess."""

from __future__ import annotations

import gzip
import hashlib
import json
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

_MAX_EXPANDED = 2 * 1024**3
_MAX_APK_LINE = 64 * 1024
_APK_DATABASES = {"lib/apk/db/installed", "usr/lib/apk/db/installed"}
_JAVA_ARCHIVES = {".jar", ".war", ".ear", ".par"}


class LayerReader:
    def __init__(self, stream: BinaryIO, remaining: int):
        self.stream = stream
        self.remaining = remaining
        self.hashed = hashlib.sha256()

    def read(self, size: int) -> bytes:
        data = self.stream.read(min(size, self.remaining + 1))
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ValueError("expanded layer limit exceeded")
        self.hashed.update(data)
        return data


def verify_layer(stream: BinaryIO, diff_id: str, remaining: int) -> int:
    reader = LayerReader(stream, remaining)
    with tarfile.open(fileobj=reader, mode="r|") as archive:
        for member in archive:
            path = PurePosixPath(member.name.lstrip("/"))
            if ".." in path.parts or path.suffix.lower() in _JAVA_ARCHIVES:
                raise ValueError("unsupported image layer member")
            if path.as_posix() in _APK_DATABASES:
                if not member.isreg():
                    raise ValueError("unsupported APK database entry")
                # Trivy's APK analyzer drops bufio.Scanner errors after a partial read.
                # Read only this known metadata file in place, without extracting it.
                database = archive.extractfile(member)
                assert database is not None
                with database:
                    while line := database.readline(_MAX_APK_LINE):
                        if len(line) >= _MAX_APK_LINE:
                            raise ValueError("APK database exceeds the scanner's line limit")
    # The OCI DiffID covers the entire uncompressed stream, including tar padding.
    while reader.read(64 * 1024):
        pass
    if "sha256:" + reader.hashed.hexdigest() != diff_id:
        raise ValueError("layer DiffID mismatch")
    return reader.remaining


def main() -> None:
    remaining = _MAX_EXPANDED
    for digest, compressed, diff_id in json.loads(sys.argv[1]):
        path = Path("blobs", "sha256", digest.removeprefix("sha256:"))
        with gzip.open(path, "rb") if compressed else path.open("rb") as stream:
            remaining = verify_layer(stream, diff_id, remaining)


if __name__ == "__main__":
    main()
