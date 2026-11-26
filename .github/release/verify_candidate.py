"""Verify the exact unsigned release payload and record its CI source and digest."""

from __future__ import annotations

import argparse
import json
import os
import re
import tarfile
import tempfile
import zlib
from pathlib import Path

from steward import release

ReleaseError = release.ReleaseError
LOCKS = ("uv.lock", "webapp/package-lock.json")


def _requirement_lines(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]


def verify_candidate(archive: Path, root: Path, source_sha: str, host_export: Path) -> dict:
    """Check the archive against the clean checkout and an independent host export."""
    try:
        if not re.fullmatch("[0-9a-f]{40}", source_sha) or release.source_state(root) != {
            "commit": source_sha,
            "dirty": False,
        }:
            raise ReleaseError("checkout is dirty or does not match the dispatch SHA")

        with tempfile.TemporaryDirectory(prefix="steward-candidate-") as scratch:
            payload = release._extract_archive(archive, Path(scratch), strict=True)
            if (payload / release.SIGNATURE).exists():
                raise ReleaseError("candidate must be unsigned")

            report = release.VerifyReport()
            manifest_path = payload / release.MANIFEST
            manifest = release._load_json(manifest_path, report, release.MANIFEST)
            release._check_release_content(payload, manifest, False, report)
            if not report.ok:
                raise ReleaseError("\n".join(report.errors))

            provenance_path = payload / release.PROVENANCE
            statement = release._load_json(provenance_path, report, release.PROVENANCE)
            predicate = statement["predicate"]
            if predicate["runDetails"]["metadata"]["source_commit"] != source_sha:
                raise ReleaseError("provenance source commit differs from the checkout")

            hashes = {name: release.sha256_file(root / name) for name in LOCKS}
            expected = [
                {"name": name, "digest": {"sha256": digest}}
                for name, digest in sorted(hashes.items())
            ]
            if predicate["buildDefinition"].get("resolvedDependencies") != expected:
                raise ReleaseError("provenance lock hashes differ from the checkout")

            if _requirement_lines(payload / "requirements.txt") != _requirement_lines(host_export):
                raise ReleaseError("candidate requirements differ from the frozen host export")

            return {
                "version": report.version,
                "file_count": report.file_count,
                "archive": archive.name,
                "archive_sha256": release.sha256_file(archive),
                "manifest_sha256": release.sha256_file(manifest_path),
                "provenance_sha256": release.sha256_file(provenance_path),
                "lock_sha256": hashes,
                "host_requirements_sha256": manifest["files"]["requirements.txt"],
            }
    except (
        OSError,
        tarfile.TarError,
        EOFError,
        zlib.error,
        ValueError,
        OverflowError,
        RecursionError,
        KeyError,
        TypeError,
    ) as exc:
        raise ReleaseError(f"cannot verify candidate ({type(exc).__name__})") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("host_export", type=Path)
    args = parser.parse_args()

    source_sha = os.environ["GITHUB_SHA"]
    workflow_sha = os.environ["GITHUB_WORKFLOW_SHA"]
    if source_sha != workflow_sha:
        parser.exit(1, "error: workflow SHA differs from the dispatch SHA\n")
    try:
        receipt = verify_candidate(args.archive, Path.cwd(), source_sha, args.host_export)
    except ReleaseError as exc:
        parser.exit(1, f"error: {exc}\n")

    receipt.update(
        source_sha=source_sha,
        workflow_sha=workflow_sha,
        controller_requirements_sha256=release.sha256_file(Path("requirements/controller.txt")),
        repository=os.environ["GITHUB_REPOSITORY"],
        ref=os.environ["GITHUB_REF"],
        run_id=os.environ["GITHUB_RUN_ID"],
        run_attempt=os.environ["GITHUB_RUN_ATTEMPT"],
    )
    args.archive.with_name("receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksum = args.archive.with_name(f"{args.archive.name}.sha256")
    checksum.write_text(f"{receipt['archive_sha256']}  {args.archive.name}\n", encoding="utf-8")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        summary.write(
            "### Verified unsigned release payload\n\n"
            f"- Source SHA: `{source_sha}`\n"
            f"- Workflow SHA: `{workflow_sha}`\n"
            f"- Run: {receipt['run_id']} (attempt {receipt['run_attempt']})\n"
            f"- Inner tar.gz SHA-256: `{receipt['archive_sha256']}`\n"
            f"- Manifest SHA-256: `{receipt['manifest_sha256']}`\n"
        )


if __name__ == "__main__":
    main()
