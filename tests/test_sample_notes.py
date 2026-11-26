import hashlib
import importlib.util
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest


@pytest.fixture
def server(tmp_path):
    path = Path(__file__).resolve().parents[1] / "sample-app/sample-notes/app.py"
    spec = importlib.util.spec_from_file_location("sample_notes_drill", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.DATA_DIR = str(tmp_path)
    module.DB_PATH = str(tmp_path / "notes.db")
    http = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}", tmp_path
    finally:
        http.shutdown()
        http.server_close()
        thread.join()


def test_attachment_read_is_content_addressed_and_bounded(server):
    address, root = server
    attachments = root / "attachments"
    attachments.mkdir()
    body = b"saved attachment"
    name = hashlib.sha256(body).hexdigest()
    (attachments / name).write_bytes(body)
    with urllib.request.urlopen(address + "/attachments/" + name, timeout=5) as response:  # noqa: S310 - loopback fixture
        assert response.read() == body
        assert response.headers["Content-Type"] == "application/octet-stream"
    (attachments / name).write_bytes(b"wrong content")
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(address + "/attachments/" + name, timeout=5)  # noqa: S310 - loopback fixture
    assert error.value.code == 404


def test_attachment_read_rejects_symlinks_invalid_paths_and_oversize(server):
    address, root = server
    attachments = root / "attachments"
    attachments.mkdir()
    target = root / "secret"
    target.write_bytes(b"private")
    name = hashlib.sha256(b"private").hexdigest()
    (attachments / name).symlink_to(target)
    for suffix in (name, "../secret", "x" * 64):
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(address + "/attachments/" + suffix, timeout=5)  # noqa: S310 - loopback fixture
        assert error.value.code == 404
    (attachments / name).unlink()
    os.link(target, attachments / name)
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(address + "/attachments/" + name, timeout=5)  # noqa: S310 - loopback fixture
    assert error.value.code == 404
    (attachments / name).unlink()
    (attachments / name).write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(address + "/attachments/" + name, timeout=5)  # noqa: S310 - loopback fixture
    assert error.value.code == 404
