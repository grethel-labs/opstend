"""Client behavior of `call()` when the executor dies or is slow (found on a host, L06)."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from steward.executor.protocol import ExecutorError, call


def serve(path, behavior):
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)

    def run():
        conn, _ = server.accept()
        with conn:
            conn.recv(65536)
            behavior(conn)
        server.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def test_dropped_connection_is_unavailable_with_unknown_outcome(tmp_path):
    path = tmp_path / "s.sock"
    thread = serve(path, lambda conn: None)  # killed executor: closes without a word
    with pytest.raises(ExecutorError) as caught:
        call("platform_status", socket_path=str(path))
    thread.join(2)
    assert caught.value.error_class == "unavailable" and caught.value.outcome_unknown


def test_partial_response_is_unavailable_not_malformed(tmp_path):
    path = tmp_path / "s.sock"
    thread = serve(path, lambda conn: conn.sendall(b'{"ok": tr'))
    with pytest.raises(ExecutorError) as caught:
        call("platform_status", socket_path=str(path))
    thread.join(2)
    assert caught.value.error_class == "unavailable"


def test_client_timeout_is_marked_unknown(tmp_path):
    path = tmp_path / "s.sock"
    thread = serve(path, lambda conn: time.sleep(0.5))
    with pytest.raises(ExecutorError) as caught:
        call("platform_status", socket_path=str(path), timeout=0.1)
    thread.join(2)
    assert caught.value.error_class == "unavailable" and caught.value.outcome_unknown


def test_unreachable_socket_is_unavailable_and_known_not_executed(tmp_path):
    with pytest.raises(ExecutorError) as caught:
        call("platform_status", socket_path=str(tmp_path / "missing.sock"))
    assert caught.value.error_class == "unavailable" and not caught.value.outcome_unknown


def test_malformed_complete_line_stays_internal(tmp_path):
    path = tmp_path / "s.sock"
    thread = serve(path, lambda conn: conn.sendall(b"not json\n"))
    with pytest.raises(ExecutorError) as caught:
        call("platform_status", socket_path=str(path))
    thread.join(2)
    assert caught.value.error_class == "internal"
