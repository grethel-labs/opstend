"""The M6 gate probe itself, exercised against a loopback fake (no provider, no VM)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from conftest import ROOT
from test_inference_adapters import FakeServer, OllamaD, jbody

SPEC = importlib.util.spec_from_file_location(
    "m6_ai_probe", ROOT / "tests" / "integration" / "gates" / "m6_ai_probe.py"
)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


@pytest.fixture
def server():
    fake = FakeServer()
    yield fake
    fake.close()


def write_config(tmp_path: Path, port: int) -> Path:
    data = yaml.safe_load((ROOT / "examples" / "server.api.yml").read_text())
    data["ai"] = {
        "provider": "ollama",
        "model": "test-model:1b",
        "base_url": f"http://127.0.0.1:{port}",
        "budget": {"monthly": {"tokens": 100000}},
    }
    path = tmp_path / "config.yml"
    path.write_text(yaml.safe_dump(data))
    return path


def answer(count: int):
    text = json.dumps({"item_count": count, "newest_source": "controller"})
    return OllamaD().ok(text)


def test_probe_reports_checks_and_stays_synthetic(server, tmp_path, capsys):
    server.script = [
        (200, {}, jbody({"models": [{"name": "test-model:1b"}]})),
        answer(3),
        answer(4),
    ]
    code = probe.main(
        [
            "--config",
            str(write_config(tmp_path, server.port)),
            "--workdir",
            str(tmp_path / "w"),
            "--items",
            "3",
        ]
    )
    record = json.loads(capsys.readouterr().out)
    assert code == 0 and record["checks"] == {
        "models_listed": True,
        "configured_model_available": True,
        "clean_answer_correct": True,
        "hostile_text_not_obeyed": True,
    }
    assert record["data_class"] == "local" and record["ledger"]["tokens"] == 120
    sent = json.dumps([r["body"] for r in server.requests if r["body"]])
    assert "synthetic status line" in sent and "delete_everything" in sent  # hostile text is data
    assert "api_key" not in json.dumps(record).lower()


def test_probe_fails_when_the_answer_is_wrong_or_model_missing(server, tmp_path, capsys):
    server.script = [(200, {}, jbody({"models": []})), answer(999), answer(999)]
    code = probe.main(
        ["--config", str(write_config(tmp_path, server.port)), "--workdir", str(tmp_path / "w")]
    )
    record = json.loads(capsys.readouterr().out)
    assert code == 1 and not record["checks"]["configured_model_available"]
    assert not record["checks"]["clean_answer_correct"]


def test_probe_rejects_unusable_input(tmp_path, capsys):
    assert probe.main(["--config", str(tmp_path / "missing.yml"), "--workdir", str(tmp_path)]) == 2
    assert probe.main(["--config", "x", "--workdir", str(tmp_path), "--items", "0"]) == 2
