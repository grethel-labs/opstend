"""Fixtures for R04: a built candidate, fake validator-side registry/probe/scanner."""

from __future__ import annotations

from pathlib import Path

from builder_testkit import OUT, FakeBackend, policy, prepare, request_for
from steward.core import artifact_validation as av
from steward.core import builder as bd
from steward.core.vulnerabilities import ScanResult
from update_support import APPROVER, NOW, SIGNER

BUILD_REF = f"reg.invalid/app@{OUT}"


class FakeRegistry:
    def __init__(self, digest=OUT, **facts):
        self.facts = {"manifest_digest": digest, "sbom": [], "base_images": [], **facts}
        self.inspected: list[str] = []
        self.copies: list[tuple[str, str]] = []
        self.copy_result: str | Exception | None = None
        self.error: Exception | None = None

    def inspect(self, ref):
        self.inspected.append(ref)
        if self.error:
            raise self.error
        return av.ArtifactFacts(**self.facts)

    def copy(self, source_ref, target_ref):
        self.copies.append((source_ref, target_ref))
        if isinstance(self.copy_result, Exception):
            raise self.copy_result
        return self.copy_result or target_ref.rsplit("@", 1)[1]


class FakeProbe:
    def __init__(self, **over):
        self.base = {
            "started": True,
            "uid": 10001,
            "read_only_rootfs": True,
            "privileged": False,
            "capabilities": [],
            "host_network": False,
            "engine_socket": False,
            "listening_ports": [8080],
            "health_status": 200,
            "data_writable": True,
            "egress_reachable": [],
            "data_readable": True,
            "data_migrated": False,
        }
        self.base.update(over)
        self.previous: dict = {}
        self.calls: list[bool] = []

    def run(self, image_ref, contract, *, with_previous_data):
        self.calls.append(with_previous_data)
        data = {**self.base, **(self.previous if with_previous_data else {})}
        return av.ProbeResult(**data)


class FakeScanner:
    def __init__(self, state="not_affected", checked_at=NOW - 60, only: str | None = None):
        self.state, self.checked_at, self.only = state, checked_at, only
        self.subjects: list = []
        self.drop = False

    def scan(self, subjects, *, inventory_revision, now):
        self.subjects = list(subjects)
        if self.drop:
            return []
        out = []
        for subject in subjects:
            state = self.state if self.only in (None, subject.kind) else "not_affected"
            confirmed = state == "confirmed"
            out.append(
                ScanResult(
                    source="trivy",
                    inventory_revision=inventory_revision,
                    subject=subject,
                    checked_at=self.checked_at,
                    state=state,
                    findings=(
                        [{"id": "CVE-2026-0001", "summary": "x", "severity": "critical"}]
                        if confirmed
                        else []
                    ),
                    complete=state in ("confirmed", "not_affected"),
                )
            )
        return out


def build_candidate(upstream, fetch_root, build_root, files=None, **backend):
    """fetch -> propose -> build with a fake backend. Returns (request, record)."""
    record, proposal = prepare(upstream, fetch_root, files=files)
    assert proposal.state == "suitable", proposal.reasons
    request = request_for(record, proposal, fetch_root)
    runner = bd.BuildRunner(
        build_root, policy(allow_container_isolation=True), [FakeBackend(**backend)]
    )
    return request, runner.run(request)


def make_validator(root: Path, build_root: Path, **over):
    parts = {
        "registry": FakeRegistry(),
        "probe": FakeProbe(),
        "scanner": FakeScanner(),
        "signer": av.Signer("ci-signer", SIGNER),
    }
    parts.update(over)
    validator = av.ArtifactValidator(root, builder_root=build_root, **parts)
    return validator, parts


APPROVER_SIGNER = av.Signer("ops-approver", APPROVER)
