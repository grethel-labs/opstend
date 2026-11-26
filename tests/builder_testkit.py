"""Fixtures for builder tests: a fetched commit with a suitable contract, a fake backend."""

from __future__ import annotations

import os
from dataclasses import replace

import yaml

from repo_testkit import POLICY, git, repository
from steward.core import builder as bd
from steward.core import repository_contract as rc
from steward.core.config import BuildPolicy
from steward.core.repositories import fetch_repository

DIGEST = "sha256:" + "a" * 64
OUT = "sha256:" + "b" * 64
FILES = {
    "Dockerfile": f"FROM python@{DIGEST}\nCOPY . /app\n",
    "app.py": "print('hello')\n",
    rc.CONTRACT_FILE: yaml.safe_dump(
        {"container_port": 8080, "data_path": "/data", "backup": {"strategy": "data-path"}}
    ),
}


def prepare(upstream, root, files=None, gitlink=False, **fields):
    """Fetch, propose and return (request, record, proposal)."""
    upstream.commit({**FILES, **(files or {})}, "revision")
    if gitlink:
        git(
            "update-index", "--add", "--cacheinfo",
            "160000,1111111111111111111111111111111111111111,vendor", cwd=upstream.work,
        )  # fmt: skip
        git("commit", "-q", "-m", "gitlink", cwd=upstream.work)
        git("push", "-q", "--force", str(upstream.bare), "HEAD:refs/heads/main", cwd=upstream.work)
    repo = repository(upstream.file_url, **fields)
    record = fetch_repository(repo, root, policy=POLICY)
    proposal = rc.propose_contract(repo, record, root, policy=POLICY)
    return record, proposal


def request_for(record, proposal, root):
    return bd.BuildRequest.create(record, proposal, root)


class FakeBackend:
    """Contract backend: claims a level, never runs anything."""

    def __init__(self, level="ephemeral_vm", *, ready=True, outcome=None, error=None):
        self.level = level
        self.ready = ready
        self.outcome = outcome or bd.BackendOutcome("succeeded", "", OUT, f"reg.invalid/app@{OUT}")
        self.error = error
        self.jobs: list[bd.BuildJob] = []
        self.cleaned: list[str] = []
        self.seen_tree: dict[str, str] = {}
        self.seen_links: dict[str, str] = {}

    def available(self):
        return self.ready, "" if self.ready else "down"

    def build(self, job):
        self.jobs.append(job)
        for path in job.source_dir.rglob("*"):
            if path.is_symlink():
                self.seen_links[str(path.relative_to(job.source_dir))] = os.readlink(path)
            elif path.is_file():
                self.seen_tree[str(path.relative_to(job.source_dir))] = path.read_text()
        if self.error:
            raise self.error
        return self.outcome

    def cleanup(self, job_id):
        self.cleaned.append(job_id)


def policy(**fields):
    return BuildPolicy.model_validate(fields)


def limits(**fields):
    return replace(bd.BuildLimits(), **fields)
