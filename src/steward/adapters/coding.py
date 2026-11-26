"""Coding-agent and forge adapter contracts for isolated repair (R05).

A *coding agent* proposes a source change for one validated finding. It is the least
trusted component in the system: it runs only in the isolated builder tier under its own
identity and credential scope, sees a copy of the source and nothing else (no production
secrets, data, host sockets, shell tools or executor access), and everything it returns
is untrusted text. Its only product is a unified diff; the repair pipeline
(``core/repair.py``) checks the diff, applies it to a scratch copy and lets the
independent R04 validator decide. The result is a pull request or a local patch, never a
deployment.

Implement :class:`CodingAgentRunner` for a supported agent and :class:`ForgeClient` for a
code host; run the shared contract cases in ``tests/test_coding_contract.py`` against the
implementation. A forge client can only *open* a pull request: the protocol has no merge,
approve or push-to-protected-branch operation, so nothing built on it can approve itself.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

AGENT_STATUSES = ("succeeded", "failed", "timeout", "limit_exceeded", "crashed", "refused")
IDENTITY = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
SCOPE = re.compile(r"^[a-z][a-z0-9:_-]{1,63}$")
# Credential scope words that would give an agent production reach. Never acceptable.
FORBIDDEN_SCOPES = ("production", "prod", "executor", "root", "deploy", "approver", "validator")

Level = Literal["ephemeral_vm", "external_ci", "container_rootless"]


@dataclass(frozen=True)
class AgentLimits:
    """Budgets reserved before the agent starts. Any breach stops it and fails the job."""

    timeout_s: float = 900
    memory_mb: int = 2048
    pids: int = 256
    log_bytes: int = 256 * 1024
    diff_bytes: int = 256 * 1024
    max_tokens: int = 200_000


@dataclass(frozen=True)
class RepairTask:
    """The scoped, bounded assignment handed to the agent. Built only by the toolkit."""

    job_id: str
    application: str
    service: str
    advisory: str
    instruction: str  # fixed toolkit text; finding fields are quoted data inside it
    finding: dict
    source_dir: Path  # a private copy of the exact fetched tree; the agent may edit it
    allowed_paths: tuple[str, ...]  # the only paths a diff may touch
    limits: AgentLimits
    on_poll: Callable[[], bool] | None = None  # lease heartbeat; False when the lease is lost


@dataclass
class AgentOutcome:
    """What a runner reports. Every field is untrusted until the pipeline checks it."""

    status: str
    code: str = ""
    diff: bytes = b""
    log: bytes = b""
    notes: str = ""  # the agent's own summary; shown only as quoted, untrusted text
    input_tokens: int | None = None
    output_tokens: int | None = None
    usage: dict = field(default_factory=dict)


class CodingAgentRunner(Protocol):
    """A coding agent confined to one isolation tier.

    ``identity`` and ``credential_scope`` name who the agent is and what its (provider)
    credential may reach; they must differ from the builder, validator and approver
    identities. ``level`` is the isolation tier the run really happens in, never what a
    request asked for.
    """

    level: Level
    identity: str
    credential_scope: str

    def available(self) -> tuple[bool, str]:
        """(ready, reason). A runner that cannot prove its isolation is not ready."""

    def run(self, task: RepairTask) -> AgentOutcome:
        """Edit the working copy and return a unified diff. Must honor ``task.limits``."""

    def cleanup(self, job_id: str) -> None:
        """Destroy only what this runner created for ``job_id``. Idempotent."""


@dataclass(frozen=True)
class PullRequestRef:
    """Observed forge values, with repository identifying the same-repository head and target."""

    id: str
    url: str
    head_branch: str
    head_commit: str
    repository: str | None = None
    base_branch: str | None = None


class ForgeClient(Protocol):
    """Opens pull requests with the repository authority it was configured with.

    Report repository, branches and the full head commit from actual forge data.
    The head and target must both belong to the requested repository. Refuse foreign
    or ambiguous heads. Branch creation is confined to opening a repair PR.
    The protocol exposes no general staging, push, merge, approval or branch-protection
    operations.
    """

    identity: str

    def find_pull_request(self, repository: str, head_branch: str) -> PullRequestRef | None:
        """Return the observed open request for this head or None when absent.

        Surface conflicts through the observed fields or raise if ambiguous.
        Filtering out a wrong base or head commit would hide a conflict.
        """

    def open_pull_request(
        self,
        repository: str,
        *,
        base_branch: str,
        base_commit: str,
        head_branch: str,
        expected_head_commit: str,
        title: str,
        body: str,
        patch: bytes,
    ) -> PullRequestRef:
        """Create the repair head from ``base_commit`` and ``patch``, then open a PR.

        Verify the candidate commit against ``expected_head_commit`` before creating
        the branch. Create the branch only if absent, or resume from an existing
        same-repository branch at that exact commit. Leave conflicting refs untouched.

        Open only if the forge can enforce the exact head commit and configured
        repository and base branch during creation. Concurrent attempts must reuse
        the same exact open PR or fail without opening a duplicate. Raise on any
        conflict or if these guarantees are unavailable. Return the observed PR fields.
        """


def check_identities(runner: CodingAgentRunner, *, others: dict[str, str]) -> str | None:
    """Reason the runner may not be used, or None.

    ``others`` maps a role (builder, validator, approver, forge) to its identity; the agent
    must be distinct from all of them and hold no production-reaching credential scope.
    """
    if not IDENTITY.fullmatch(str(runner.identity)):
        return "bad_identity"
    if not SCOPE.fullmatch(str(runner.credential_scope)):
        return "bad_credential_scope"
    if any(word in re.split(r"[:_-]", runner.credential_scope) for word in FORBIDDEN_SCOPES):
        return "credential_scope_reaches_production"
    if runner.identity in others.values():
        return "identity_not_distinct"
    return None
