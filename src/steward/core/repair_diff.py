"""Inspect and apply an agent's proposed diff under a fixed path policy (R05).

The diff is untrusted text. It is parsed strictly (only plain ``diff --git`` sections of
text files; no renames, copies, mode changes, symlinks, submodules or binary data),
bounded, and applied to a scratch copy of the exact source. The set of files that
*really* changed is then recomputed from the two trees and must equal what the diff
claimed, so a parser/applier disagreement cannot hide a change from the policy.

Path policy (deny always wins; an operator may only add to the deny list):

- the agent's approval chain and controls: CI definitions, code owners, the workload
  contract, agent instruction files, Git metadata/hooks, and the toolkit's own control
  code (``src/steward``, ``ansible``, ``schemas``);
- test and policy configuration: existing test files and test-runner configuration
  cannot be modified, deleted or renamed, so a patch cannot be made to pass by weakening
  its checks;
- everything else must lie inside the task's allowed paths (by default the manifests and
  lockfiles that declare the vulnerable component).

Nothing here executes repository content or touches a host.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .builder import BuildError
from .repositories import FetchPolicy, git_env
from .repository_contract import CONTRACT_FILE

# Protected for every task and every repository. Matched case-insensitively; patterns
# without a slash match a file or directory name at any depth.
PROTECTED = (
    ".github/**", ".gitlab/**", ".gitlab-ci.yml", ".circleci/**", ".buildkite/**",
    "azure-pipelines.yml", "Jenkinsfile", ".drone.yml", ".travis.yml", "bitbucket-pipelines.yml",
    "CODEOWNERS", ".git", ".git/**", ".gitmodules", ".gitattributes", ".githooks/**",
    ".husky/**", ".pre-commit-config.yaml", CONTRACT_FILE, "AGENTS.md", "CLAUDE.md",
    ".agents/**", ".claude/**", ".cursor/**", ".cursorrules", "SECURITY.md",
    "CONTRIBUTING.md", "docs/guardrails.md", "docs/working-guidelines.md",
    "src/steward/**", "ansible/**", "schemas/**",
)  # fmt: skip
# Existing files matching these can be neither modified, deleted nor renamed.
TEST_FILES = (
    "**/tests/**", "**/test/**", "**/__tests__/**", "**/spec/**", "conftest.py", "test_*.py",
    "*_test.py",
    "*_test.go", "*.test.js", "*.test.ts", "*.spec.js", "*.spec.ts", "pytest.ini", "tox.ini",
    "noxfile.py", ".coveragerc", "jest.config.*", "vitest.config.*", ".eslintrc*", "ruff.toml",
    ".ruff.toml", "mypy.ini", "codecov.yml", ".codecov.yml", "sonar-project.properties",
)  # fmt: skip

MAX_PATH = 300
HEADER_PREFIXES = (
    "index ", "new file mode ", "deleted file mode ", "similarity index ", "old mode ",
    "new mode ", "rename from ", "rename to ", "copy from ", "copy to ", "dissimilarity index ",
)  # fmt: skip
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")


@dataclass(frozen=True)
class DiffLimits:
    max_bytes: int = 256 * 1024
    max_files: int = 20
    max_changed_lines: int = 2000
    max_tree_bytes: int = 256 * 2**20


@dataclass(frozen=True)
class FileChange:
    path: str
    kind: str  # add | modify | delete
    added: int = 0
    removed: int = 0


@dataclass(frozen=True)
class PathPolicy:
    allowed: tuple[str, ...]
    extra_deny: tuple[str, ...] = ()

    def reason(self, change: FileChange) -> str | None:
        """Why this change is refused, or None."""
        path = change.path
        if any(_glob(p, True).fullmatch(path) for p in (*PROTECTED, *self.extra_deny)):
            return "protected_path"
        if change.kind != "add" and any(_glob(p, True).fullmatch(path) for p in TEST_FILES):
            return "test_or_policy_file"
        if not any(_glob(p, False).fullmatch(path) for p in self.allowed):
            return "outside_task_scope"
        return None


_glob_cache: dict[tuple[str, bool], re.Pattern] = {}


def _glob(pattern: str, ignore_case: bool) -> re.Pattern:
    key = (pattern, ignore_case)
    if key not in _glob_cache:
        out, i = "", 0
        while i < len(pattern):
            if pattern.startswith("**/", i):
                out, i = out + "(?:.*/)?", i + 3
            elif pattern.startswith("/**", i) and i + 3 == len(pattern):
                out, i = out + "(?:/.*)?", i + 3
            elif pattern.startswith("**", i):
                out, i = out + ".*", i + 2
            elif pattern[i] == "*":
                out, i = out + "[^/]*", i + 1
            elif pattern[i] == "?":
                out, i = out + "[^/]", i + 1
            else:
                out, i = out + re.escape(pattern[i]), i + 1
        if ignore_case and "/" not in pattern.rstrip("*"):
            out = "(?:.*/)?" + out  # a bare name matches at any depth
        _glob_cache[key] = re.compile(out, re.IGNORECASE if ignore_case else 0)
    return _glob_cache[key]


def safe_path(path: str) -> bool:
    parts = path.split("/")
    return not (
        not path or len(path) > MAX_PATH or path.startswith("/") or path.endswith("/")
        or any(p in ("", ".", "..") or p.lower() == ".git" for p in parts)
        or any(ord(c) < 32 or ord(c) == 127 or c in '"\\\t' for c in path)
    )  # fmt: skip


def _reject(code: str, detail: str = "") -> BuildError:
    return BuildError(code, detail)


# --- strict parser ---------------------------------------------------------------------


def parse_diff(data: bytes, limits: DiffLimits = DiffLimits()) -> list[FileChange]:  # noqa: B008
    """Parse ``git diff`` output of plain text changes; raise BuildError on anything else."""
    if not data.strip():
        raise _reject("empty_diff")
    if len(data) > limits.max_bytes:
        raise _reject("diff_too_large", f"{len(data)} bytes")
    if b"\0" in data:
        raise _reject("binary_diff")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _reject("diff_not_utf8") from None
    if not text.endswith("\n"):
        raise _reject("bad_diff", "missing final newline")
    lines = text[:-1].split("\n")
    changes: list[FileChange] = []
    seen: set[str] = set()
    i = 0
    while i < len(lines):
        head = lines[i]
        if not head.startswith("diff --git a/"):
            raise _reject("bad_diff", f"line {i + 1}: expected a file header")
        rest = head[len("diff --git a/") :]
        half = (len(rest) - 3) // 2
        path = rest[:half]
        if len(rest) < 5 or rest != f"{path} b/{path}" or not safe_path(path):
            raise _reject("bad_diff_path", head[:120].encode("unicode_escape").decode())
        if path.lower() in seen:
            raise _reject("bad_diff", "a file appears twice")
        seen.add(path.lower())
        i += 1
        kind, old_marker, new_marker = "modify", f"--- a/{path}", f"+++ b/{path}"
        while i < len(lines) and not lines[i].startswith("--- "):
            line = lines[i]
            if line.startswith(("Binary files", "GIT binary patch")):
                raise _reject("binary_diff", path)
            if not line.startswith(HEADER_PREFIXES):
                raise _reject("bad_diff", f"{path}: unexpected header")
            if line.startswith(("rename ", "copy ", "similarity ", "dissimilarity ")):
                raise _reject("rename_or_copy", path)
            if line.startswith(("old mode ", "new mode ")):
                raise _reject("mode_change", path)
            if line.startswith("new file mode "):
                if line != "new file mode 100644":
                    raise _reject("unsafe_mode", path)
                kind, old_marker = "add", "--- /dev/null"
            elif line.startswith("deleted file mode "):
                if line not in ("deleted file mode 100644", "deleted file mode 100755"):
                    raise _reject("unsafe_mode", path)
                kind, new_marker = "delete", "+++ /dev/null"
            i += 1
        if i + 1 >= len(lines) or lines[i] != old_marker or lines[i + 1] != new_marker:
            raise _reject("bad_diff", f"{path}: ---/+++ lines do not match the header")
        i += 2
        added = removed = hunks = 0
        while i < len(lines) and lines[i].startswith("@@"):
            match = HUNK.fullmatch(lines[i])
            if not match:
                raise _reject("bad_diff", f"{path}: bad hunk header")
            old_n = int(match.group(2) if match.group(2) is not None else 1)
            new_n = int(match.group(4) if match.group(4) is not None else 1)
            i += 1
            hunks += 1
            while old_n > 0 or new_n > 0 or (i < len(lines) and lines[i].startswith("\\")):
                if i >= len(lines):
                    raise _reject("bad_diff", f"{path}: truncated hunk")
                line = lines[i]
                tag = line[:1]
                if tag == " ":
                    old_n, new_n = old_n - 1, new_n - 1
                elif tag == "-":
                    old_n, removed = old_n - 1, removed + 1
                elif tag == "+":
                    new_n, added = new_n - 1, added + 1
                elif not line.startswith("\\ "):
                    raise _reject("bad_diff", f"{path}: bad hunk line")
                if old_n < 0 or new_n < 0:
                    raise _reject("bad_diff", f"{path}: hunk longer than declared")
                i += 1
        if hunks == 0:
            raise _reject("bad_diff", f"{path}: no content change")
        if kind == "add" and removed or kind == "delete" and added:
            raise _reject("bad_diff", f"{path}: inconsistent add/delete")
        changes.append(FileChange(path, kind, added, removed))
        if len(changes) > limits.max_files:
            raise _reject("diff_too_many_files", str(len(changes)))
    if sum(c.added + c.removed for c in changes) > limits.max_changed_lines:
        raise _reject("diff_too_many_lines")
    return changes


# --- applying and re-deriving the change set --------------------------------------------


def apply_diff(base: Path, patched: Path, diff: bytes, spool: Path, policy: FetchPolicy) -> None:
    """Copy ``base`` to ``patched`` and apply ``diff`` there with ``git apply`` (no hooks)."""
    shutil.copytree(base, patched, symlinks=True)
    patch = spool / "agent.diff"
    fd = os.open(patch, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(diff)
    argv = [
        policy.git_binary, "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=true",
        "apply", "--whitespace=nowarn", str(patch),
    ]  # fmt: skip
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv, cwd=patched, env=git_env(policy, spool), stdin=subprocess.DEVNULL,
            capture_output=True, timeout=60, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        raise _reject("apply_failed", "git apply did not run") from None
    if result.returncode != 0:
        raise _reject("apply_failed", "the diff does not apply to the exact source")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot(root: Path, max_bytes: int) -> dict[str, tuple]:
    """path -> (kind, executable, content); symlinks and special files are visible."""
    out: dict[str, tuple] = {}
    total = 0
    for current, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted([*dirs, *files]):
            full = Path(current) / name
            rel = full.relative_to(root).as_posix()
            info = full.lstat()
            if stat.S_ISLNK(info.st_mode):
                out[rel] = ("link", False, os.readlink(full))
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                if total > max_bytes:
                    raise _reject("tree_too_large")
                out[rel] = ("file", bool(info.st_mode & 0o111), _sha(full))
            elif not stat.S_ISDIR(info.st_mode):
                out[rel] = ("special", False, "")
    return out


def actual_changes(
    base: Path, patched: Path, limits: DiffLimits = DiffLimits()
) -> list[FileChange]:  # noqa: B008
    """What differs between the two trees. Links, special files and mode changes refuse."""
    before, after = (
        _snapshot(base, limits.max_tree_bytes),
        _snapshot(patched, limits.max_tree_bytes),
    )
    changes = []
    for path in sorted(before.keys() | after.keys()):
        old, new = before.get(path), after.get(path)
        if old == new:
            continue
        for item in (old, new):
            if item is not None and item[0] in ("link", "special"):
                raise _reject("unsafe_file_type", path)
        if old is not None and new is not None and old[1] != new[1]:
            raise _reject("mode_change", path)
        if old is None and new is not None and new[1]:
            raise _reject("unsafe_mode", path)
        kind = "add" if old is None else "delete" if new is None else "modify"
        changes.append(FileChange(path, kind))
    return changes


def check_diff(
    diff: bytes,
    base: Path,
    patched: Path,
    spool: Path,
    policy: PathPolicy,
    *,
    limits: DiffLimits = DiffLimits(),  # noqa: B008
    fetch_policy: FetchPolicy | None = None,
) -> list[FileChange]:
    """Full inspection. Returns the verified change set or raises BuildError(code)."""
    claimed = parse_diff(diff, limits)
    for change in claimed:  # refuse before anything touches a file
        if (code := policy.reason(change)) is not None:
            raise _reject(code, change.path)
    apply_diff(base, patched, diff, spool, fetch_policy or FetchPolicy())
    real = actual_changes(base, patched, limits)
    if [(c.path, c.kind) for c in real] != sorted((c.path, c.kind) for c in claimed):
        raise _reject("diff_mismatch", "the applied change differs from the diff's own claim")
    for change in real:
        if (code := policy.reason(change)) is not None:
            raise _reject(code, change.path)
    return [
        FileChange(r.path, r.kind, c.added, c.removed)
        for r in real
        for c in claimed
        if c.path == r.path
    ]
