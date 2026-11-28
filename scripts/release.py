"""Compute the next version and release notes from Conventional Commits.

Usage: python scripts/release.py  ->  prints JSON {"release": bool, "version": "...", "notes": "..."}

Rules (pre-1.0): `feat` and breaking changes bump the minor version, `fix`, `perf`,
`security` and `refactor` bump the patch version. Other types (docs, chore, ci, test,
build, style) do not create a release. The first release uses the version in
src/opstend/__init__.py.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TYPES = {"feat": "Features", "fix": "Fixes", "perf": "Performance", "security": "Security",
         "refactor": "Changes"}
SUBJECT = re.compile(r"^(?P<type>\w+)(?:\((?P<scope>[^)]+)\))?(?P<bang>!)?: (?P<text>.+)$")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True,
                          text=True).stdout.strip()


def current_base() -> tuple[str | None, tuple[int, int, int]]:
    tags = [t for t in git("tag", "--list", "v*", "--sort=-v:refname").splitlines() if t]
    if tags:
        major, minor, patch = (int(x) for x in tags[0].lstrip("v").split("-")[0].split("."))
        return tags[0], (major, minor, patch)
    text = (ROOT / "src/opstend/__init__.py").read_text()
    version = re.search(r'__version__ = "([^"]+)"', text)
    assert version
    major, minor, patch = (int(x) for x in version.group(1).split("."))
    return None, (major, minor, patch)


def main() -> int:
    tag, (major, minor, patch) = current_base()
    log = git("log", "--format=%H%x1f%s%x1f%b%x1e", f"{tag}..HEAD" if tag else "HEAD")
    sections: dict[str, list[str]] = {}
    bump = 0  # 0 none, 1 patch, 2 minor, 3 major
    for record in log.split("\x1e"):
        if not record.strip():
            continue
        sha, subject, body = (record.strip().split("\x1f") + ["", ""])[:3]
        m = SUBJECT.match(subject)
        if not m:
            continue
        kind = m.group("type")
        breaking = bool(m.group("bang")) or "BREAKING CHANGE" in body
        if breaking:
            bump = max(bump, 3)
        elif kind == "feat":
            bump = max(bump, 2)
        elif kind in TYPES:
            bump = max(bump, 1)
        if kind in TYPES or breaking:
            scope = f"**{m.group('scope')}**: " if m.group("scope") else ""
            sections.setdefault("Breaking changes" if breaking else TYPES[kind], []).append(
                f"- {scope}{m.group('text')} ({sha[:7]})")
    if tag is None:
        version = f"{major}.{minor}.{patch}"
        release = True
    elif bump == 0:
        print(json.dumps({"release": False, "version": tag.lstrip("v"), "notes": ""}))
        return 0
    elif bump == 3 and major >= 1:
        version = f"{major + 1}.0.0"
        release = True
    elif bump >= 2:
        version = f"{major}.{minor + 1}.0"
        release = True
    else:
        version = f"{major}.{minor}.{patch + 1}"
        release = True
    order = ["Breaking changes", "Features", "Security", "Fixes", "Performance", "Changes"]
    notes = "\n\n".join(f"### {name}\n" + "\n".join(sections[name]) for name in order
                        if name in sections) or "First release of the rebuilt OpsTend."
    print(json.dumps({"release": release, "version": version, "notes": notes}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
