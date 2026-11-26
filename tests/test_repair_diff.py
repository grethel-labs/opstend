"""R05: strict diff parsing, the protected-path policy and re-derived change sets."""

from __future__ import annotations

import pytest

from coding_testkit import GOOD_DIFF, REPAIR_FILES, make_diff
from steward.core.builder import BuildError
from steward.core.repair_diff import DiffLimits, PathPolicy, check_diff, parse_diff

ALLOWED = PathPolicy(("requirements.txt",))


def code_of(call):
    with pytest.raises(BuildError) as info:
        call()
    return info.value.code


@pytest.fixture
def trees(tmp_path):
    base = tmp_path / "base"
    for name, text in REPAIR_FILES.items():
        (base / name).parent.mkdir(parents=True, exist_ok=True)
        (base / name).write_text(text)
    spool = tmp_path / "spool"
    spool.mkdir()
    return base, tmp_path / "patched", spool


def check(trees, diff, policy=ALLOWED, **kw):
    base, patched, spool = trees
    return check_diff(diff, base, patched, spool, policy, **kw)


def test_a_dependency_bump_in_scope_is_accepted_and_applied(trees):
    (change,) = check(trees, GOOD_DIFF)
    assert (change.path, change.kind, change.added, change.removed) == (
        "requirements.txt",
        "modify",
        1,
        1,
    )
    assert "flask==2.0.3" in (trees[1] / "requirements.txt").read_text()
    assert "flask==2.0.0" in (trees[0] / "requirements.txt").read_text()  # base untouched


@pytest.mark.parametrize(
    ("path", "code"),
    [
        (".github/workflows/ci.yml", "protected_path"),
        ("CODEOWNERS", "protected_path"),
        ("docs/CODEOWNERS", "protected_path"),
        ("steward.contract.yml", "protected_path"),
        ("AGENTS.md", "protected_path"),
        (".agents/skills/steward-executor/SKILL.md", "protected_path"),
        ("docs/guardrails.md", "protected_path"),
        ("docs/working-guidelines.md", "protected_path"),
        (".CLAUDE/settings.json", "protected_path"),
        ("src/steward/core/builder.py", "protected_path"),
        (".gitattributes", "protected_path"),
        ("tests/test_app.py", "test_or_policy_file"),
        ("pytest.ini", "test_or_policy_file"),
        ("pkg/tests/test_x.py", "test_or_policy_file"),
        ("app.py", "outside_task_scope"),
    ],
)
def test_the_agent_cannot_touch_its_approval_chain_tests_or_other_code(trees, path, code):
    old = {path: REPAIR_FILES.get(path, "x = 1\n")}
    diff = make_diff(old, {path: old[path] + "# changed\n"})
    # even a task that allows everything cannot touch protected or test files
    policy = ALLOWED if code == "outside_task_scope" else PathPolicy(("**",))
    assert code_of(lambda: check(trees, diff, policy)) == code


def test_new_test_files_are_additions_not_modifications(trees):
    diff = make_diff({}, {"tests/test_new.py": "def test_x():\n    pass\n"})
    assert check(trees, diff, PathPolicy(("tests/**",)))[0].kind == "add"


def test_operators_can_only_extend_the_deny_list(trees):
    policy = PathPolicy(("requirements.txt",), extra_deny=("requirements.txt",))
    assert code_of(lambda: check(trees, GOOD_DIFF, policy)) == "protected_path"


@pytest.mark.parametrize(
    "diff",
    [
        b"",
        b"hello\n",
        b"diff --git a/requirements.txt b/requirements.txt\n--- a/requirements.txt\n",
        b"diff --git a/a b/a\nrename from a\nrename to b\n",
        b"diff --git a/a b/a\nold mode 100644\nnew mode 100755\n",
        b"diff --git a/a b/a\nnew file mode 120000\n--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+x\n",
        b"diff --git a/a b/a\nnew file mode 100755\n--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+x\n",
        b"diff --git a/a b/a\nnew file mode 100644\nBinary files /dev/null and b/a differ\n",
        b"diff --git a/../x b/../x\n--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n",
        b"diff --git a/.git/config b/.git/config\n--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-a\n+b\n",
        b'diff --git "a/x y" "b/x y"\n',
        b"diff --git a/x b/y\n--- a/x\n+++ b/y\n@@ -1 +1 @@\n-a\n+b\n",
        b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n+c\n",
        b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\nunexpected\n",
        b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b",
        b"diff --git a/x b/x\nsurprise header\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
        b"\0diff",
    ],
)
def test_anything_but_plain_text_changes_is_refused(diff):
    with pytest.raises(BuildError):
        parse_diff(diff)


def test_a_header_hidden_inside_a_hunk_is_content_not_a_second_file():
    inner = (
        b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n a\n"
        b"+diff --git a/.github/ci.yml b/.github/ci.yml\n"
    )
    (only,) = parse_diff(inner)
    assert only.path == "x"


def test_size_file_and_line_bounds(trees):
    assert code_of(lambda: parse_diff(GOOD_DIFF, DiffLimits(max_bytes=50))) == "diff_too_large"
    assert code_of(lambda: parse_diff(GOOD_DIFF, DiffLimits(max_changed_lines=1))) == (
        "diff_too_many_lines"
    )
    many = make_diff({}, {f"f{i}.txt": "x\n" for i in range(3)})
    assert code_of(lambda: parse_diff(many, DiffLimits(max_files=2))) == "diff_too_many_files"


def test_a_diff_that_does_not_apply_to_the_exact_source_is_refused(trees):
    stale = make_diff({"requirements.txt": "flask==1.0\n"}, {"requirements.txt": "flask==2.0.3\n"})
    assert code_of(lambda: check(trees, stale)) == "apply_failed"


def test_deleting_an_in_scope_file_is_a_visible_change(trees):
    diff = make_diff({"requirements.txt": REPAIR_FILES["requirements.txt"]}, {})
    (change,) = check(trees, diff)
    assert change.kind == "delete" and not (trees[1] / "requirements.txt").exists()
