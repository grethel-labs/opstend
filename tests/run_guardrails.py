"""Run the executable acceptance checks listed in docs/guardrails.md."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RULE = re.compile(r"^### (G\d+) .+$", re.MULTILINE)
CHECK = re.compile(r"^- `(tests/[\w/]+\.py::test_\w+)`$", re.MULTILINE)


def collect_checks(markdown: str) -> tuple[int, list[str]]:
    preamble, *sections = RULE.split(markdown)
    if not sections or CHECK.search(preamble):
        raise ValueError("Declare checks under guardrail headings in docs/guardrails.md")

    rules = set()
    checks = {}
    for rule, section in zip(sections[::2], sections[1::2], strict=True):
        if rule in rules:
            raise ValueError(f"Duplicate guardrail {rule}")
        rules.add(rule)
        selectors = CHECK.findall(section)
        if not selectors:
            raise ValueError(f"{rule} requires at least one pytest node ID")
        checks.update(dict.fromkeys(selectors))
    return len(rules), list(checks)


def load_checks() -> tuple[int, list[str]]:
    return collect_checks((ROOT / "docs/guardrails.md").read_text(encoding="utf-8"))


class GuardrailResults:
    def __init__(self) -> None:
        self.unverified: set[str] = set()

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.skipped or hasattr(report, "wasxfail"):
            self.unverified.add(report.nodeid)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-n", "--workers", default="0", help="pytest-xdist worker count or auto")
    args = parser.parse_args()
    try:
        rules, checks = load_checks()
    except ValueError as error:
        print(error)
        return 1
    print(f"Running {len(checks)} test functions for {rules} guardrails", flush=True)
    results = GuardrailResults()
    code = pytest.main(
        ["--strict-markers", "-n", args.workers, "--maxprocesses", "4", *checks],
        plugins=[results],
    )
    for node in sorted(results.unverified):
        print(f"Guardrail must pass without skip or xfail — {node}")
    return code or int(bool(results.unverified))


if __name__ == "__main__":
    raise SystemExit(main())
