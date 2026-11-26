from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from steward.core import canonical
from steward.core.config import ConfigError, effective, load_config_file, parse_config
from steward.core.maintenance import (
    admit,
    immediate_exposure_removal,
    plan_emergency_window,
    regular_window,
)

SPEC = "Sun 03:00 Europe/Berlin"


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


def test_window_is_one_hour_on_configured_local_time():
    # 2026-11-22 is a Sunday; Berlin is UTC+1 in November.
    window = regular_window(SPEC, utc(2026, 11, 21, 12, 0))
    assert window.start == utc(2026, 11, 22, 2, 0)
    assert window.end == utc(2026, 11, 22, 3, 0)


def test_current_window_is_returned_while_inside_and_next_after_end():
    inside = regular_window(SPEC, utc(2026, 11, 22, 2, 30))
    assert inside.start == utc(2026, 11, 22, 2, 0)
    after = regular_window(SPEC, utc(2026, 11, 22, 3, 0))
    assert after.start == utc(2026, 11, 29, 2, 0)


def test_window_straddling_utc_midnight_is_found_from_the_previous_day():
    window = regular_window("Mon 00:30 Pacific/Auckland", utc(2026, 11, 22, 11, 45))
    # Auckland is UTC+13 in November: Monday 00:30 local = Sunday 11:30 UTC.
    assert window.start == utc(2026, 11, 22, 11, 30)
    assert window.contains(utc(2026, 11, 22, 11, 45))


def test_dst_spring_forward_keeps_one_real_hour():
    # 2027-03-28: 02:00-03:00 Berlin does not exist. 02:30 resolves after the gap.
    window = regular_window("Sun 02:30 Europe/Berlin", utc(2027, 3, 27, 0, 0))
    assert window.start == utc(2027, 3, 28, 1, 30)
    assert window.end - window.start == timedelta(hours=1)


def test_dst_fall_back_uses_first_occurrence_once():
    # 2026-10-25: 02:30 Berlin happens twice; the first (CEST, UTC+2) is used.
    window = regular_window("Sun 02:30 Europe/Berlin", utc(2026, 10, 24, 0, 0))
    assert window.start == utc(2026, 10, 25, 0, 30)
    after = regular_window("Sun 02:30 Europe/Berlin", window.end)
    assert after.start == utc(2026, 11, 1, 1, 30)


def test_offset_changes_between_summer_and_winter():
    summer = regular_window(SPEC, utc(2026, 7, 1))
    winter = regular_window(SPEC, utc(2026, 12, 1))
    assert summer.start.hour == 1  # UTC+2
    assert winter.start.hour == 2  # UTC+1


@pytest.mark.parametrize(
    "spec",
    [
        "Sun 3:00 Europe/Berlin",
        "Foo 03:00 Europe/Berlin",
        "Sun 24:00 Europe/Berlin",
        "Sun 03:00 Mars/Base",
        "Sun 03:00",
        "Sun 03:60 UTC",
        "Sun 03:00 Europe/Berlin x",
    ],
)
def test_invalid_window_specs_are_rejected(spec):
    with pytest.raises(ValueError):
        regular_window(spec, utc(2026, 11, 21))


def test_naive_clock_values_are_rejected():
    with pytest.raises(ValueError):
        regular_window(SPEC, datetime(2026, 11, 21))
    with pytest.raises(ValueError):
        admit(SPEC, datetime(2026, 11, 22, 2, 0), work_seconds=60)


def test_admission_inside_window_when_work_fits():
    result = admit(SPEC, utc(2026, 11, 22, 2, 10), work_seconds=1200)
    assert result.allowed and result.reason == "regular_window"


def test_admission_at_exact_window_end_boundary():
    assert admit(SPEC, utc(2026, 11, 22, 2, 40), work_seconds=1200).allowed
    late = admit(SPEC, utc(2026, 11, 22, 2, 40, 1), work_seconds=1200)
    assert not late.allowed
    assert late.reason == "does_not_fit_before_window_end"
    assert late.retry_at == utc(2026, 11, 29, 2, 0)


def test_admission_outside_window_names_next_start():
    result = admit(SPEC, utc(2026, 11, 21, 12, 0), work_seconds=60)
    assert not result.allowed and result.reason == "outside_window"
    assert result.retry_at == utc(2026, 11, 22, 2, 0)


def test_work_longer_than_a_window_never_fits():
    result = admit(SPEC, utc(2026, 11, 22, 2, 0), work_seconds=3601)
    assert not result.allowed and result.reason == "exceeds_window_duration"
    assert result.retry_at is None


def test_reboot_needs_explicit_consent_even_inside_window():
    now = utc(2026, 11, 22, 2, 0)
    assert admit(SPEC, now, work_seconds=60, kind="reboot").reason == "reboot_not_permitted"
    assert admit(SPEC, now, work_seconds=60, kind="reboot", allow_reboot=True).allowed


def test_emergency_window_opens_only_after_notice_and_only_for_critical_reasons():
    now = utc(2026, 11, 24, 10, 0)
    emergency = plan_emergency_window(now, reason="critical_vulnerability", notice_minutes=60)
    assert emergency.window.start == utc(2026, 11, 24, 11, 0)
    before = admit(SPEC, utc(2026, 11, 24, 10, 59), work_seconds=60, emergency=emergency)
    assert not before.allowed and before.retry_at == emergency.window.start
    during = admit(SPEC, utc(2026, 11, 24, 11, 0), work_seconds=60, emergency=emergency)
    assert during.allowed and during.reason == "emergency_window"
    over = admit(SPEC, utc(2026, 11, 24, 11, 59), work_seconds=120, emergency=emergency)
    assert not over.allowed and over.reason == "does_not_fit_before_window_end"
    with pytest.raises(ValueError):
        plan_emergency_window(now, reason="routine_update", notice_minutes=60)


def test_emergency_announced_in_the_future_is_clock_inconsistent():
    emergency = plan_emergency_window(
        utc(2026, 11, 24, 12, 0), reason="isolation_lost", notice_minutes=15
    )
    result = admit(SPEC, utc(2026, 11, 24, 11, 0), work_seconds=60, emergency=emergency)
    assert not result.allowed and result.reason == "clock_inconsistent"


@pytest.mark.parametrize(
    ("enabled", "exploited", "reachable", "expected"),
    [
        (True, True, True, True),
        (False, True, True, False),
        (True, False, True, False),
        (True, True, False, False),
    ],
)
def test_known_exploited_exception_needs_all_facts(enabled, exploited, reachable, expected):
    assert (
        immediate_exposure_removal(
            enabled=enabled, known_exploited=exploited, network_reachable=reachable
        )
        is expected
    )


def _base() -> dict:
    return {
        "schema_version": 1,
        "server": {"name": "box", "host": "203.0.113.10", "user": "ops"},
        "admin": {"token_ref": "env:STEWARD_TOKEN"},
    }


def test_config_without_maintenance_keeps_its_revision():
    cfg = parse_config(_base())
    assert cfg.maintenance is None
    assert "maintenance" not in effective(cfg)


def test_config_maintenance_policy_round_trips_with_defaults():
    data = {**_base(), "maintenance": {"weekly_window": SPEC}}
    cfg = parse_config(data)
    assert cfg.maintenance.emergency.notice_minutes == 60
    assert cfg.maintenance.emergency.immediate_if_known_exploited is True
    assert cfg.maintenance.allow_reboot is False
    assert effective(cfg)["maintenance"]["weekly_window"] == SPEC
    assert canonical.revision_id(effective(cfg)) != canonical.revision_id(
        effective(parse_config(_base()))
    )


@pytest.mark.parametrize(
    "policy",
    [
        {},
        {"weekly_window": "Sun 03:00 Nowhere/City"},
        {"weekly_window": SPEC, "emergency": {"notice_minutes": 5}},
        {"weekly_window": SPEC, "unknown": 1},
        {"weekly_window": SPEC, "drills": ["restart", "restart"]},
    ],
)
def test_config_rejects_invalid_maintenance_policy(policy):
    with pytest.raises(ConfigError):
        parse_config({**_base(), "maintenance": policy}, allow_unavailable=True)


def test_drills_are_unavailable_until_l11():
    data = {**_base(), "maintenance": {"weekly_window": SPEC, "drills": ["restart"]}}
    with pytest.raises(ConfigError, match="maintenance.drills"):
        parse_config(data)
    assert parse_config(data, allow_unavailable=True).maintenance.drills == ["restart"]


def test_examples_still_load():
    from steward.core.config import ROOT_EXAMPLES

    for path in sorted(ROOT_EXAMPLES.glob("*.yml")):
        load_config_file(path, allow_unavailable=True)
