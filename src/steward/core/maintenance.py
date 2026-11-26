"""Maintenance windows and work admission (ADR 0002 section 8).

Pure functions over aware datetimes: the caller supplies the clock, so every rule
is testable with a fake clock. Nothing here mutates the host. Controller health
restarts are not maintenance and never consult this module.

Rules:
- The regular window is one real hour (UTC arithmetic) starting at the configured
  local weekday and wall time. A local time skipped by a DST gap starts after the
  gap; an ambiguous local time uses its first occurrence.
- Work is admitted only if it fits before the window ends; otherwise it waits for
  the next window. Work longer than one hour never fits and is reported as such.
- An emergency window opens only for a critical reason, after the configured
  notice. Ordinary updates cannot open one.
- The known-exploited exception needs a vulnerability source fact and network
  reachability; a model proposal alone never grants it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from zoneinfo import ZoneInfo

DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
WINDOW_DURATION = timedelta(hours=1)
CLOCK_SKEW_TOLERANCE = timedelta(minutes=5)

WorkKind = Literal["routine", "reboot"]
EmergencyReason = Literal["critical_vulnerability", "isolation_lost", "imminent_data_loss"]
EMERGENCY_REASONS: tuple[str, ...] = (
    "critical_vulnerability",
    "isolation_lost",
    "imminent_data_loss",
)


@dataclass(frozen=True)
class Window:
    start: datetime  # aware, UTC
    end: datetime

    def contains(self, moment: datetime) -> bool:
        return self.start <= moment < self.end


@dataclass(frozen=True)
class EmergencyWindow:
    reason: str
    announced_at: datetime
    window: Window


@dataclass(frozen=True)
class Admission:
    allowed: bool
    reason: str
    window: Window | None = None
    retry_at: datetime | None = None


def parse_window_spec(spec: str) -> tuple[int, int, int, ZoneInfo]:
    """Parse 'Sun 03:00 Europe/Berlin' into weekday, hour, minute and zone."""
    parts = spec.split(" ")
    if len(parts) != 3 or parts[0] not in DAYS:
        raise ValueError("weekly_window must look like 'Sun 03:00 Europe/Berlin'")
    clock = parts[1]
    if len(clock) != 5 or clock[2] != ":" or not (clock[:2] + clock[3:]).isdigit():
        raise ValueError("weekly_window needs a 24-hour HH:MM time")
    hour, minute = int(clock[:2]), int(clock[3:])
    if hour > 23 or minute > 59:
        raise ValueError("weekly_window time is out of range")
    try:
        zone = ZoneInfo(parts[2])
    except (KeyError, ValueError, OSError):
        raise ValueError(f"unknown time zone {parts[2]!r}") from None
    return DAYS.index(parts[0]), hour, minute, zone


def _aware_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("maintenance clock values must be timezone-aware")
    return moment.astimezone(UTC)


def _window_on(day, hour: int, minute: int, zone: ZoneInfo) -> Window:
    local = datetime(day.year, day.month, day.day, hour, minute, tzinfo=zone)
    start = local.astimezone(UTC)
    return Window(start, start + WINDOW_DURATION)


def regular_window(spec: str, now: datetime) -> Window:
    """The regular window containing `now`, else the next one that starts."""
    weekday, hour, minute, zone = parse_window_spec(spec)
    now_utc = _aware_utc(now)
    local_day = now_utc.astimezone(zone).date()
    # Scan from the day before (a window may straddle local midnight) through the
    # next 8 days; the first window ending after `now` is the answer.
    for offset in range(-1, 9):
        day = local_day + timedelta(days=offset)
        if day.weekday() != weekday:
            continue
        window = _window_on(day, hour, minute, zone)
        if window.end > now_utc:
            return window
    raise AssertionError("a weekly window always exists within eight days")


def admit(
    spec: str,
    now: datetime,
    *,
    work_seconds: int,
    kind: WorkKind = "routine",
    allow_reboot: bool = False,
    emergency: EmergencyWindow | None = None,
) -> Admission:
    """Decide whether planned work may start now. Never starts anything itself."""
    if work_seconds <= 0:
        raise ValueError("work_seconds must be positive")
    now_utc = _aware_utc(now)
    if kind == "reboot" and not allow_reboot:
        return Admission(False, "reboot_not_permitted")
    duration = timedelta(seconds=work_seconds)
    if duration > WINDOW_DURATION:
        return Admission(False, "exceeds_window_duration")

    candidates: list[tuple[Window, str]] = []
    if emergency is not None:
        if emergency.announced_at - now_utc > CLOCK_SKEW_TOLERANCE:
            return Admission(False, "clock_inconsistent")
        candidates.append((emergency.window, "emergency"))
    candidates.append((regular_window(spec, now_utc), "regular"))

    inside = False
    for window, label in candidates:
        if window.contains(now_utc):
            if now_utc + duration <= window.end:
                return Admission(True, f"{label}_window", window)
            inside = True
    upcoming = [w for w, _ in candidates if w.start > now_utc]
    if inside:
        later = regular_window(spec, max(w.end for w, _ in candidates if w.contains(now_utc)))
        upcoming.append(later)
    nxt = min(upcoming, key=lambda w: w.start)
    return Admission(
        False, "does_not_fit_before_window_end" if inside else "outside_window", nxt, nxt.start
    )


def plan_emergency_window(now: datetime, *, reason: str, notice_minutes: int) -> EmergencyWindow:
    """Announce an unscheduled window. Only critical reasons qualify."""
    if reason not in EMERGENCY_REASONS:
        raise ValueError(f"{reason!r} cannot open an emergency window")
    if notice_minutes < 1:
        raise ValueError("notice_minutes must be positive")
    announced = _aware_utc(now)
    start = announced + timedelta(minutes=notice_minutes)
    return EmergencyWindow(reason, announced, Window(start, start + WINDOW_DURATION))


def immediate_exposure_removal(
    *, enabled: bool, known_exploited: bool, network_reachable: bool
) -> bool:
    """The single no-notice exception: known-exploited and network-reachable."""
    return enabled and known_exploited and network_reachable
