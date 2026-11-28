"""Weekly maintenance windows in a named time zone.

A window like "Sun 02:00 for 3h, Europe/Berlin" stays at 02:00 local time
across daylight saving changes. Disruptive automatic work (reboots, updates)
only starts inside an open window.
"""

from __future__ import annotations

from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

from pydantic import Field, field_validator

from opstend.core.models import Model

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class Window(Model):
    name: str = "default"
    days: list[str] = Field(default_factory=lambda: ["sun"])
    start: time = time(2, 0)
    duration_minutes: int = 180
    timezone: str = "Europe/Berlin"

    @field_validator("days")
    @classmethod
    def _days(cls, value: list[str]) -> list[str]:
        days = [d.lower()[:3] for d in value]
        unknown = [d for d in days if d not in DAYS]
        if unknown or not days:
            raise ValueError(f"days must be a non-empty subset of {DAYS}")
        return days

    @field_validator("duration_minutes")
    @classmethod
    def _duration(cls, value: int) -> int:
        if not 5 <= value <= 24 * 60:
            raise ValueError("duration must be between 5 minutes and 24 hours")
        return value

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str) -> str:
        ZoneInfo(value)
        return value

    def _occurrences(self, around: datetime) -> list[tuple[datetime, datetime]]:
        tz = ZoneInfo(self.timezone)
        local = around.astimezone(tz)
        out = []
        for delta in range(-2, 9):
            day = (local + timedelta(days=delta)).date()
            if DAYS[day.weekday()] not in self.days:
                continue
            start = datetime.combine(day, self.start, tzinfo=tz)
            out.append((start, start + timedelta(minutes=self.duration_minutes)))
        return out

    def is_open(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return any(start <= now < end for start, end in self._occurrences(now))

    def next_open(self, now: datetime | None = None) -> tuple[datetime, datetime]:
        now = now or datetime.now(UTC)
        for start, end in self._occurrences(now):
            if end > now:
                return (max(start, now), end)
        raise RuntimeError("no window within the next week")  # pragma: no cover

    def remaining(self, now: datetime | None = None) -> timedelta:
        now = now or datetime.now(UTC)
        for start, end in self._occurrences(now):
            if start <= now < end:
                return end - now
        return timedelta(0)
