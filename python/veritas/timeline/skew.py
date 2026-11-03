"""Timezone normalization and clock-skew correction.

Parsers emit UTC nanoseconds. Two corrections are applied at ingest time:

1. **Local-time artifacts.** Some artifacts store local wall-clock time without an offset
   (FAT directory entries, many text logs). The parser marks these with ``timezone=None`` and
   ``attrs['time_is_local']=True``; :func:`localize` converts them using the host timezone
   recovered from the registry (``TimeZoneInformation``) or supplied by the examiner.
2. **Clock skew.** The acquisition entry records the measured offset between the host clock and
   a trusted reference (``TimeSource.offset_ms``). Event logs and other host-clock artifacts are
   shifted by ``-offset`` so that evidence from several hosts lines up. The shift is recorded in
   ``Event.skew_ns`` so it is visible, reversible and reported.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .schema import NS, Event


@dataclass(frozen=True, slots=True)
class HostClock:
    """Per-evidence clock model."""

    evidence_sha256: str
    tz_name: str | None = None
    skew_ns: int = 0  # host clock minus reference clock

    def zone(self) -> ZoneInfo | None:
        if not self.tz_name:
            return None
        try:
            return ZoneInfo(self.tz_name)
        except ZoneInfoNotFoundError:
            return None


WINDOWS_TZ_TO_IANA = {
    "Pacific Standard Time": "America/Los_Angeles",
    "Mountain Standard Time": "America/Denver",
    "Central Standard Time": "America/Chicago",
    "Eastern Standard Time": "America/New_York",
    "GMT Standard Time": "Europe/London",
    "W. Europe Standard Time": "Europe/Berlin",
    "Romance Standard Time": "Europe/Paris",
    "Central Europe Standard Time": "Europe/Budapest",
    "Central European Standard Time": "Europe/Warsaw",
    "E. Europe Standard Time": "Europe/Chisinau",
    "FLE Standard Time": "Europe/Kiev",
    "Russian Standard Time": "Europe/Moscow",
    "Turkey Standard Time": "Europe/Istanbul",
    "Israel Standard Time": "Asia/Jerusalem",
    "Arabian Standard Time": "Asia/Dubai",
    "India Standard Time": "Asia/Kolkata",
    "China Standard Time": "Asia/Shanghai",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Korea Standard Time": "Asia/Seoul",
    "AUS Eastern Standard Time": "Australia/Sydney",
    "New Zealand Standard Time": "Pacific/Auckland",
    "UTC": "UTC",
    "Coordinated Universal Time": "UTC",
    "South Africa Standard Time": "Africa/Johannesburg",
    "SA Pacific Standard Time": "America/Bogota",
    "E. South America Standard Time": "America/Sao_Paulo",
    "Hawaiian Standard Time": "Pacific/Honolulu",
    "Alaskan Standard Time": "America/Anchorage",
    "Singapore Standard Time": "Asia/Singapore",
}


def windows_tz_to_iana(name: str) -> str | None:
    return WINDOWS_TZ_TO_IANA.get(name)


def local_to_utc_ns(naive_ns: int, zone: ZoneInfo) -> int:
    """Interpret a UTC-labelled nanosecond value as local wall time in `zone` and return true UTC."""
    secs, rem = divmod(naive_ns, NS)
    wall = datetime.fromtimestamp(secs, tz=timezone.utc).replace(tzinfo=None, microsecond=0)
    local = wall.replace(tzinfo=zone)
    return int(local.timestamp()) * NS + rem


def localize(event: Event, clock: HostClock) -> Event:
    if event.attrs.get("time_is_local") and event.timestamp is not None:
        zone = clock.zone()
        if zone is not None:
            event.timestamp = local_to_utc_ns(event.timestamp, zone)
            event.timezone = clock.tz_name
            event.attrs = {k: v for k, v in event.attrs.items() if k != "time_is_local"}
    return event


def apply_skew(event: Event, clock: HostClock) -> Event:
    """Shift host-clock timestamps by the measured offset; idempotent via ``skew_ns``."""
    if event.timestamp is None or clock.skew_ns == 0 or event.skew_ns != 0:
        return event
    if event.attrs.get("time_source") == "external":
        return event  # already from a reference clock (e.g. cloud provider), do not shift
    event.timestamp = event.timestamp - clock.skew_ns
    event.skew_ns = -clock.skew_ns
    return event


def normalize(events: Iterable[Event], clocks: dict[str, HostClock]) -> Iterator[Event]:
    for e in events:
        clock = clocks.get(e.evidence_sha256)
        if clock is not None:
            e = apply_skew(localize(e, clock), clock)
        yield e
