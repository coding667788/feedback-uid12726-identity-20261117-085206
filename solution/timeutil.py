"""Exact time arithmetic.

All instants are handled as integer nanoseconds since the Unix epoch (UTC).
Nanoseconds keep every sample value exact and keep the constraint solver on
integers, so feasibility results are exact rather than floating point
approximations.  Calendar conversion reuses :mod:`datetime` for civil time
rules (leap years, month lengths) and treats every day as exactly 86400 s.
"""

from __future__ import annotations

import datetime as _dt
import re

NS = 1
US = 1_000
MS = 1_000_000
SECOND = 1_000_000_000
MINUTE = 60 * SECOND
HOUR = 60 * MINUTE
DAY = 24 * HOUR

_MAX_DAYS = 100_000_000  # ~273 000 years; keeps arithmetic in a sane range

_RFC3339 = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"[Tt ](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<offset>[Zz]|[+-]\d{2}:\d{2})\Z"
)

_EPOCH_ORDINAL = _dt.date(1970, 1, 1).toordinal()


class TimestampError(ValueError):
    """Raised when a text timestamp cannot be parsed."""


def parse_rfc3339_ns(text: str) -> int:
    """Parse an RFC 3339 timestamp into integer nanoseconds since the epoch.

    Accepted: ``YYYY-MM-DDTHH:MM:SS[.frac]`` followed by ``Z`` or a signed
    ``+HH:MM`` offset, ASCII digits only, 1..9 fractional digits.  Leap second
    ``:60`` is rejected rather than silently normalised.
    """
    if not isinstance(text, str):
        raise TimestampError(f"timestamp must be a string, got {type(text).__name__}")
    if not text.isascii():
        raise TimestampError("timestamp contains non-ASCII characters")
    m = _RFC3339.match(text)
    if not m:
        raise TimestampError(f"not an RFC 3339 timestamp: {text!r}")
    year = int(m.group("year"))
    month = int(m.group("month"))
    day = int(m.group("day"))
    hour = int(m.group("hour"))
    minute = int(m.group("minute"))
    second = int(m.group("second"))
    if year < 1:
        raise TimestampError(f"year out of range: {text!r}")
    if not (1 <= month <= 12):
        raise TimestampError(f"month out of range: {text!r}")
    if not (1 <= day <= 31):
        raise TimestampError(f"day out of range: {text!r}")
    try:
        date = _dt.date(year, month, day)
    except ValueError as exc:
        raise TimestampError(f"invalid calendar date in {text!r}: {exc}") from None
    if hour > 23:
        raise TimestampError(f"hour out of range: {text!r}")
    if minute > 59:
        raise TimestampError(f"minute out of range: {text!r}")
    if second > 59:
        raise TimestampError(
            f"second out of range (leap seconds are not accepted): {text!r}"
        )
    fraction = m.group("fraction") or ""
    nanos = int(fraction.ljust(9, "0")) if fraction else 0
    offset = m.group("offset")
    if offset in ("Z", "z"):
        offset_ns = 0
    else:
        sign = 1 if offset[0] == "+" else -1
        off_h = int(offset[1:3])
        off_m = int(offset[4:6])
        if off_h > 23 or off_m > 59:
            raise TimestampError(f"timezone offset out of range: {text!r}")
        offset_ns = sign * (off_h * HOUR + off_m * MINUTE)
    days = date.toordinal() - _EPOCH_ORDINAL
    return (((days * 24 + hour) * 60 + minute) * 60 + second) * SECOND + nanos - offset_ns


def format_rfc3339_ns(value: int) -> str:
    """Render integer nanoseconds as an RFC 3339 UTC (``Z``) timestamp."""
    if not isinstance(value, int):
        raise TimestampError("nanoseconds must be an integer")
    days, rest = divmod(value, DAY)
    ordinal = _EPOCH_ORDINAL + days
    if not (1 <= ordinal <= _dt.date.max.toordinal()):
        # Outside datetime's chronological range: fall back to a plain day count.
        return f"day{days:+d}T{rest // HOUR:02d}:{rest % HOUR // MINUTE:02d}:{rest % MINUTE // SECOND:02d}"
    date = _dt.date.fromordinal(ordinal)
    hour, rest = divmod(rest, HOUR)
    minute, rest = divmod(rest, MINUTE)
    second, nanos = divmod(rest, SECOND)
    base = f"{date.isoformat()}T{hour:02d}:{minute:02d}:{second:02d}"
    if nanos:
        return base + "." + f"{nanos:09d}".rstrip("0") + "Z"
    return base + "Z"
