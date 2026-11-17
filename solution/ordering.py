"""Closed integer intervals in nanoseconds.

Two kinds of interval appear in the tool and they must not be confused:

``possible``
    The set of UTC instants at which one event may have happened, given its
    own clock reading and its host's calibration.  Closed on both ends.

``feasible``
    The range the solver actually allows for the event after the precedence
    constraints are taken into account.  Also closed, intersected with the
    possible interval.

All arithmetic is on Python integers (nanoseconds), so no feasibility question
is ever decided by floating point rounding.

Whether one interval is *before* another is **not** used to claim an order on
its own: two events are ordered only when the constraint system proves it
(see :mod:`solution.constraints`).  This module deliberately exposes no
"compare two events" helper, because such a helper invites exactly the
wall-clock sorting the task forbids.
"""

from __future__ import annotations

from dataclasses import dataclass

from .timeutil import format_rfc3339_ns


@dataclass(frozen=True, order=True)
class Interval:
    """Closed integer interval ``[lo, hi]``."""

    lo: int
    hi: int

    def __post_init__(self) -> None:
        if self.lo > self.hi:
            raise ValueError(f"empty interval [{self.lo},{self.hi}]")

    def intersect(self, other: "Interval") -> "Interval | None":
        lo = max(self.lo, other.lo)
        hi = min(self.hi, other.hi)
        return None if lo > hi else Interval(lo, hi)

    def contains(self, value: int) -> bool:
        return self.lo <= value <= self.hi

    def overlaps(self, other: "Interval") -> bool:
        return self.lo <= other.hi and other.lo <= self.hi

    def strictly_before(self, other: "Interval") -> bool:
        """Every instant of ``self`` precedes every instant of ``other``.

        This is a statement about the two *intervals*, not about the events:
        it is exposed for reporting, and the solver never uses it to decide an
        order between events.
        """
        return self.hi < other.lo

    def width(self) -> int:
        return self.hi - self.lo

    def to_json(self) -> dict:
        return {
            "lo_ns": self.lo,
            "hi_ns": self.hi,
            "lo": format_rfc3339_ns(self.lo),
            "hi": format_rfc3339_ns(self.hi),
            "width_ns": self.width(),
        }
