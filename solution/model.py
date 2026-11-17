"""Reconstruction model: evidence -> difference constraints.

Unknowns
--------
One integer variable ``t_X`` per accepted event: the true UTC instant of the
event, in nanoseconds since the epoch.

Facts that become constraints
-----------------------------
1. **Wall clock + calibration.**  A boot record states that the host clock was
   off by some amount drawn from a closed interval ``[lo, hi]``, so the event
   happened at ``t = wall - offset`` and therefore

       ``wall - hi <= t_X <= wall - lo``

   That closed interval is the event's *possible UTC interval* — the honest
   representation of "the host says 10:00:00 but its clock may be 2 s fast or
   1 s slow".

2. **Monotonic + sequence inside one boot.**  Sequence numbers give a strict
   order.  The monotonic counter additionally bounds elapsed real time:
   for ``seq_A < seq_B`` on the same boot,

       ``t_B - t_A >= (mono_B - mono_A) - drift``

   with ``drift = ceil(|mono_B - mono_A| * drift_ppm / 1e6)`` (0 by default).
   This is what makes a wall-clock rollback detectable: the wall readings
   claim B happened before A while the monotonic counter says time moved
   forward by a known amount.

   **Monotonic counters are never compared across boots.**  A reboot resets
   the counter, so ``boot_id`` is part of the variable's identity and no
   constraint ever spans two boots through ``mono_ns``.  The only cross-boot
   evidence is wall calibration, message send/receive and an optional declared
   reboot order.

3. **Message causality.**  A ``send`` strictly precedes the matching ``recv``.
   A message id with anything other than exactly one send and one receive
   endpoint contributes no constraint and is reported instead.

4. **Declared reboot order.**  If a boot record carries ``follows``, the last
   sequence-numbered event of the previous boot strictly precedes the first
   event of this boot.  This is *declared* evidence; the tool never infers a
   reboot order from wall clocks or counters.

Everything above has the shape ``t_v - t_u <= w``, so the whole reconstruction
is one simple temporal problem solved exactly in :mod:`solution.constraints`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .collect import Collection
from .constraints import EPOCH, Constraint, Solver, SolveResult
from .errors import Diagnostic
from .ordering import Interval
from .records import BootRecord
from .timeutil import format_rfc3339_ns

RESOLUTION_NS = 1
DEFAULT_DRIFT_PPM = 0

ORDERING_KINDS = frozenset({"seq", "message", "boot_order"})
MEASUREMENT_KINDS = frozenset({"wall_lo", "wall_hi", "mono_elapsed"})


@dataclass
class BootModel:
    host: str
    boot_id: str
    calibration_lo_ns: int
    calibration_hi_ns: int
    drift_ppm: int
    follows: tuple[str, str] | None
    events: list[str] = field(default_factory=list)
    source: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        return (self.host, self.boot_id)

    @property
    def label(self) -> str:
        return f"{self.host}/{self.boot_id}"

    def to_json(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "boot_id": self.boot_id,
            "calibration": {
                "offset_lo_ns": self.calibration_lo_ns,
                "offset_hi_ns": self.calibration_hi_ns,
            },
            "drift_ppm": self.drift_ppm,
            "follows": list(self.follows) if self.follows else None,
            "event_count": len(self.events),
            "source": self.source,
        }


@dataclass
class EventModel:
    id: str
    host: str
    boot_id: str
    seq: int
    mono_ns: int
    wall_ns: int
    kind: str
    message_id: str | None
    possible: Interval
    signature: str
    occurrences: list[dict[str, Any]]
    order_index: int

    @property
    def boot_key(self) -> tuple[str, str]:
        return (self.host, self.boot_id)

    @property
    def sort_key(self) -> tuple:
        return (self.host, self.boot_id, self.seq, self.id)


@dataclass
class MessageBinding:
    message_id: str
    send: str
    receive: str
    constraint_id: str

    def to_json(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "send": self.send,
            "receive": self.receive,
            "constraint": self.constraint_id,
        }


@dataclass
class Model:
    events: dict[str, EventModel]
    event_order: list[str]
    boots: dict[tuple[str, str], BootModel]
    solver: Solver
    bindings: list[MessageBinding]
    diagnostics: list[Diagnostic]
    excluded: dict[str, str]
    boot_order_constraints: list[Constraint] = field(default_factory=list)

    # populated by :func:`solution.analysis.analyse`
    result: SolveResult | None = None
    tight: dict[tuple[str, str], int] = field(default_factory=dict)
    _kind_index: dict[tuple[str, str], set[str]] = field(default_factory=dict, repr=False)

    def window(self, event_id: str) -> Interval | None:
        """Feasible window of one event, or ``None`` when unbounded."""
        lower = self.tight.get((event_id, EPOCH))
        upper = self.tight.get((EPOCH, event_id))
        if lower is None or upper is None:
            return None
        return Interval(lo=-lower, hi=upper)

    def window_from(self, tight: dict[tuple[str, str], int], event_id: str) -> Interval | None:
        """Same as :meth:`window` but against an explicit closure (quarantine view)."""
        lower = tight.get((event_id, EPOCH))
        upper = tight.get((EPOCH, event_id))
        if lower is None or upper is None:
            return None
        return Interval(lo=-lower, hi=upper)

    def before(self, a: str, b: str) -> bool:
        """True when the system proves ``a`` strictly precedes ``b``.

        ``tight[(x, y)]`` bounds ``t_y - t_x``.  ``a`` precedes ``b`` when
        ``t_b - t_a >= 1 ns``, i.e. ``t_a - t_b <= -1``, i.e.
        ``tight[(b, a)] <= -RESOLUTION_NS``.
        """
        bound = self.tight.get((b, a))
        return bound is not None and bound <= -RESOLUTION_NS

    def pair_reason(self, a: str, b: str) -> str:
        """Label the evidence behind a proven order.

        Priority, most specific first:

        1. a direct message / declared-reboot constraint between this pair;
        2. the same boot (an increasing-sequence chain), because ``seq`` is the
           evidence a reader expects and it is boot-local by construction;
        3. disjoint calibration windows, a bound that needs no chain;
        4. a transitive chain across boots.

        The proof is always the solver bound; this only names the evidence.
        """
        kinds = self._pair_kinds(a, b)
        if "message" in kinds:
            return "message_causality"
        if "boot_order" in kinds:
            return "declared_reboot_order"
        if self.events[a].boot_key == self.events[b].boot_key:
            return "same_boot_sequence"
        ea, eb = self.events[a], self.events[b]
        if ea.possible.hi < eb.possible.lo or eb.possible.hi < ea.possible.lo:
            return "calibration_windows_disjoint"
        return "transitive_constraints"

    def _pair_kinds(self, a: str, b: str) -> set[str]:
        key = (a, b) if a <= b else (b, a)
        cached = self._kind_index.get(key)
        if cached is None:
            cached = {
                c.kind for c in self.solver.constraints
                if len(c.refs) == 2 and set(c.refs) == {a, b}
            }
            self._kind_index[key] = cached
        return cached

    def supporting_constraints(self, a: str, b: str) -> list[str]:
        """Ids of direct constraints that mention both events."""
        out = []
        for c in self.solver.constraints:
            if len(c.refs) == 2 and set(c.refs) == {a, b}:
                out.append(c.cid)
        return out


def build_model(collection: Collection, drift_ppm: int = DEFAULT_DRIFT_PPM) -> Model:
    solver = Solver()
    diagnostics: list[Diagnostic] = []
    events: dict[str, EventModel] = {}
    excluded: dict[str, str] = {}
    order: list[str] = []

    conflicted = {c.id for c in collection.conflicts}

    # --- boots ---------------------------------------------------------
    boots: dict[tuple[str, str], BootModel] = {}
    for key, record in sorted(collection.boots.items()):
        host, boot_id = key
        boots[key] = BootModel(
            host=host,
            boot_id=boot_id,
            calibration_lo_ns=record.calibration.offset_lo_ns,
            calibration_hi_ns=record.calibration.offset_hi_ns,
            drift_ppm=_drift_ppm_of(record, drift_ppm),
            follows=_follows_of(record),
            # The boot's own first occurrence, so the provenance points at the
            # record that defined the calibration, not merely at the host.
            source=record.occurrence,
        )

    # --- events --------------------------------------------------------
    for event_id in sorted(collection.events):
        node_obj = collection.events[event_id]
        if event_id in conflicted:
            excluded[event_id] = "E_ID_CONFLICT"
            continue
        if not event_id or event_id.startswith("@"):
            excluded[event_id] = "E_LINE_SCHEMA"
            diagnostics.append(
                Diagnostic(
                    code="E_LINE_SCHEMA",
                    message=f"event id {event_id!r} is empty or uses the reserved '@' prefix",
                    detail={"event_id": event_id},
                )
            )
            continue
        boot = boots.get((node_obj.host, node_obj.boot_id))
        if boot is None:
            excluded[event_id] = "E_BOOT_MISSING"
            diagnostics.append(
                Diagnostic(
                    code="E_BOOT_MISSING",
                    message=(
                        f"event {event_id!r} is on boot {node_obj.boot_id!r} of host "
                        f"{node_obj.host!r}, which has no boot record with a calibration"
                    ),
                    detail={
                        "event_id": event_id,
                        "host": node_obj.host,
                        "boot_id": node_obj.boot_id,
                        "occurrences": [o.to_json() for o in node_obj.occurrences],
                    },
                )
            )
            continue

        possible = Interval(
            node_obj.wall_ns - boot.calibration_hi_ns,
            node_obj.wall_ns - boot.calibration_lo_ns,
        )
        em = EventModel(
            id=event_id,
            host=node_obj.host,
            boot_id=node_obj.boot_id,
            seq=node_obj.seq,
            mono_ns=node_obj.mono_ns,
            wall_ns=node_obj.wall_ns,
            kind=node_obj.kind,
            message_id=node_obj.message_id,
            possible=possible,
            signature=node_obj.signature,
            occurrences=[o.to_json() for o in node_obj.occurrences],
            order_index=len(order),
        )
        events[event_id] = em
        order.append(event_id)
        boot.events.append(event_id)

        solver.add_upper("wall_hi", event_id, possible.hi, refs=(event_id,),
                         note="true time <= wall - calibration_lo")
        solver.add_lower("wall_lo", event_id, possible.lo, refs=(event_id,),
                         note="true time >= wall - calibration_hi")

    # --- sequence + monotonic elapsed time, per boot ---------------------
    for boot in boots.values():
        by_seq: dict[int, list[str]] = {}
        for event_id in boot.events:
            by_seq.setdefault(events[event_id].seq, []).append(event_id)
        for seq, group in sorted(by_seq.items()):
            if len(group) > 1:
                diagnostics.append(
                    Diagnostic(
                        code="E_SEQ_DUP",
                        message=(
                            f"boot {boot.label} has {len(group)} events with seq {seq}; "
                            "they are left unordered with respect to each other"
                        ),
                        detail={
                            "host": boot.host,
                            "boot_id": boot.boot_id,
                            "seq": seq,
                            "events": sorted(group),
                        },
                    )
                )
        seq_values = sorted(by_seq)
        for lower_seq, upper_seq in zip(seq_values, seq_values[1:]):
            for event_id in sorted(by_seq[lower_seq]):
                for event_id_b in sorted(by_seq[upper_seq]):
                    solver.add_before("seq", event_id, event_id_b, RESOLUTION_NS,
                                      refs=(event_id, event_id_b),
                                      note=f"same boot, seq {lower_seq} < {upper_seq}")
                    ea, eb = events[event_id], events[event_id_b]
                    delta = eb.mono_ns - ea.mono_ns
                    if delta < 0:
                        diagnostics.append(
                            Diagnostic(
                                code="E_MONO_ANOMALY",
                                message=(
                                    f"monotonic counter went backwards inside boot {boot.label}: "
                                    f"{event_id} seq {ea.seq} mono {ea.mono_ns} -> "
                                    f"{event_id_b} seq {eb.seq} mono {eb.mono_ns}"
                                ),
                                detail={
                                    "host": boot.host,
                                    "boot_id": boot.boot_id,
                                    "events": [event_id, event_id_b],
                                },
                            )
                        )
                        continue
                    slack = _drift_slack(delta, boot.drift_ppm)
                    if delta == 0 and slack == 0:
                        # Nothing gained: the sequence constraint already says
                        # "at least 1 ns", the counter says "at least 0 ns".
                        continue
                    # t_b - t_a >= delta - slack  <=>  t_a - t_b <= -delta + slack
                    solver.add("mono_elapsed", event_id_b, event_id, -delta + slack,
                               refs=(event_id, event_id_b),
                               note=(
                                   f"elapsed monotonic time {delta} ns between "
                                   f"seq {lower_seq} and seq {upper_seq}"
                               ))

    # --- message causality ---------------------------------------------
    bindings: list[MessageBinding] = []
    by_message: dict[str, list[str]] = {}
    for event_id in order:
        mid = events[event_id].message_id
        if mid:
            by_message.setdefault(mid, []).append(event_id)

    for mid in sorted(by_message):
        members = by_message[mid]
        sends = sorted(e for e in members if events[e].kind == "send")
        recvs = sorted(e for e in members if events[e].kind == "recv")
        if len(sends) == 1 and len(recvs) == 1 and sends[0] != recvs[0]:
            c = solver.add_before("message", sends[0], recvs[0], RESOLUTION_NS,
                                  refs=(sends[0], recvs[0]),
                                  note=f"message {mid}: send strictly precedes receive")
            bindings.append(MessageBinding(mid, sends[0], recvs[0], c.cid))
            continue
        code = "E_DANGLING" if (not sends or not recvs) else "E_MESSAGE_PAIR"
        diagnostics.append(
            Diagnostic(
                code=code,
                message=(
                    f"message {mid!r} has {len(sends)} send and {len(recvs)} receive endpoint(s) "
                    "among accepted events; no causal constraint was added"
                ),
                detail={"message_id": mid, "sends": sends, "receives": recvs},
            )
        )

    # --- declared reboot order -----------------------------------------
    boot_order_constraints: list[Constraint] = []
    for boot in boots.values():
        if not boot.follows or not boot.events:
            continue
        previous = boots.get(boot.follows)
        if previous is None or not previous.events:
            diagnostics.append(
                Diagnostic(
                    code="E_REBOOT_ORDER",
                    message=(
                        f"boot {boot.label} declares follows={list(boot.follows)!r}, "
                        "which is not a collected boot with events"
                    ),
                    detail={"host": boot.host, "boot_id": boot.boot_id, "follows": list(boot.follows)},
                )
            )
            continue
        last_previous = max(previous.events, key=lambda e: (events[e].seq, e))
        first_this = min(boot.events, key=lambda e: (events[e].seq, e))
        c = solver.add_before(
            "boot_order", last_previous, first_this, RESOLUTION_NS,
            refs=(last_previous, first_this),
            note=f"declared reboot order {previous.label} -> {boot.label}",
        )
        boot_order_constraints.append(c)

    return Model(
        events=events,
        event_order=order,
        boots=boots,
        solver=solver,
        bindings=bindings,
        diagnostics=diagnostics,
        excluded=excluded,
        boot_order_constraints=boot_order_constraints,
    )


# ---------------------------------------------------------------------------
# helpers


def _drift_ppm_of(record: BootRecord, default: int) -> int:
    raw = record.raw.get("drift_ppm")
    if raw is None:
        return default
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise ValueError(f"boot {record.boot_id!r}: drift_ppm must be a non-negative integer")
    return raw


def _follows_of(record: BootRecord) -> tuple[str, str] | None:
    raw = record.raw.get("follows")
    if raw is None:
        return None
    if isinstance(raw, dict):
        host = raw.get("host")
        boot_id = raw.get("boot_id")
        if isinstance(host, str) and isinstance(boot_id, str):
            return (host, boot_id)
        return None
    if isinstance(raw, str):
        return (record.host, raw)
    return None


def _drift_slack(delta_ns: int, ppm: int) -> int:
    if ppm <= 0 or delta_ns <= 0:
        return 0
    return (delta_ns * ppm + 999_999) // 1_000_000


def format_instant(value: int) -> str:
    return format_rfc3339_ns(value)
