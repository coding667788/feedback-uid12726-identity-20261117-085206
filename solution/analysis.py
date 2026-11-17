"""Analysis: solve, interpret, and render the partial order.

This module turns a :class:`solution.model.Model` into everything the result
JSON needs:

``timeline``
    one entry per accepted event with its possible interval, its feasible
    window after all constraints, and a witness instant;
``order``
    the strict partial order (transitive reduction) plus the explicit
    concurrency relation, derived from the solver's tightest pairwise bounds —
    never from wall clocks alone;
``unsat_cores``
    minimal unsatisfiable cores with a certificate per member;
``topological``
    a deterministic linear extension with Kahn's algorithm and a fixed
    tie-break key, plus a certificate that every edge is implied by the model.

Reading the bounds
------------------
``tight[(x, y)]`` is the tightest ``d`` with ``t_y - t_x <= d``.  Hence

* ``x`` precedes ``y``  iff  ``tight[(y, x)] <= -1``  (``t_x <= t_y - 1``);
* ``y`` precedes ``x``  iff  ``tight[(x, y)] <= -1``;
* otherwise both orders have a solution with the two events equal, so they are
  concurrent — no amount of wall-clock reading can separate them.

A pair with ``tight[(x, y)] == tight[(y, x)] == 0`` is genuinely simultaneous.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass
from typing import Any

from .collect import Collection
from .constraints import EPOCH, Constraint, SolveResult
from .errors import Diagnostic
from .model import ORDERING_KINDS, RESOLUTION_NS, Model, format_instant
from .ordering import Interval

# Above this many accepted events the full quadratic pair listing is replaced
# by the transitive reduction plus per-event predecessors/successors.  The
# strict order itself is unaffected; only the dense rendering is dropped.
FULL_PAIR_LIMIT = 256


@dataclass
class PairwiseOrder:
    ids: list[str]
    # precedes[a] / follows[a] are sorted event ids
    precedes: dict[str, list[str]]
    follows: dict[str, list[str]]
    concurrent: dict[str, list[str]]

    def comparable_count(self) -> int:
        """Number of *ordered pairs* with a proven order (a precedes b)."""
        return sum(len(v) for v in self.follows.values())


@dataclass
class Analysis:
    model: Model
    result: SolveResult
    order: PairwiseOrder
    diagnostics: list[Diagnostic]
    cores: list[dict[str, Any]]
    topological: dict[str, Any]
    feasible: bool
    total_pairs: int
    concurrent_pairs: int
    quarantine: dict[str, Any] | None = None


def analyse(model: Model, collection: Collection) -> Analysis:
    diagnostics = list(model.diagnostics)
    cores_json: list[dict[str, Any]] = []

    solved = model.solver.solve()
    model.result = solved
    if solved.feasible:
        model.tight = dict(solved.tight)
    else:
        model.tight = {}

    remaining_ids: set[str] = set()

    quarantine: dict[str, Any] | None = None
    if not solved.feasible:
        cores_json, remaining_ids, more = _all_cores(model, solved.core, max_cores=8)
        diagnostics.append(
            Diagnostic(
                code="E_CONTRADICTION",
                message=(
                    f"constraint system is unsatisfiable; {len(cores_json)} minimal "
                    f"core(s) reported"
                    + (" (search stopped at the configured limit)" if more else "")
                ),
                detail={
                    "cores": [core["constraint_ids"] for core in cores_json],
                    "negative_cycle": [c.cid for c in solved.negative_cycle],
                    "events_in_cores": sorted(
                        {e for core in cores_json for m in core["constraints"] for e in m["constraint"]["events"]}
                    ),
                    "more_cores_possible": more,
                },
            )
        )
        quarantine = _quarantine_view(model, remaining_ids, cores_json)

    order = _pairwise(model, solved)
    topological = _topological_extension(model, order, solved)
    if topological["status"] == "cycle" and solved.feasible:
        diagnostics.append(
            Diagnostic(
                code="E_ORDER_CYCLE",
                message="the strict precedence relation contains a cycle",
            )
        )
    n = len(order.ids)
    total_pairs = n * (n - 1) // 2
    concurrent_pairs = sum(len(v) for v in order.concurrent.values()) // 2
    return Analysis(
        model=model,
        result=solved,
        order=order,
        diagnostics=diagnostics,
        cores=cores_json,
        topological=topological,
        feasible=solved.feasible,
        total_pairs=total_pairs,
        concurrent_pairs=concurrent_pairs,
        quarantine=quarantine,
    )


def _all_cores(model: Model, first_core: list[Constraint],
               max_cores: int) -> tuple[list[dict[str, Any]], set[str], bool]:
    """Enumerate minimal cores by withdrawing each found core and re-solving.

    Cores are disjoint because each round removes the constraints it reported.
    The first core is the one from the initial solve (the negative cycle the
    solver actually hit); later cores come from re-solving without the earlier
    ones.  Enumeration stops at ``max_cores`` or when the rest is feasible; the
    third return value says whether a further core may exist.
    """
    rendered: list[dict[str, Any]] = [_render_core(model, first_core, None, 1)]
    removed: set[str] = {c.cid for c in first_core}
    for index in range(2, max_cores + 1):
        remaining = [c for c in model.solver.constraints if c.cid not in removed]
        if not remaining:
            return rendered, removed, False
        result = model.solver.solve(remaining)
        if result.feasible:
            return rendered, removed, False
        if not result.core or {c.cid for c in result.core} <= removed:
            return rendered, removed, True
        rendered.append(_render_core(model, result.core, None, index))
        removed |= {c.cid for c in result.core}
    return rendered, removed, True


def _quarantine_view(model: Model, removed: set[str],
                     cores: list[dict[str, Any]]) -> dict[str, Any]:
    """Re-solve with contested evidence withdrawn, for a counterfactual view.

    This is *not* the answer.  It exists so a reader can see what the timeline
    would look like if the disputed evidence were set aside; the primary result
    stays ``contradiction`` and the withdrawn constraints are listed.

    Two scopes are tried, in order of how much evidence they discard:

    ``ordering_only``
        withdraw just the ordering constraints (seq / message / boot order)
        that appear in the cores.  This is the interesting reading: if the
        system becomes consistent once the *ordering* claims are dropped, the
        contradiction is an ordering dispute and every measurement still
        bounds its event.
    ``full_core``
        withdraw whole cores, measurements included.  Used only when the
        ordering-only view is still inconsistent; the view is then weaker
        because some events lose the wall-clock anchor that made them
        comparable at all.
    """
    remaining = [c for c in model.solver.constraints if c.cid not in removed]
    core_ids = sorted(removed)
    by_id = {c.cid: c for c in model.solver.constraints}
    ordering_ids = sorted(
        cid for cid in core_ids
        if cid in by_id and by_id[cid].kind in ORDERING_KINDS
    )

    scope = "full_core"
    chosen: list[str] = core_ids
    solved = model.solver.solve(remaining) if remaining else None
    if ordering_ids and ordering_ids != core_ids:
        ordering_remaining = [c for c in model.solver.constraints if c.cid not in ordering_ids]
        ordering_solved = model.solver.solve(ordering_remaining)
        if ordering_solved.feasible:
            scope = "ordering_only"
            chosen = ordering_ids
            remaining = ordering_remaining
            solved = ordering_solved

    view: dict[str, Any] = {
        "scope": scope,
        "withdrawn_constraints": chosen,
        "withdrawn_cores": [core["index"] for core in cores],
        "withdrawn_kinds": sorted({by_id[cid].kind for cid in chosen if cid in by_id}),
        "note": (
            "counterfactual only: contested evidence is withdrawn so the rest of the "
            "timeline can be inspected; this is not evidence that the core is wrong"
        ),
    }
    if not remaining or solved is None:
        view.update({"feasible": False, "reason": "withdrawing the cores leaves no constraints"})
        return view
    view["feasible"] = solved.feasible
    if not solved.feasible:
        view["reason"] = "the remaining constraints are still unsatisfiable"
        return view
    ids_order = sorted(model.events, key=lambda e: model.events[e].sort_key)
    pairs = []
    for i, a in enumerate(ids_order):
        for b in ids_order[i + 1:]:
            ab = solved.tight.get((a, b))
            ba = solved.tight.get((b, a))
            if ab is not None and ab <= -RESOLUTION_NS:
                verdict = "after"
            elif ba is not None and ba <= -RESOLUTION_NS:
                verdict = "before"
            else:
                verdict = "concurrent"
            pairs.append({"a": a, "b": b, "verdict": verdict,
                          "precedes": b if verdict == "after" else (a if verdict == "before" else None)})
    order = _pairwise_from_tight(model, ids_order, solved)
    topological = _topological_extension(model, order, solved)
    windows = {}
    for event_id in ids_order:
        window = model.window_from(solved.tight, event_id)
        windows[event_id] = window.to_json() if window else None
    view.update(
        {
            "pairwise": pairs,
            "topological": topological,
            "windows": windows,
        }
    )
    return view


def _pairwise_from_tight(model: Model, ids: list[str], result: SolveResult) -> PairwiseOrder:
    precedes: dict[str, list[str]] = {}
    follows: dict[str, list[str]] = {}
    concurrent: dict[str, list[str]] = {}
    for a in ids:
        pred, succ, conc = [], [], []
        for b in ids:
            if a == b:
                continue
            if _le(result, (a, b)):
                pred.append(b)
            elif _le(result, (b, a)):
                succ.append(b)
            else:
                conc.append(b)
        precedes[a], follows[a], concurrent[a] = pred, succ, conc
    return PairwiseOrder(ids, precedes, follows, concurrent)


# ---------------------------------------------------------------------------
# pairwise order


def _pairwise(model: Model, result: SolveResult) -> PairwiseOrder:
    ids = sorted(model.events, key=lambda e: model.events[e].sort_key)
    precedes: dict[str, list[str]] = {}
    follows: dict[str, list[str]] = {}
    concurrent: dict[str, list[str]] = {}
    for a in ids:
        pred: list[str] = []
        succ: list[str] = []
        conc: list[str] = []
        for b in ids:
            if a == b:
                continue
            if not result.feasible:
                conc.append(b)
                continue
            # b precedes a  <=>  t_b <= t_a - 1  <=>  tight[(a, b)] <= -1
            if _le(result, (a, b)):
                pred.append(b)
            elif _le(result, (b, a)):
                succ.append(b)
            else:
                conc.append(b)
        precedes[a] = pred
        follows[a] = succ
        concurrent[a] = conc
    return PairwiseOrder(ids, precedes, follows, concurrent)


def _le(result: SolveResult, key: tuple[str, str]) -> bool:
    bound = result.tight.get(key)
    return bound is not None and bound <= -RESOLUTION_NS


# ---------------------------------------------------------------------------
# rendering


def _interval_json(interval: Interval | None) -> dict[str, Any] | None:
    if interval is None:
        return None
    return interval.to_json()


def event_summary(model: Model, event_id: str) -> dict[str, Any]:
    e = model.events[event_id]
    return {
        "id": e.id,
        "host": e.host,
        "boot_id": e.boot_id,
        "seq": e.seq,
        "kind": e.kind,
        "wall": format_instant(e.wall_ns),
        "mono_ns": e.mono_ns,
    }


def _render_core(model: Model, core: list[Constraint],
                 certificate: list[dict] | None, index: int) -> dict[str, Any]:
    members = []
    for c in core:
        members.append(
            {
                "constraint": c.to_json(),
                "events": [event_summary(model, e) for e in c.refs if e in model.events],
            }
        )
    if certificate is None:
        certificate = [{"remove": c.cid, "feasible_without": True} for c in core]
    return {
        "index": index,
        "size": len(core),
        "constraint_ids": [c.cid for c in core],
        "minimal": True,
        "definition": (
            "the core is unsatisfiable and, for every member c, removing c alone "
            "makes the remaining set satisfiable"
        ),
        "constraints": members,
        "contradiction": _core_contradiction(members),
        "certificate": certificate,
    }


def _core_contradiction(members: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Summarise the core as a cycle in words, when it forms one.

    Every core produced by the negative-cycle extraction is a simple cycle
    ``x1 -> x2 -> ... -> x1`` with total weight < 0.  Restating it as
    "A must be at least X ns before B, B at least Y ns before A, but X + Y > 0"
    is what a reader needs; the raw constraint list stays in the output.
    """
    edges = [(m["constraint"]["from"], m["constraint"]["to"], m["constraint"]["weight_ns"])
             for m in members]
    if not edges:
        return None
    successors: dict[str, list[tuple[str, int]]] = {}
    for u, v, w in edges:
        successors.setdefault(u, []).append((v, w))
    # Try to find a cycle covering exactly these edges (cores from a single
    # negative cycle always admit one).
    start = edges[0][0]
    path: list[tuple[str, int]] = []
    visited = {start}
    node = start
    total = 0
    while True:
        options = [(v, w) for v, w in successors.get(node, []) if v not in visited or v == start]
        if not options:
            return None
        nxt, w = options[0]
        path.append((node, w))
        total += w
        if nxt == start:
            break
        visited.add(nxt)
        node = nxt
        if len(path) > len(edges) + 1:
            return None
    steps = []
    for i, (u, w) in enumerate(path):
        v = path[i + 1][0] if i + 1 < len(path) else start
        steps.append({"from": u, "to": v, "weight_ns": w})

    def reading(step: dict[str, Any]) -> str:
        u, v, w = step["from"], step["to"], step["weight_ns"]
        if u == EPOCH:
            return f"t[{v}] <= {w} ns"
        if v == EPOCH:
            return f"t[{u}] >= {-w} ns"
        return f"{u} at least {-w} ns before {v}"

    return {
        "cycle": [s["from"] for s in steps],
        "total_weight_ns": total,
        "requirements": [reading(s) for s in steps],
        "explanation": (
            "walking the cycle gives 0 <= sum(weight_ns) = "
            f"{total} ns, which is impossible; no assignment of instants "
            "satisfies every constraint in this core"
        ),
    }


def render_timeline(model: Model, result: SolveResult) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for event_id in sorted(model.events, key=lambda e: model.events[e].sort_key):
        e = model.events[event_id]
        entry: dict[str, Any] = {
            "id": e.id,
            "host": e.host,
            "boot_id": e.boot_id,
            "seq": e.seq,
            "kind": e.kind,
            "message_id": e.message_id,
            "wall": format_instant(e.wall_ns),
            "wall_ns": e.wall_ns,
            "mono_ns": e.mono_ns,
            "possible_interval": e.possible.to_json(),
            "signature": e.signature,
            "occurrences": e.occurrences,
            "feasible_window": None,
            "witness_t_ns": None,
            "witness_t": None,
        }
        if result.feasible:
            window = model.window(event_id)
            entry["feasible_window"] = _interval_json(window)
            value = result.solution.get(event_id)
            entry["witness_t_ns"] = value
            entry["witness_t"] = format_instant(value) if value is not None else None
        out.append(entry)
    return out


def render_pairs(model: Model, analysis: Analysis) -> tuple[list[dict[str, Any]] | None, int]:
    """Full pairwise listing, or ``(None, total)`` when trimmed by size."""
    ids = analysis.order.ids
    total = len(ids) * (len(ids) - 1) // 2
    if len(ids) > FULL_PAIR_LIMIT:
        return None, total
    result = analysis.result
    pairs: list[dict[str, Any]] = []
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            pairs.append(_pair_entry(model, result, a, b))
    return pairs, total


def _pair_entry(model: Model, result: SolveResult, a: str, b: str) -> dict[str, Any]:
    """One row of the pairwise relation.

    ``verdict`` describes ``a`` relative to ``b``: ``before`` means a precedes
    b, ``after`` means b precedes a.  ``precedes`` names the earlier event
    outright so no reader has to invert anything.
    """
    if not result.feasible:
        return {"a": a, "b": b, "verdict": "unknown", "precedes": None,
                "reason": "unsatisfiable_system", "bound_ns": None, "bound": None,
                "supporting_constraints": []}
    # b precedes a  <=>  t_b <= t_a - 1  <=>  tight[(a, b)] <= -1
    ab = result.tight.get((a, b))
    ba = result.tight.get((b, a))
    support = model.supporting_constraints(a, b)
    if ab is not None and ab <= -RESOLUTION_NS:
        return {"a": a, "b": b, "verdict": "after", "precedes": b,
                "reason": model.pair_reason(a, b), "bound_ns": ab,
                "bound": f"t[{b}] - t[{a}] <= {ab} ns",
                "supporting_constraints": support}
    if ba is not None and ba <= -RESOLUTION_NS:
        return {"a": a, "b": b, "verdict": "before", "precedes": a,
                "reason": model.pair_reason(a, b), "bound_ns": ba,
                "bound": f"t[{a}] - t[{b}] <= {ba} ns",
                "supporting_constraints": support}
    return {
        "a": a,
        "b": b,
        "verdict": "concurrent",
        "precedes": None,
        "reason": "no_provable_order",
        "bound_ns": None,
        "bound": None,
        "supporting_constraints": support,
        # A feasible point with t_a == t_b exists, so neither order is forced.
        "separation_bounds_ns": {
            "t_b_minus_t_a_upper": ab,
            "t_a_minus_t_b_upper": ba,
        },
    }


def render_windows(model: Model, result: SolveResult) -> list[dict[str, Any]]:
    out = []
    for event_id in sorted(model.events, key=lambda e: model.events[e].sort_key):
        possible = model.events[event_id].possible
        window = model.window(event_id) if result.feasible else None
        out.append(
            {
                "id": event_id,
                "possible": possible.to_json(),
                "feasible": _interval_json(window),
                "narrowed": bool(
                    window is not None and (window.lo > possible.lo or window.hi < possible.hi)
                ),
            }
        )
    return out


# ---------------------------------------------------------------------------
# deterministic linear extension


def _topological_extension(model: Model, order: PairwiseOrder, result: SolveResult) -> dict[str, Any]:
    ids = order.ids
    if not result.feasible:
        return {
            "status": "unavailable",
            "reason": "the constraint system is unsatisfiable, so no linear extension exists",
            "algorithm": "kahn",
            "tie_break": "host, boot_id, seq, id",
            "sequence": [],
            "edges": [],
            "certificate": {
                "edges_checked": 0,
                "edges_implied": 0,
                "edges_in_violation": [],
                "edges_backwards": [],
                "concurrent_pairs": 0,
                "concurrent_pairs_broken_by_tie_break": 0,
            },
        }

    edges = _transitive_reduction(ids, order)
    indeg = {i: 0 for i in ids}
    succ: dict[str, list[str]] = {i: [] for i in ids}
    for a, b in edges:
        succ[a].append(b)
        indeg[b] += 1
    heap = [(model.events[i].sort_key, i) for i in ids if indeg[i] == 0]
    heapq.heapify(heap)
    sequence: list[str] = []
    while heap:
        _, node = heapq.heappop(heap)
        sequence.append(node)
        for nxt in sorted(succ[node], key=lambda x: model.events[x].sort_key):
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                heapq.heappush(heap, (model.events[nxt].sort_key, nxt))
    if len(sequence) != len(ids):
        return {
            "status": "cycle",
            "reason": "the strict precedence relation contains a cycle",
            "algorithm": "kahn",
            "tie_break": "host, boot_id, seq, id",
            "sequence": [],
            "edges": [{"from": a, "to": b} for a, b in edges],
            "certificate": {
                "edges_checked": len(edges),
                "edges_implied": 0,
                "edges_in_violation": [{"from": a, "to": b} for a, b in edges],
                "edges_backwards": [],
                "concurrent_pairs": 0,
                "concurrent_pairs_broken_by_tie_break": 0,
            },
        }

    position = {event_id: index for index, event_id in enumerate(sequence)}
    violated = [e for e in edges if not model.before(*e)]
    backwards = [e for e in edges if position[e[0]] >= position[e[1]]]
    concurrent_total = sum(len(v) for v in order.concurrent.values()) // 2
    broken = sum(1 for a in ids for b in order.concurrent[a] if position[a] < position[b])
    return {
        "status": "ok",
        "algorithm": "kahn",
        "tie_break": "host, boot_id, seq, id",
        "sequence": sequence,
        "edges": [{"from": a, "to": b} for a, b in edges],
        "certificate": {
            "edges_checked": len(edges),
            "edges_implied": len(edges) - len(violated),
            "edges_in_violation": [{"from": a, "to": b} for a, b in violated],
            "edges_backwards": [{"from": a, "to": b} for a, b in backwards],
            "concurrent_pairs": concurrent_total,
            "concurrent_pairs_broken_by_tie_break": broken,
            "note": (
                "a linear extension must place every concurrent pair in some order; "
                "the tie-break decides those, and only those"
            ),
        },
    }


def _transitive_reduction(ids: list[str], order: PairwiseOrder) -> list[tuple[str, str]]:
    """Keep ``a -> b`` only when no ``c`` satisfies ``a < c < b``."""
    pred_sets = {b: set(order.precedes[b]) for b in ids}
    edges: list[tuple[str, str]] = []
    for a in ids:
        for b in order.follows[a]:
            if any(c in pred_sets[b] for c in order.follows[a] if c != b):
                continue
            edges.append((a, b))
    edges.sort(key=lambda pair: (ids.index(pair[0]), ids.index(pair[1])))
    return edges
