"""Difference-constraint solver over integer nanoseconds.

Model
-----
One integer variable per event node: ``t_X`` = the unknown true UTC instant
of the event, in nanoseconds since the epoch.  Plus one constant node
``@epoch`` with ``t = 0``.

Every rule the task requires is a difference constraint ``t_v - t_u <= w``:

=========================  ==============================================
rule                       constraint
=========================  ==============================================
wall / calibration upper    ``@epoch -> X : w = upper_bound``
wall / calibration lower    ``X -> @epoch : w = -lower_bound``
same boot, seq order        ``s -> r : w = -resolution``  (s strictly before r)
message send before recv    ``s -> r : w = -resolution``
declared reboot order       ``s -> r : w = -resolution``
=========================  ==============================================

The system is a *simple temporal problem*.  It is feasible exactly when its
constraint graph has no negative cycle, and Bellman-Ford gives the tightest
implied bound ``t_b - t_a <= d(a,b)`` as a shortest-path distance.

Consequences used by the rest of the tool:

* the feasible time window of event ``X`` is ``[-d(X,@epoch), d(@epoch,X)]``;
* ``a`` must precede ``b`` iff ``d(a,b) <= -resolution``.  If that is not the
  case, the exact interval of possible values of ``t_b - t_a`` contains 0, so
  a solution with ``t_a == t_b`` exists and the two events are genuinely
  concurrent.  Window overlap alone is **not** used to claim an order;
  transitive constraints are taken into account.
* resolution is 1 ns, so "strictly before" means "at least 1 ns earlier".

Minimal unsatisfiable cores
---------------------------
On a negative cycle the tool extracts that cycle as a witness, then runs a
deletion based minimisation: for each member ``c`` of the current set, test
whether the set without ``c`` is still infeasible and if so drop it.
Feasibility is monotone (a subset of a feasible system is feasible), so one
pass yields a *subset-minimal* core: removing any single remaining member
makes the system feasible.  Each member is then re-tested and the result is
recorded as a machine checkable certificate.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Iterable

EPOCH = "@epoch"


@dataclass(frozen=True)
class Constraint:
    """``t_dst - t_src <= weight`` with provenance for reporting."""

    cid: str
    kind: str          # wall_lo | wall_hi | seq | message | boot_order
    src: str
    dst: str
    weight: int
    refs: tuple[str, ...] = ()
    note: str = ""

    def to_json(self) -> dict:
        return {
            "id": self.cid,
            "kind": self.kind,
            "from": self.src,
            "to": self.dst,
            "weight_ns": self.weight,
            "events": list(self.refs),
            "note": self.note,
            "means": self.semantic(),
        }

    def semantic(self) -> str:
        """Plain language reading of the constraint."""
        src = "epoch(0)" if self.src == EPOCH else f"t[{self.src}]"
        dst = "epoch(0)" if self.dst == EPOCH else f"t[{self.dst}]"
        if self.kind == "wall_hi":
            return f"{dst} <= {self.weight}"
        if self.kind == "wall_lo":
            return f"{src} >= {-self.weight}"
        if self.kind in ("seq", "message", "boot_order", "mono_elapsed"):
            # src is the later event, dst the earlier one: dst precedes src.
            return f"{dst} precedes {src} by at least {-self.weight}"
        return f"{dst} - {src} <= {self.weight}"


@dataclass
class SolveResult:
    feasible: bool
    # tightest bound t[target] - t[source] <= tight[(source, target)]
    tight: dict[tuple[str, str], int] = field(default_factory=dict)
    # deterministic witness solution, relative to @epoch = 0
    solution: dict[str, int] = field(default_factory=dict)
    negative_cycle: list[Constraint] = field(default_factory=list)
    core: list[Constraint] = field(default_factory=list)
    # [(constraint id, feasible without it)] for the minimality proof
    core_certificate: list[dict] = field(default_factory=list)
    passes: int = 0


def bellman_ford(constraints: list[Constraint], anchored: bool = False):
    """Feasibility plus shortest distances.

    ``anchored=False`` (the default) starts every node at 0, i.e. adds a
    virtual super source.  That detects a negative cycle *anywhere* in the
    graph, including one among nodes that no wall-clock constraint reaches,
    and the resulting distances satisfy ``d[v] <= d[u] + w`` for every edge,
    which makes them valid Johnson potentials.  ``anchored=True`` pins
    ``@epoch`` at 0 instead; it is used only where absolute instants are
    wanted, and it cannot see a cycle unreachable from ``@epoch``.

    Returns ``(feasible, distances, negative_cycle_edges)``.
    """
    nodes: set[str] = set()
    for c in constraints:
        nodes.add(c.src)
        nodes.add(c.dst)
    nodes.add(EPOCH)

    dist: dict[str, int | None] = {n: None for n in nodes}
    if anchored:
        dist[EPOCH] = 0
    else:
        for n in nodes:
            dist[n] = 0
    pred: dict[str, tuple[str, Constraint] | None] = {n: None for n in nodes}
    edges = [(c.src, c.dst, c.weight, c) for c in constraints]

    changed_node: str | None = None
    for _ in range(len(nodes)):
        changed_node = None
        for u, v, w, c in edges:
            du = dist[u]
            if du is None:
                continue
            nd = du + w
            dv = dist[v]
            if dv is None or nd < dv:
                dist[v] = nd
                pred[v] = (u, c)
                changed_node = v
        if changed_node is None:
            return True, {k: v for k, v in dist.items() if v is not None}, []

    return False, {}, _extract_cycle(pred, changed_node or EPOCH)


def _extract_cycle(pred: dict[str, tuple[str, Constraint] | None], start: str) -> list[Constraint]:
    """Walk predecessors until a node repeats, then return that cycle's edges."""
    n = len(pred)
    node = start
    # Move far enough back that ``node`` is guaranteed to be on the cycle.
    for _ in range(n):
        entry = pred.get(node)
        if entry is None:
            break
        node = entry[0]
    origin = node
    hops: list[Constraint] = []
    cursor = origin
    for _ in range(n + 1):
        entry = pred.get(cursor)
        if entry is None:
            break
        prev, c = entry
        hops.append(c)
        cursor = prev
        if cursor == origin:
            return _dedupe(reversed(hops))
    return _dedupe(reversed(hops))


class Solver:
    def __init__(self) -> None:
        self.nodes: set[str] = set()
        self.constraints: list[Constraint] = []
        self._seq = 0

    # -- construction ----------------------------------------------------
    def add(self, kind: str, src: str, dst: str, weight: int,
            refs: Iterable[str] = (), note: str = "", cid: str | None = None) -> Constraint:
        self.nodes.add(src)
        self.nodes.add(dst)
        if cid is None:
            self._seq += 1
            cid = f"c{self._seq:04d}"
        c = Constraint(cid=cid, kind=kind, src=src, dst=dst, weight=weight,
                       refs=tuple(refs), note=note)
        self.constraints.append(c)
        return c

    def add_upper(self, kind: str, node: str, bound: int, refs=(), note: str = "") -> Constraint:
        return self.add(kind, EPOCH, node, bound, refs, note)

    def add_lower(self, kind: str, node: str, bound: int, refs=(), note: str = "") -> Constraint:
        return self.add(kind, node, EPOCH, -bound, refs, note)

    def add_before(self, kind: str, first: str, second: str, resolution_ns: int = 1,
                   refs=(), note: str = "") -> Constraint:
        """``t_first + resolution_ns <= t_second``.

        As ``t_second - t_first >= d`` this is ``t_first - t_second <= -d``,
        i.e. an edge from ``second`` to ``first`` with weight ``-d``.
        """
        return self.add(kind, second, first, -resolution_ns, refs, note)

    def by_kind(self, kind: str) -> list[Constraint]:
        return [c for c in self.constraints if c.kind == kind]

    # -- solving ---------------------------------------------------------
    def solve(self, constraints: list[Constraint] | None = None) -> SolveResult:
        """Solve the given constraints (default: the whole system).

        Passing a subset is how the quarantine view is computed: the same
        solver, minus the constraints in the minimal cores, so the reader can
        see what the timeline looks like once the contradicted evidence is
        set aside.  The result is never presented as the primary answer.
        """
        active = self.constraints if constraints is None else constraints
        feasible, dist, cycle = bellman_ford(active)
        if not feasible:
            core, certificate = self._minimise_core(cycle, active)
            return SolveResult(
                feasible=False,
                negative_cycle=cycle,
                core=core,
                core_certificate=certificate,
            )
        tight, passes = self._all_pairs(dist, active)
        solution: dict[str, int] = {}
        for node in sorted(self.nodes):
            if node == EPOCH:
                continue
            lower = tight.get((node, EPOCH))
            upper = tight.get((EPOCH, node))
            if lower is not None:
                solution[node] = -lower
            else:  # pragma: no cover - every event has a lower bound
                solution[node] = upper or 0
        return SolveResult(feasible=True, tight=tight, solution=solution, passes=passes)

    def _all_pairs(self, dist: dict[str, int],
                   constraints: list[Constraint] | None = None) -> tuple[dict[tuple[str, str], int], int]:
        """Tightest pairwise bounds via Johnson reweighting + Dijkstra."""
        active = self.constraints if constraints is None else constraints
        nodes = sorted(self.nodes)
        h = {n: dist.get(n, 0) for n in nodes}
        h[EPOCH] = 0
        reduced: dict[str, list[tuple[str, int]]] = {n: [] for n in nodes}
        for c in active:
            # w' = w + h[src] - h[dst] >= 0 because h are shortest distances.
            reduced[c.src].append((c.dst, c.weight + h[c.src] - h[c.dst]))

        big = 1 << 62
        tight: dict[tuple[str, str], int] = {}
        passes = 0
        for source in nodes:
            d: dict[str, int] = {source: 0}
            heap: list[tuple[int, str]] = [(0, source)]
            while heap:
                du, u = heapq.heappop(heap)
                if du > d.get(u, big):
                    continue
                passes += 1
                for v, w in reduced[u]:
                    nd = du + w
                    if nd < d.get(v, big):
                        d[v] = nd
                        heapq.heappush(heap, (nd, v))
            for target in nodes:
                if target in d:
                    tight[(source, target)] = d[target] - h[source] + h[target]
        return tight, passes

    # -- cores -----------------------------------------------------------
    def _infeasible(self, subset: list[Constraint]) -> bool:
        ok, _, _ = bellman_ford(subset, anchored=False)
        return not ok

    def _minimise_core(self, cycle: list[Constraint],
                       constraints: list[Constraint] | None = None) -> tuple[list[Constraint], list[dict]]:
        active = self.constraints if constraints is None else constraints
        seed = _dedupe(cycle)
        if not seed or not self._infeasible(seed):
            seed = _dedupe(active)
        core = deletion_minimise(seed, self._infeasible)
        core = sorted(core, key=lambda c: c.cid)
        certificate: list[dict] = []
        for c in core:
            without = [x for x in core if x.cid != c.cid]
            feasible_without = not self._infeasible(without) if without else True
            certificate.append({"remove": c.cid, "feasible_without": feasible_without})
        return core, certificate


def _dedupe(constraints: Iterable[Constraint]) -> list[Constraint]:
    if isinstance(constraints, (list, tuple)):
        items = constraints
    else:
        items = list(constraints)
    seen: set[str] = set()
    out: list[Constraint] = []
    for c in items:
        if c.cid in seen:
            continue
        seen.add(c.cid)
        out.append(c)
    return out


def deletion_minimise(candidates: list[Constraint], infeasible) -> list[Constraint]:
    """Subset-minimal infeasible subset, deterministic in candidate order."""
    core = list(candidates)
    for c in candidates:
        trial = [x for x in core if x.cid != c.cid]
        if trial and infeasible(trial):
            core = trial
    return core
