"""Independent feasibility oracles used by the tests and by ``--verify``.

Three separate implementations of "is this constraint system satisfiable",
so a bug in one is unlikely to be mirrored in the others:

``bellman_ford``
    the production algorithm, in :mod:`solution.constraints`.
``floyd_warshall``
    reachability/tightest-bound closure via Floyd-Warshall, negative cycle
    detected by a negative diagonal entry.  Same theory, different code path.
``fourier_motzkin``
    variable elimination on the raw inequality system: no graph, no shortest
    paths.  If the system is feasible over the rationals it is feasible over
    the integers (the difference-constraint matrix is totally unimodular), so
    this is an exact integer feasibility oracle.

Plus two witnesses that make results checkable without trusting the solver at
all:

``check_assignment``
    a candidate solution must satisfy every constraint; a satisfying
    assignment proves feasibility constructively.
``exhaustive_search``
    bounded-domain brute force over a discrete grid, for tiny instances.
"""

from __future__ import annotations

import itertools
from fractions import Fraction
from typing import Iterable

from .constraints import EPOCH, Constraint


# ---------------------------------------------------------------------------
# Floyd-Warshall


def floyd_warshall(constraints: list[Constraint], nodes: Iterable[str] | None = None) -> tuple[bool, dict[tuple[str, str], int]]:
    """Return ``(feasible, dist)``; ``dist[(u,v)]`` is the tightest ``t_v - t_u <= dist``."""
    names = set(nodes or ())
    for c in constraints:
        names.add(c.src)
        names.add(c.dst)
    names.add(EPOCH)
    idx = {n: i for i, n in enumerate(sorted(names))}
    n = len(idx)
    big = 1 << 62
    dist = [[big] * n for _ in range(n)]
    for i in range(n):
        dist[i][i] = 0
    for c in constraints:
        u, v = idx[c.src], idx[c.dst]
        if c.weight < dist[u][v]:
            dist[u][v] = c.weight
    for k in range(n):
        for i in range(n):
            dik = dist[i][k]
            if dik == big:
                continue
            for j in range(n):
                nd = dik + dist[k][j]
                if nd < dist[i][j]:
                    dist[i][j] = nd
    for i in range(n):
        if dist[i][i] < 0:
            return False, {}
    # Rebuild the distance dictionary for a readable result.
    names_sorted = sorted(names)
    out = {}
    for i, a in enumerate(names_sorted):
        for j, b in enumerate(names_sorted):
            if dist[i][j] < big:
                out[(a, b)] = dist[i][j]
    return True, out


# ---------------------------------------------------------------------------
# Fourier-Motzkin


def fourier_motzkin(constraints: list[Constraint]) -> tuple[bool, list[tuple[str, str, int]] | str]:
    """Exact satisfiability by eliminating every variable in turn.

    Constants: ``@epoch`` is fixed to 0, so it is eliminated last and any
    remaining constraint ``@epoch - @epoch <= w`` with ``w < 0`` is the
    contradiction test.

    Returns ``(feasible, residual)``; when infeasible the residual is a short
    explanation string.
    """
    # Rows are (a, b, w) meaning t_b - t_a <= w, with numbers as Fraction
    # to keep the elimination exact for the ms-to-ns conversions.
    rows: list[tuple[str, str, Fraction]] = [(c.src, c.dst, Fraction(c.weight)) for c in constraints]
    for a, b, w in rows:
        if a == b and w < 0:
            return False, f"self constraint {a} - {a} <= {w} is unsatisfiable"
    variables = sorted({x for row in rows for x in row[:2]} - {EPOCH})

    for var in variables:
        lowers = [r for r in rows if r[1] == var and r[0] != var]   # t_var <= t_a + w
        uppers = [r for r in rows if r[0] == var and r[1] != var]   # t_b <= t_var + w
        # Rows on the variable itself are constants once it is eliminated.
        for a, b, w in rows:
            if a == b == var and w < 0:
                return False, f"eliminating {var}: {var} - {var} <= {w} is unsatisfiable"
        rest = [r for r in rows if r[0] != var and r[1] != var]
        merged: list[tuple[str, str, Fraction]] = []
        for low in lowers:
            for up in uppers:
                # t_b <= w_up + t_var <= w_up + w_low + t_a  =>  t_b - t_a <= ...
                a, b = low[0], up[1]
                w = low[2] + up[2]
                merged.append((a, b, w))
        # Keep the strongest duplicate only, to stop the row count exploding.
        best: dict[tuple[str, str], Fraction] = {}
        for a, b, w in rest + merged:
            key = (a, b)
            if key not in best or w < best[key]:
                best[key] = w
        rows = [(a, b, w) for (a, b), w in best.items()]
        if len(rows) > 200_000:  # pragma: no cover - guard for huge inputs
            return False, "system too large for the independent oracle"

    for a, b, w in rows:
        if a == b:
            if w < 0:
                return False, f"residual {b} - {a} <= {w} is unsatisfiable"
            continue
        if a != EPOCH and b != EPOCH:
            # Elimination should have removed every non-epoch variable pair.
            raise AssertionError(f"unexpected residual row {a},{b},{w}")
    return True, []


# ---------------------------------------------------------------------------
# witness checks


def check_assignment(constraints: list[Constraint], solution: dict[str, int]) -> list[str]:
    """Return a list of violated constraints for ``solution`` (empty = valid)."""
    violations: list[str] = []
    values = dict(solution)
    values.setdefault(EPOCH, 0)
    for c in constraints:
        lhs = values.get(c.dst, 0) - values.get(c.src, 0)
        if lhs > c.weight:
            violations.append(
                f"{c.cid}: t[{c.dst}] - t[{c.src}] = {lhs} > {c.weight}"
            )
    return violations


def exhaustive_search(constraints: list[Constraint], candidates: dict[str, list[int]]) -> dict[str, int] | None:
    """Grid brute force over the given finite candidate values per node.

    Only usable for tiny instances; it exists to cross-check the solver on
    hand-sized examples and to show that a feasible point really exists.
    """
    nodes = sorted(candidates)
    for combo in itertools.product(*(candidates[n] for n in nodes)):
        assignment = dict(zip(nodes, combo))
        if not check_assignment(constraints, assignment):
            return assignment
    return None


def grid_candidates(lo: int, hi: int, steps: int) -> list[int]:
    if steps <= 1 or lo == hi:
        return [lo]
    step = max(1, (hi - lo) // (steps - 1))
    values = list(range(lo, hi + 1, step))
    if values[-1] != hi:
        values.append(hi)
    return values


__all__ = [
    "check_assignment",
    "exhaustive_search",
    "floyd_warshall",
    "fourier_motzkin",
    "grid_candidates",
]
