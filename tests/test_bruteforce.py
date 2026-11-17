"""Cross-checks between the reconstruction model and brute force.

The solver claims things like "a precedes b".  Here those claims are checked
against an independent search:

* for a small model, the pairwise verdicts must equal what an exhaustive grid
  search over the feasible windows says;
* the feasible windows must equal the bounds a separate enumeration produces;
* concurrency must be witnessed by an actual assignment with the two events at
  the same instant, not merely by the absence of a bound.
"""

from __future__ import annotations

import itertools
import random
import unittest

from _support import BASE, MS, S, SEED_H1, SEED_H2, CaseBuilder, CaseDir

from solution.constraints import EPOCH
from solution.pipeline import load_cases, run_case
from solution.verify import check_assignment


class BruteForceOrderTests(unittest.TestCase):
    """Small systems where every ordering claim can be checked by enumeration."""

    def build(self, edges, windows):
        from solution.constraints import Solver

        solver = Solver()
        for name, (lo, hi) in windows.items():
            solver.add_upper("wall_hi", name, hi)
            solver.add_lower("wall_lo", name, lo)
        solver.add("hi", EPOCH, "anchor", 0)
        solver.add("lo", "anchor", EPOCH, 0)
        for kind, a, b, w in edges:
            solver.add(kind, a, b, w)
        return solver

    def brute_force_pairs(self, solver, windows, step=1):
        """For each pair, list which relative orders actually occur."""
        names = sorted(windows)
        candidates = {
            name: list(range(windows[name][0], windows[name][1] + 1, step))
            for name in names
        }
        feasible_points = []
        for combo in itertools.product(*(candidates[n] for n in names)):
            point = dict(zip(names, combo))
            if not check_assignment(solver.constraints, point):
                feasible_points.append(point)
        return feasible_points

    def test_verdicts_match_exhaustive_enumeration(self):
        rng = random.Random(4242)
        for trial in range(25):
            windows = {name: (0, 6) for name in ("A", "B", "C")}
            edges = []
            for _ in range(3):
                a, b = rng.sample(sorted(windows), 2)
                edges.append(("edge", a, b, rng.randint(-3, 3)))
            solver = self.build(edges, windows)
            result = solver.solve()
            if not result.feasible:
                continue
            points = self.brute_force_pairs(solver, windows)
            self.assertTrue(points)
            for a, b in itertools.combinations(sorted(windows), 2):
                a_first = all(p[a] < p[b] for p in points)
                b_first = all(p[b] < p[a] for p in points)
                claimed_a = result.tight.get((b, a), 1) <= -1      # a precedes b
                claimed_b = result.tight.get((a, b), 1) <= -1      # b precedes a
                with self.subTest(trial=trial, pair=(a, b)):
                    self.assertEqual(claimed_a, a_first)
                    self.assertEqual(claimed_b, b_first)
                    # Not always-first in either direction => concurrent, and
                    # there is a witness with both at the same instant or
                    # strictly reversed readings.
                    if not claimed_a and not claimed_b:
                        self.assertFalse(a_first or b_first)

    def test_concurrency_has_an_equal_instant_witness(self):
        # Two events with overlapping windows and nothing between them.
        windows = {"A": (10, 20), "B": (15, 25)}
        solver = self.build([], windows)
        result = solver.solve()
        self.assertTrue(result.feasible)
        points = self.brute_force_pairs(solver, windows)
        equal = [p for p in points if p["A"] == p["B"]]
        self.assertTrue(equal, "concurrency must admit t_A == t_B")
        self.assertEqual(equal[0], {"A": 15, "B": 15})

    def test_window_bounds_match_enumeration(self):
        rng = random.Random(99)
        for trial in range(20):
            windows = {name: (0, 8) for name in ("A", "B")}
            edges = [("edge", "A", "B", rng.randint(-6, 6)),
                     ("edge", "B", "A", rng.randint(-6, 6))]
            solver = self.build(edges, windows)
            result = solver.solve()
            if not result.feasible:
                continue
            points = self.brute_force_pairs(solver, windows)
            for name in windows:
                lo = min(p[name] for p in points)
                hi = max(p[name] for p in points)
                lower = result.tight[(name, EPOCH)]
                upper = result.tight[(EPOCH, name)]
                with self.subTest(trial=trial, event=name):
                    self.assertEqual(-lower, lo)
                    self.assertEqual(upper, hi)


class ModelLevelBruteForceTests(unittest.TestCase):
    """The same check through the full pipeline on a tiny generated case."""

    def test_pipeline_order_matches_enumeration(self):
        case_dir = CaseDir(self)
        h1 = CaseBuilder("h1", SEED_H1)
        # One boot, +-5 ms calibration.  Monotonic readings advance with the
        # true instants (10 ms, 20 ms, 120 ms), so nothing contradicts.
        h1.boot("b1", offset_lo_ms=-5, offset_hi_ms=5)
        h1.event("a", "b1", 1, mono_ns=10 * MS, wall_ns=BASE + 10 * MS,
                 kind="send", message_id="m")
        h1.event("b", "b1", 2, mono_ns=20 * MS, wall_ns=BASE + 20 * MS)
        h1.event("c", "b1", 3, mono_ns=120 * MS, wall_ns=BASE + 120 * MS)
        h2 = CaseBuilder("h2", SEED_H2)
        h2.boot("b1", offset_lo_ms=-80, offset_hi_ms=80)
        # h2's receiver could be before or after b: windows overlap.
        h2.event("r", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 20 * MS,
                 kind="recv", message_id="m")
        case_dir.write("h1.jsonl", h1.render())
        case_dir.write("h2.jsonl", h2.render())
        result = run_case(load_cases(case_dir.cases(["h1.jsonl", "h2.jsonl"])))

        self.assertEqual(result["status"], "ok")
        pairs = {(p["a"], p["b"]): p for p in result["order"]["pairwise"]}
        by_pair = {}
        for (a, b), entry in pairs.items():
            by_pair[frozenset((a, b))] = entry
        # Message forces a before r; seq forces b before c; a before b; r vs b concurrent.
        self.assertEqual(by_pair[frozenset(("a", "r"))]["verdict"], "before")
        self.assertEqual(by_pair[frozenset(("a", "b"))]["verdict"], "before")
        self.assertEqual(by_pair[frozenset(("r", "b"))]["verdict"], "concurrent")
        # r is after a, and a before b, but b and r are unordered; c is 100 ms
        # after b on the same boot, so it is provably after r too.
        self.assertEqual(by_pair[frozenset(("b", "c"))]["verdict"], "before")
        self.assertEqual(by_pair[frozenset(("r", "c"))]["verdict"], "after")

        # Re-derive the same verdicts from the exported constraints by brute force.
        from solution.constraints import Constraint

        constraints = [
            Constraint(
                cid=c["id"], kind=c["kind"], src=c["from"], dst=c["to"],
                weight=c["weight_ns"], refs=tuple(c["events"]), note=c["note"],
            )
            for c in result["models"]["constraints"]
        ]
        windows = {}
        for entry in result["timeline"]:
            window = entry["feasible_window"]
            windows[entry["id"]] = (window["lo_ns"], window["hi_ns"])

        # Enumerate on a 1 ms grid inside each feasible window; 1 ms is fine
        # because every boundary in this case is a whole number of ms.
        grids = {
            name: list(range(lo, hi + 1, MS)) if hi - lo > MS else [lo, hi]
            for name, (lo, hi) in windows.items()
        }
        points = [
            dict(zip(sorted(grids), combo))
            for combo in itertools.product(*(grids[n] for n in sorted(grids)))
            if not check_assignment(constraints, dict(zip(sorted(grids), combo)))
        ]
        self.assertTrue(points)
        for pair in result["order"]["pairwise"]:
            a, b = pair["a"], pair["b"]
            a_first = all(p[a] < p[b] for p in points)
            b_first = all(p[b] < p[a] for p in points)
            with self.subTest(pair=(a, b)):
                if pair["verdict"] == "before":
                    self.assertTrue(a_first)
                elif pair["verdict"] == "after":
                    self.assertTrue(b_first)
                else:
                    self.assertFalse(a_first or b_first)


if __name__ == "__main__":
    unittest.main()
