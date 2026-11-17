"""Tests for the difference-constraint solver and its independent oracles."""

from __future__ import annotations

import random
import unittest

from _support import ROOT  # noqa: F401

from solution.constraints import EPOCH, Constraint, Solver, bellman_ford, deletion_minimise
from solution.verify import (
    check_assignment,
    exhaustive_search,
    floyd_warshall,
    fourier_motzkin,
    grid_candidates,
)


def system(*edges) -> Solver:
    """``edges`` are ``(kind, src, dst, weight)`` meaning ``t_dst - t_src <= w``."""
    solver = Solver()
    for kind, a, b, w in edges:
        solver.add(kind, a, b, w)
    return solver


def pinned(name: str, value: int) -> Solver:
    """A solver holding one event pinned to exactly ``value``."""
    solver = Solver()
    solver.add_upper("wall_hi", name, value)
    solver.add_lower("wall_lo", name, value)
    return solver


class SolverBasicsTests(unittest.TestCase):
    def test_single_interval(self):
        solver = system(("hi", EPOCH, "A", 100), ("lo", "A", EPOCH, -50))
        result = solver.solve()
        self.assertTrue(result.feasible)
        # tight[(A, epoch)] is the tightest d with t_epoch - t_A <= d, i.e. -50.
        self.assertEqual(result.tight[(EPOCH, "A")], 100)
        self.assertEqual(result.tight[("A", EPOCH)], -50)
        self.assertEqual(result.solution["A"], 50)

    def test_strict_order_needs_one_nanosecond(self):
        solver = system(
            ("hi", EPOCH, "A", 100), ("lo", "A", EPOCH, -90),
            ("hi", EPOCH, "B", 100), ("lo", "B", EPOCH, -90),
            ("seq", "B", "A", -1),  # A before B
        )
        result = solver.solve()
        self.assertTrue(result.feasible)
        # t_B - t_A >= 1
        self.assertEqual(result.tight[("B", "A")], -1)

    def test_simultaneous_events_are_detected(self):
        solver = system(
            ("hi", EPOCH, "A", 1_000), ("lo", "A", EPOCH, 0),
            ("hi", EPOCH, "B", 1_000), ("lo", "B", EPOCH, 0),
        )
        result = solver.solve()
        self.assertTrue(result.feasible)
        self.assertEqual(result.tight[("A", "B")], 1_000)
        self.assertEqual(result.tight[("B", "A")], 1_000)
        # No order is provable in either direction.
        self.assertFalse(result.tight[("A", "B")] <= -1)
        self.assertFalse(result.tight[("B", "A")] <= -1)

    def test_partial_overlap_leaves_no_order(self):
        solver = system(
            ("hi", EPOCH, "A", 1_100), ("lo", "A", EPOCH, 900),
            ("hi", EPOCH, "B", 1_200), ("lo", "B", EPOCH, 1_000),
        )
        result = solver.solve()
        self.assertTrue(result.feasible)
        self.assertGreater(result.tight[("A", "B")], 0)
        self.assertGreater(result.tight[("B", "A")], 0)


class ContradictionTests(unittest.TestCase):
    def build(self) -> Solver:
        # A and B are both pinned to exactly 1000 ns, but B is forced to
        # precede A by at least 1 ns: unsatisfiable.
        solver = pinned("A", 1_000)
        solver.add_upper("wall_hi", "B", 1_000)
        solver.add_lower("wall_lo", "B", 1_000)
        solver.add_before("seq", "B", "A", 1)
        return solver

    def test_infeasible_and_core_size(self):
        result = self.build().solve()
        self.assertFalse(result.feasible)
        # The core uses one side of each pin plus the ordering constraint: the
        # other two constraints are already implied by what is left.
        self.assertEqual(len(result.core), 3)
        kinds = sorted(c.kind for c in result.core)
        self.assertEqual(kinds, ["seq", "wall_hi", "wall_lo"])
    def test_core_is_minimal_by_construction(self):
        solver = self.build()
        result = solver.solve()
        ids = [c.cid for c in result.core]
        by_id = {c.cid: c for c in solver.constraints}
        core = [by_id[i] for i in ids]
        self.assertTrue(solver._infeasible(core))
        for c in core:
            without = [x for x in core if x.cid != c.cid]
            self.assertFalse(solver._infeasible(without), f"removing {c.cid} kept it infeasible")
        for entry in result.core_certificate:
            self.assertTrue(entry["feasible_without"])

    def test_negative_cycle_is_reported(self):
        result = self.build().solve()
        self.assertTrue(result.negative_cycle)
        total = sum(c.weight for c in result.negative_cycle)
        self.assertLess(total, 0)

    def test_core_excludes_irrelevant_constraints(self):
        solver = self.build()
        # Add a pile of unrelated constraints; none may enter the core.
        for i in range(30):
            solver.add("noise", EPOCH, f"X{i}", 500 + i)
            solver.add("noise", f"X{i}", EPOCH, -(400 + i))
        result = solver.solve()
        self.assertFalse(result.feasible)
        self.assertEqual(len(result.core), 3)
        self.assertEqual(
            sorted(c.kind for c in result.core),
            ["seq", "wall_hi", "wall_lo"],
        )

    def test_three_constraint_core(self):
        # t_A pinned to 0; t_B pinned to 10; and t_A must be >= t_B + 1.
        solver = pinned("A", 0)
        solver.add_upper("wall_hi", "B", 10)
        solver.add_lower("wall_lo", "B", 10)
        solver.add_before("seq", "B", "A", 1)  # t_B >= t_A + 1
        result = solver.solve()
        self.assertFalse(result.feasible)
        self.assertEqual(len(result.core), 3)
        for c in result.core:
            without = [x for x in solver.constraints if x.cid != c.cid]
            ok, _, _ = bellman_ford(without)
            self.assertTrue(ok, f"removing {c.cid} left the system infeasible")


class OracleAgreementTests(unittest.TestCase):
    """Random systems: Bellman-Ford, Floyd-Warshall and Fourier-Motzkin agree."""

    def random_system(self, rng: random.Random, nodes: int, edges: int) -> Solver:
        """Windows around a hidden true assignment, plus relations.

        Every event gets a window that contains a hidden ``truth`` value, so
        without the extra edges the system is always feasible; the extra edges
        are drawn so that roughly half of the systems survive them.
        """
        solver = Solver()
        names = [f"n{i}" for i in range(nodes)]
        truth = {name: rng.randint(0, 200) for name in names}
        for name in names:
            solver.add_upper("wall_hi", name, truth[name] + rng.randint(0, 40))
            solver.add_lower("wall_lo", name, truth[name] - rng.randint(0, 40))
        for _ in range(edges):
            a, b = rng.sample(names, 2)
            # Constraint t_b - t_a <= w.  Consistent with truth about half the
            # time, because w is drawn around the true separation.
            w = (truth[b] - truth[a]) + rng.randint(-25, 25)
            solver.add("edge", a, b, w)
        return solver

    def test_three_oracles_agree_on_feasibility(self):
        rng = random.Random(20260101)
        feasible_seen = infeasible_seen = 0
        for trial in range(200):
            solver = self.random_system(rng, nodes=4, edges=6)
            constraints = list(solver.constraints)
            bf, _, _ = bellman_ford(constraints)
            fw_ok, _ = floyd_warshall(constraints)
            fm_ok, _ = fourier_motzkin(constraints)
            with self.subTest(trial=trial):
                self.assertEqual(bf, fw_ok)
                self.assertEqual(bf, fm_ok)
            if bf:
                feasible_seen += 1
            else:
                infeasible_seen += 1
        # The generator must exercise both branches for the test to mean anything.
        self.assertGreater(feasible_seen, 20)
        self.assertGreater(infeasible_seen, 20)

    def test_tight_bounds_match_floyd_warshall(self):
        rng = random.Random(99)
        for trial in range(40):
            solver = self.random_system(rng, nodes=4, edges=5)
            result = solver.solve()
            fw_ok, fw = floyd_warshall(solver.constraints)
            with self.subTest(trial=trial):
                self.assertEqual(result.feasible, fw_ok)
                if result.feasible:
                    for key, value in result.tight.items():
                        self.assertEqual(value, fw[key], key)

    def test_witness_satisfies_every_constraint(self):
        rng = random.Random(2026)
        for trial in range(40):
            solver = self.random_system(rng, nodes=5, edges=7)
            result = solver.solve()
            if not result.feasible:
                continue
            with self.subTest(trial=trial):
                self.assertEqual(check_assignment(solver.constraints, result.solution), [])


class ExhaustiveSearchTests(unittest.TestCase):
    def test_brute_force_finds_the_same_answer(self):
        solver = system(
            ("hi", EPOCH, "A", 3), ("lo", "A", EPOCH, 1),
            ("hi", EPOCH, "B", 3), ("lo", "B", EPOCH, 1),
            ("seq", "B", "A", -1),
        )
        result = solver.solve()
        self.assertTrue(result.feasible)
        candidates = {e: grid_candidates(0, 4, 5) for e in ("A", "B")}
        witness = exhaustive_search(solver.constraints, candidates)
        self.assertIsNotNone(witness)
        self.assertEqual(check_assignment(solver.constraints, witness), [])
        self.assertLess(witness["A"], witness["B"])

    def test_brute_force_confirms_infeasibility(self):
        solver = system(
            ("hi", EPOCH, "A", 0), ("lo", "A", EPOCH, 0),
            ("hi", EPOCH, "B", 0), ("lo", "B", EPOCH, 0),
            ("seq", "B", "A", -1),
        )
        self.assertFalse(solver.solve().feasible)
        candidates = {e: grid_candidates(-1, 1, 3) for e in ("A", "B")}
        self.assertIsNone(exhaustive_search(solver.constraints, candidates))


class DeletionMinimiseTests(unittest.TestCase):
    def test_returns_a_subset_and_keeps_infeasibility(self):
        solver = system(
            ("hi", EPOCH, "A", 0), ("lo", "A", EPOCH, 0),
            ("hi", EPOCH, "B", 0), ("lo", "B", EPOCH, 0),
            ("seq", "B", "A", -1),
            ("noise", "A", "B", 100),
        )
        constraints = list(solver.constraints)

        def infeasible(subset):
            ok = True
            from solution.constraints import bellman_ford

            ok, _, _ = bellman_ford(subset)
            return not ok

        core = deletion_minimise(constraints, infeasible)
        self.assertTrue(infeasible(core))
        self.assertLess(len(core), len(constraints))
        for c in core:
            self.assertFalse(infeasible([x for x in core if x.cid != c.cid]))


if __name__ == "__main__":
    unittest.main()
