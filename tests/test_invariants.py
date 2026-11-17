"""Global invariants over every shipped sample.

Where the per-scenario tests assert one specific fact, this file asserts the
properties that must hold in *every* result the tool produces:

* the JSON matches the documented key set at every level used by a consumer;
* if a pair is ordered the reverse pair agrees (antisymmetry);
* if a pair is reported concurrent, neither direction has a <= -1 bound;
* the topological sequence is a linear extension of the proven order;
* every constraint referenced by an event core exists in ``models.constraints``;
* every core is genuinely minimal when re-checked with a second solver;
* the integrity section is internally consistent (hashes agree).
"""

from __future__ import annotations

import os
import unittest

from _support import ROOT

from solution.constraints import Constraint, bellman_ford
from solution.pipeline import load_cases, run_case
from solution.verify import floyd_warshall, fourier_motzkin


def all_samples() -> list[str]:
    base = os.path.join(ROOT, "samples")
    out = []
    for entry in sorted(os.listdir(base)):
        if entry == "main":
            out.append(os.path.join(base, entry, "cases.json"))
        elif entry == "scenarios":
            for name in sorted(os.listdir(os.path.join(base, entry))):
                case = os.path.join(base, entry, name, "cases.json")
                if os.path.exists(case):
                    out.append(case)
    return out


class GlobalInvariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.samples = {}
        for path in all_samples():
            cls.samples[os.path.relpath(path, ROOT)] = run_case(load_cases(path))

    # -- structural ------------------------------------------------------
    def test_status_is_one_of_the_documented_values(self):
        for name, result in self.samples.items():
            with self.subTest(sample=name):
                self.assertIn(
                    result["status"], {"ok", "partial", "conflict", "contradiction", "error"}
                )

    def test_errors_list_matches_diagnostics(self):
        for name, result in self.samples.items():
            with self.subTest(sample=name):
                self.assertEqual(
                    result["errors"],
                    sorted({d["code"] for d in result["diagnostics"]}),
                )

    def test_every_diagnostic_has_a_registered_code(self):
        from solution.errors import ALL_CODES

        for name, result in self.samples.items():
            for diag in result["diagnostics"]:
                with self.subTest(sample=name, code=diag["code"]):
                    self.assertIn(diag["code"], ALL_CODES)
                    self.assertTrue(diag["message"])

    def test_source_reports_are_all_hashed(self):
        for name, result in self.samples.items():
            with self.subTest(sample=name):
                for entry in result["sources"]:
                    self.assertEqual(len(entry["sha256"]), 64)
                    self.assertGreater(entry["bytes"], 0)

    # -- order algebra ---------------------------------------------------
    def test_antisymmetry(self):
        for name, result in self.samples.items():
            order = result["order"]
            for a, succ in order["follows"].items():
                for b in succ:
                    with self.subTest(sample=name, a=a, b=b):
                        self.assertIn(a, order["precedes"][b])
                        self.assertNotIn(b, order["precedes"][a])

    def test_concurrent_is_symmetric(self):
        for name, result in self.samples.items():
            order = result["order"]
            for a, others in order["concurrent"].items():
                for b in others:
                    with self.subTest(sample=name, a=a, b=b):
                        self.assertIn(a, order["concurrent"][b])

    def test_pairwise_rows_agree_with_the_closure(self):
        for name, result in self.samples.items():
            order = result["order"]
            for row in order["pairwise"] or []:
                a, b = row["a"], row["b"]
                with self.subTest(sample=name, a=a, b=b):
                    if row["verdict"] == "before":
                        self.assertIn(b, order["follows"][a])
                        self.assertEqual(row["precedes"], a)
                    elif row["verdict"] == "after":
                        self.assertIn(a, order["follows"][b])
                        self.assertEqual(row["precedes"], b)
                    elif row["verdict"] == "concurrent":
                        self.assertIn(b, order["concurrent"][a])
                        self.assertIsNone(row["precedes"])
                    else:
                        self.assertEqual(row["verdict"], "unknown")
                        self.assertFalse(order["feasible"])

    def test_no_order_is_ever_claimed_from_overlap_alone(self):
        """A concurrent pair must have both direction bounds > 0 (or unknown)."""
        for name, result in self.samples.items():
            for row in result["order"]["pairwise"] or []:
                if row["verdict"] != "concurrent":
                    continue
                bounds = row["separation_bounds_ns"]
                with self.subTest(sample=name, a=row["a"], b=row["b"]):
                    for value in bounds.values():
                        if value is not None:
                            self.assertGreater(value, -1)

    # -- topological display --------------------------------------------
    def test_topological_sequence_respects_every_proven_order(self):
        for name, result in self.samples.items():
            topo = result["order"]["topological"]
            if topo["status"] != "ok":
                continue
            position = {event: i for i, event in enumerate(topo["sequence"])}
            self.assertEqual(len(position), len(result["timeline"]))
            for a, succ in result["order"]["follows"].items():
                for b in succ:
                    with self.subTest(sample=name, a=a, b=b):
                        self.assertLess(position[a], position[b])

    def test_topological_edges_equal_the_transitive_reduction(self):
        for name, result in self.samples.items():
            topo = result["order"]["topological"]
            if topo["status"] != "ok":
                continue
            follows = result["order"]["follows"]
            for edge in topo["edges"]:
                a, b = edge["from"], edge["to"]
                with self.subTest(sample=name, edge=(a, b)):
                    self.assertIn(b, follows[a])
                    # No intermediate node: the edge is not implied away.
                    for c in follows[a]:
                        if c == b:
                            continue
                        self.assertNotIn(b, follows[c])

    # -- cores -----------------------------------------------------------
    def test_core_constraints_exist_in_the_model(self):
        for name, result in self.samples.items():
            ids = {c["id"] for c in result["models"]["constraints"]}
            for core in result["unsat_cores"]:
                for cid in core["constraint_ids"]:
                    with self.subTest(sample=name, cid=cid):
                        self.assertIn(cid, ids)

    def test_each_core_is_minimal_under_three_oracles(self):
        for name, result in self.samples.items():
            if not result["unsat_cores"]:
                continue
            by_id = {
                c["id"]: Constraint(
                    cid=c["id"], kind=c["kind"], src=c["from"], dst=c["to"],
                    weight=c["weight_ns"], refs=tuple(c["events"]), note=c["note"],
                )
                for c in result["models"]["constraints"]
            }
            for core in result["unsat_cores"]:
                constraints = [by_id[cid] for cid in core["constraint_ids"]]
                with self.subTest(sample=name, core=core["index"]):
                    bf_ok, _, _ = bellman_ford(constraints)
                    fw_ok, _ = floyd_warshall(constraints)
                    fm_ok, _ = fourier_motzkin(constraints)
                    self.assertFalse(bf_ok)
                    self.assertFalse(fw_ok)
                    self.assertFalse(fm_ok)
                    for c in constraints:
                        subset = [x for x in constraints if x.cid != c.cid]
                        if not subset:
                            continue
                        self.assertTrue(bellman_ford(subset)[0], c.cid)
                        self.assertTrue(floyd_warshall(subset)[0], c.cid)
                        self.assertTrue(fourier_motzkin(subset)[0], c.cid)

    def test_core_cycle_sums_to_a_negative_number(self):
        for name, result in self.samples.items():
            for core in result["unsat_cores"]:
                contradiction = core["contradiction"]
                if contradiction is None:
                    continue
                with self.subTest(sample=name, core=core["index"]):
                    self.assertLess(contradiction["total_weight_ns"], 0)
                    self.assertEqual(
                        len(contradiction["requirements"]),
                        len(contradiction["cycle"]),
                    )

    # -- integrity -------------------------------------------------------
    def test_integrity_hashes_agree_everywhere(self):
        for name, result in self.samples.items():
            integrity = result["integrity"]
            with self.subTest(sample=name):
                self.assertTrue(integrity["sources_unchanged"])
                first = {e["id"]: e["sha256"] for e in integrity["first_read"]}
                last = {e["id"]: e["sha256_after"] for e in integrity["last_read"]}
                self.assertEqual(first, last)
                reported = {e["id"]: e["sha256"] for e in result["sources"]}
                self.assertEqual(first, reported)

    def test_cross_check_passed_on_every_sample(self):
        for name, result in self.samples.items():
            with self.subTest(sample=name):
                self.assertTrue(result["cross_check"]["ok"], result["cross_check"])


if __name__ == "__main__":
    unittest.main()
