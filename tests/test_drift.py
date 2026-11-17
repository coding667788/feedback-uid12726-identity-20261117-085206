"""Tests for the monotonic drift budget (``drift_ppm``).

Scenario: the host's monotonic counter runs slightly fast, so each 20 s
interval of counter time corresponds to slightly less wall time.  With a
+-1 ms calibration the wall readings can absorb at most 2 ms per interval, so
a 3 ms deviation is a contradiction unless the drift budget covers it.
"""

from __future__ import annotations

import unittest

from _support import BASE, MS, S, SEED_H1, CaseBuilder, CaseDir

from solution.pipeline import load_cases, run_case

STEP_MONO = 20 * S
STEP_WALL = 20 * S - 3 * MS   # counter gains 3 ms per interval
CAL_MS = 1                    # +-1 ms, i.e. 2 ms of slack per interval
# Over the four intervals the counter gains 4 x 3 ms = 12 ms while wall time
# advances 12 ms less.  The two +-1 ms windows let t5 - t1 be as small as
# 80 s - 12 ms - 2 ms, so the drift budget must cover 10 ms over 80 s:
# 10 ms / 80 s = 125 ppm exactly.  The test pins that exact threshold.
THRESHOLD_PPM = 125


class DriftBudgetTests(unittest.TestCase):
    def setUp(self):
        self.case_dir = CaseDir(self)
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=-CAL_MS, offset_hi_ms=CAL_MS)
        for i in range(1, 6):
            builder.event(
                f"e{i}", "b1", i,
                mono_ns=i * STEP_MONO,
                wall_ns=BASE + i * STEP_WALL,
            )
        self.case_dir.write("d.jsonl", builder.render())

    def run_with(self, drift_ppm: int) -> dict:
        return run_case(load_cases(self.case_dir.cases(["d.jsonl"], drift_ppm=drift_ppm)))

    def test_zero_drift_budget_is_contradictory(self):
        result = self.run_with(0)
        self.assertEqual(result["status"], "contradiction")
        kinds = {m["constraint"]["kind"] for m in result["unsat_cores"][0]["constraints"]}
        self.assertIn("mono_elapsed", kinds)

    def test_sufficient_drift_budget_restores_feasibility(self):
        result = self.run_with(200)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["case"]["drift_ppm"], 200)
        pairs = {(p["a"], p["b"]): p for p in result["order"]["pairwise"]}
        self.assertEqual(pairs[("e1", "e5")]["verdict"], "before")

    def test_exact_threshold_is_sufficient(self):
        result = self.run_with(THRESHOLD_PPM)
        self.assertEqual(result["status"], "ok")
        # The bound is exactly tight: the witness must use every nanosecond.
        windows = {w["id"]: w for w in result["windows"]}
        self.assertTrue(windows["e1"]["narrowed"] or windows["e5"]["narrowed"])

    def test_one_ppm_below_the_threshold_is_contradictory(self):
        result = self.run_with(THRESHOLD_PPM - 1)
        self.assertEqual(result["status"], "contradiction")

    def test_boot_level_drift_overrides_the_case_default(self):
        # Rebuild with drift declared on the boot record instead.
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=-CAL_MS, offset_hi_ms=CAL_MS, drift_ppm=200)
        for i in range(1, 6):
            builder.event(
                f"e{i}", "b1", i,
                mono_ns=i * STEP_MONO,
                wall_ns=BASE + i * STEP_WALL,
            )
        self.case_dir.write("d.jsonl", builder.render())
        result = self.run_with(0)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["models"]["boots"][0]["drift_ppm"], 200)

    def test_negative_drift_is_rejected_at_load_time(self):
        from solution.errors import ToolError

        path = self.case_dir.write_json(
            "cases.json",
            {
                "schema": "evidence-reconstruction/cases-v1",
                "drift_ppm": -5,
                "sources": ["d.jsonl"],
            },
        )
        with self.assertRaises(ToolError) as ctx:
            load_cases(path)
        self.assertEqual(ctx.exception.code, "E_INPUT_SCHEMA")


if __name__ == "__main__":
    unittest.main()
