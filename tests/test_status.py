"""Tests for the ``status`` roll-up rules.

The status is what a consumer switches on, so the mapping from diagnostics to
status is pinned here, including the cases that must *not* downgrade.
"""

from __future__ import annotations

import unittest

from _support import BASE, S, SEED_H1, CaseBuilder, CaseDir
from _support import sign_record
import json

from solution.pipeline import load_cases, run_case


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.case_dir = CaseDir(self)

    def run_sources(self, builders, **kwargs):
        paths = []
        for i, builder in enumerate(builders):
            name = f"s{i}.jsonl"
            self.case_dir.write(name, builder.render())
            paths.append(name)
        return run_case(load_cases(self.case_dir.cases(paths, **kwargs)))

    def clean(self) -> list[CaseBuilder]:
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("e1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        builder.event("e2", "b1", 2, mono_ns=2 * S, wall_ns=BASE + 2 * S)
        return [builder]

    def test_clean_case_is_ok(self):
        self.assertEqual(self.run_sources(self.clean())["status"], "ok")

    def test_identical_duplicate_does_not_downgrade(self):
        builders = self.clean()
        result = self.run_sources(builders * 2)
        self.assertIn("E_DUPLICATE", result["errors"])
        self.assertEqual(result["status"], "ok")

    def test_unverified_signature_is_partial(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("e1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        lines = builder.render().decode().splitlines()
        # Drop the host_key record: the signature cannot be checked any more.
        self.case_dir.write("s0.jsonl", ("\n".join(lines[1:]) + "\n").encode())
        result = run_case(load_cases(self.case_dir.cases(["s0.jsonl"])))
        self.assertIn("E_SIG_UNVERIFIED", result["errors"])
        self.assertEqual(result["status"], "partial")

    def test_invalid_signature_is_partial(self):
        builder = self.clean()[0]
        lines = builder.render().decode().splitlines()
        record = json.loads(lines[2])
        record["seq"] = 7
        lines[2] = json.dumps(record)  # no re-sign
        self.case_dir.write("s0.jsonl", ("\n".join(lines) + "\n").encode())
        result = run_case(load_cases(self.case_dir.cases(["s0.jsonl"])))
        self.assertIn("E_SIG_INVALID", result["errors"])
        self.assertEqual(result["status"], "partial")

    def test_dangling_message_is_partial(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("s1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S,
                      kind="send", message_id="lost")
        result = self.run_sources([builder])
        self.assertEqual(result["status"], "partial")

    def test_id_conflict_is_conflict_not_partial(self):
        original = self.clean()[0]
        lines = original.render().decode().splitlines()
        changed = json.loads(lines[3])
        changed["seq"] = 9
        other = CaseBuilder("h1", SEED_H1)
        other.records = None
        body = ("\n".join(lines[:3]) + "\n" + json.dumps(sign_record(changed, SEED_H1)) + "\n")
        self.case_dir.write("a.jsonl", original.render())
        self.case_dir.write("b.jsonl", body.encode())
        result = run_case(load_cases(self.case_dir.cases(["a.jsonl", "b.jsonl"])))
        self.assertEqual(result["status"], "conflict")

    def test_contradiction_wins_over_conflict(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("s", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 10 * S,
                      kind="send", message_id="m")
        builder.event("r", "b1", 2, mono_ns=2 * S, wall_ns=BASE + 1 * S,
                      kind="recv", message_id="m")
        result = self.run_sources([builder])
        self.assertEqual(result["status"], "contradiction")


if __name__ == "__main__":
    unittest.main()
