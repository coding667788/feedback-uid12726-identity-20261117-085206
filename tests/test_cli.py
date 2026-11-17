"""CLI tests: exit codes, output file, and the documented error codes.

The CLI is exercised the way a user runs it — ``python -m solution`` as a
child process — so argument handling, exit codes and the on-disk result are
all covered, not just the library functions.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from _support import BASE, S, SEED_H1, ROOT, CaseBuilder, CaseDir, load_json


def run_cli(*args: str, cwd: str | None = None, env_extra: dict | None = None):
    env = dict(os.environ)
    env.pop("EVIDENCE_SEAL_KEY", None)
    # Run the tool exactly as documented: from the project root, without
    # PYTHONPATH help.  A stale PYTHONPATH from the caller would mask bugs.
    env.pop("PYTHONPATH", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "solution", *args],
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
    )


class CliTests(unittest.TestCase):
    def setUp(self):
        self.case_dir = CaseDir(self)
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=-100, offset_hi_ms=100)
        builder.event("e1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        builder.event("e2", "b1", 2, mono_ns=2 * S, wall_ns=BASE + 2 * S)
        self.source = self.case_dir.write("host_h1.jsonl", builder.render())
        self.cases = self.case_dir.cases(["host_h1.jsonl"], case_id="cli-ok")
        self.out = os.path.join(self.case_dir.dir, "result.json")

    def test_successful_run_writes_result_and_exits_zero(self):
        proc = run_cli("--input", self.cases, "--output", self.out)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.exists(self.out))
        result = load_json(self.out)
        self.assertEqual(result["schema"], "evidence-reconstruction/result-v1")
        self.assertEqual(result["status"], "ok")
        self.assertEqual([e["id"] for e in result["timeline"]], ["e1", "e2"])
        # The summary line on stdout is JSON and reports the same status.
        summary = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["events"], 2)

    def test_output_directory_is_created(self):
        nested = os.path.join(self.case_dir.dir, "a", "b", "result.json")
        proc = run_cli("--input", self.cases, "--output", nested)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.exists(nested))

    def test_contradiction_exits_one(self):
        builder = CaseBuilder("h9", b"\x09" * 32)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("s", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 10 * S,
                      kind="send", message_id="m")
        builder.event("r", "b1", 2, mono_ns=2 * S, wall_ns=BASE + 1 * S,
                      kind="recv", message_id="m")
        self.case_dir.write("host_h9.jsonl", builder.render())
        cases = self.case_dir.cases(["host_h9.jsonl"], case_id="cli-contradiction")
        proc = run_cli("--input", cases, "--output", self.out)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        result = load_json(self.out)
        self.assertEqual(result["status"], "contradiction")
        self.assertEqual(len(result["unsat_cores"]), 1)

    def test_missing_cases_file_exits_two_with_code(self):
        missing = os.path.join(self.case_dir.dir, "nope.json")
        proc = run_cli("--input", missing, "--output", self.out)
        self.assertEqual(proc.returncode, 2)
        result = load_json(self.out)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"], ["E_INPUT_MISSING"])

    def test_missing_source_file_exits_two_with_code(self):
        cases = self.case_dir.cases(["does_not_exist.jsonl"])
        proc = run_cli("--input", cases, "--output", self.out)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(load_json(self.out)["errors"], ["E_INPUT_MISSING"])

    def test_malformed_cases_json_exits_two(self):
        bad = self.case_dir.write("bad.json", b"{not json")
        proc = run_cli("--input", bad, "--output", self.out)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(load_json(self.out)["errors"], ["E_INPUT_JSON"])

    def test_unknown_cases_schema_exits_two(self):
        path = self.case_dir.write_json("cases.json", {"schema": "wrong/v9", "sources": []})
        proc = run_cli("--input", path, "--output", self.out)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(load_json(self.out)["errors"], ["E_INPUT_SCHEMA"])

    def test_source_outside_the_cases_directory_is_refused(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        outside_dir = CaseDir(self)
        outside = outside_dir.write("outside.jsonl", builder.render())
        path = self.case_dir.write_json(
            "cases.json",
            {
                "schema": "evidence-reconstruction/cases-v1",
                "sources": [{"id": "x", "path": outside}],
            },
        )
        proc = run_cli("--input", path, "--output", self.out)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(load_json(self.out)["errors"], ["E_PATH_OUTSIDE_ROOT"])

    def test_unwritable_output_exits_three(self):
        # A directory in place of the output file cannot be replaced.
        blocked = os.path.join(self.case_dir.dir, "blocked")
        os.makedirs(blocked)
        proc = run_cli("--input", self.cases, "--output", blocked)
        self.assertEqual(proc.returncode, 3)
        self.assertIn("E_OUTPUT_WRITE", proc.stderr)

    def test_check_flag_reports_cross_check_failure_status(self):
        proc = run_cli("--input", self.cases, "--output", self.out, "--check")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = load_json(self.out)
        self.assertTrue(result["cross_check"]["ok"])

    def test_quiet_suppresses_stdout(self):
        proc = run_cli("--input", self.cases, "--output", self.out, "--quiet")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")

    def test_help_exits_zero(self):
        proc = run_cli("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--input", proc.stdout)
        self.assertIn("--output", proc.stdout)

    def test_missing_required_argument_exits_two(self):
        proc = run_cli("--input", self.cases)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--output", proc.stderr)


class ErrorCodeRegistryTests(unittest.TestCase):
    def test_every_emitted_code_is_registered(self):
        from solution.errors import ALL_CODES

        # Codes emitted anywhere in the source tree must be in the registry.
        import pathlib
        import re

        pattern = re.compile(r'"(E_[A-Z_]+)"')
        seen = set()
        for path in pathlib.Path(ROOT, "solution").glob("*.py"):
            if path.name == "errors.py":
                continue
            for match in pattern.finditer(path.read_text(encoding="utf-8")):
                seen.add(match.group(1))
        self.assertTrue(seen)
        self.assertEqual(seen - ALL_CODES, set(), "unregistered error codes in solution/")

    def test_fatal_codes_are_the_documented_ones(self):
        from solution.errors import FATAL_CODES

        self.assertEqual(
            FATAL_CODES,
            {
                "E_INPUT_MISSING",
                "E_INPUT_IO",
                "E_INPUT_JSON",
                "E_INPUT_SCHEMA",
                "E_OUTPUT_WRITE",
                "E_PATH_OUTSIDE_ROOT",
                "E_SOURCE_HASH",
                "E_SOURCE_READ",
                "E_INTERNAL",
            },
        )

    def test_unregistered_code_is_rejected(self):
        from solution.errors import Diagnostic

        with self.assertRaises(ValueError):
            Diagnostic(code="E_NOT_A_CODE", message="x")


if __name__ == "__main__":
    unittest.main()
