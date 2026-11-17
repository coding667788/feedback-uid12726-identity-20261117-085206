"""Integrity tests: byte-exact provenance, hashes before/after, manifest checks.

These assert *specific* hashes and byte ranges, and prove the tool never
modifies its inputs by comparing a full directory snapshot taken before and
after a run.
"""

from __future__ import annotations

import hashlib
import json
import os
import unittest

from _support import (
    BASE,
    S,
    SEED_H1,
    CaseBuilder,
    CaseDir,
    load_json,
    sha256_file,
)

from solution.integrity import compute_seal, sha256_bytes
from solution.pipeline import load_cases, run_case
from solution.sources import read_source, slice_bytes, split_lines


class IntegrityHarness(unittest.TestCase):
    def setUp(self):
        self.case_dir = CaseDir(self)
        self.builder = CaseBuilder("h1", SEED_H1)
        self.builder.boot("b1", offset_lo_ms=-100, offset_hi_ms=100)
        self.builder.event("e1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        self.builder.event("e2", "b1", 2, mono_ns=2 * S, wall_ns=BASE + 2 * S)
        self.source = self.case_dir.write("host_h1.jsonl", self.builder.render())

    def run_case(self, **kwargs):
        cases = self.case_dir.cases(["host_h1.jsonl"], **kwargs)
        return run_case(load_cases(cases))


class HashTests(IntegrityHarness):
    def test_source_digest_matches_an_independent_hash(self):
        result = self.run_case()
        reported = result["sources"][0]["sha256"]
        self.assertEqual(reported, sha256_file(self.source))
        self.assertEqual(reported, hashlib.sha256(self.builder.render()).hexdigest())

    def test_sources_unchanged_before_and_after(self):
        result = self.run_case()
        self.assertTrue(result["integrity"]["sources_unchanged"])
        first = result["integrity"]["first_read"]
        last = result["integrity"]["last_read"]
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["sha256"], last[0]["sha256_before"])
        self.assertEqual(last[0]["sha256_before"], last[0]["sha256_after"])
        self.assertEqual(first[0]["bytes"], last[0]["bytes_before"])
        self.assertEqual(last[0]["unchanged"], True)

    def test_every_occurrence_byte_range_reproduces_the_record(self):
        result = self.run_case()
        with open(self.source, "rb") as handle:
            raw = handle.read()
        for entry in result["timeline"]:
            for occ in entry["occurrences"]:
                chunk = raw[occ["byte_start"]:occ["byte_end"]]
                self.assertEqual(hashlib.sha256(chunk).hexdigest(), occ["line_sha256"])
                # The slice must be exactly one terminated line of the file.
                self.assertEqual(chunk.count(b"\n"), 1)
                # Re-parsing the slice returns the same event id.
                self.assertEqual(json.loads(chunk)["id"], entry["id"])

    def test_line_numbers_are_one_based_and_match_the_file(self):
        result = self.run_case()
        with open(self.source, "rb") as handle:
            raw = handle.read().split(b"\n")
        for entry in result["timeline"]:
            occ = entry["occurrences"][0]
            line = raw[occ["line"] - 1]
            self.assertIn(entry["id"].encode(), line)

    def test_blank_lines_do_not_shift_byte_ranges(self):
        # Two blank lines between the boot record and e2.  The blank lines must
        # not confuse line numbering or byte offsets.
        lines = self.builder.render().split(b"\n")
        # lines: [host_key, boot, e1, e2, ""]
        payload = b"\n".join(
            [lines[0], lines[1], b"", b"", lines[2], lines[3], b""]
        )
        self.case_dir.write("edge.jsonl", payload)
        cases = self.case_dir.cases(["edge.jsonl"])
        result = run_case(load_cases(cases))
        e2 = [e for e in result["timeline"] if e["id"] == "e2"][0]
        occ = e2["occurrences"][0]
        self.assertEqual(occ["line"], 6)
        chunk = payload[occ["byte_start"]:occ["byte_end"]]
        self.assertEqual(json.loads(chunk)["id"], "e2")
        self.assertEqual(chunk.count(b"\n"), 1)


class ManifestTests(IntegrityHarness):
    def build_manifest(self, *, override_sha: str | None = None, seal=True) -> str:
        with open(self.source, "rb") as handle:
            payload = handle.read()
        body = {
            "schema": "evidence-collection/manifest-v1",
            "case_id": "integrity",
            "collected_at": "2026-01-01T03:00:00Z",
            "sources": [
                {
                    "id": "host_h1",
                    "path": "host_h1.jsonl",
                    "sha256": override_sha or sha256_bytes(payload),
                    "bytes": len(payload),
                }
            ],
        }
        if seal:
            body["seal"] = compute_seal(body, b"unit-key")
        return self.case_dir.write_json("manifest.json", body)

    def test_manifest_digest_matches(self):
        self.build_manifest()
        os.environ["EVIDENCE_SEAL_KEY"] = "unit-key"
        self.addCleanup(os.environ.pop, "EVIDENCE_SEAL_KEY", None)
        result = self.run_case(manifest="manifest.json")
        self.assertTrue(result["sources"][0]["manifest_match"])
        self.assertEqual(result["manifest"]["seal_state"], "valid")
        self.assertNotIn("E_MANIFEST_HASH_MISMATCH", result["errors"])

    def test_manifest_digest_mismatch_is_reported(self):
        self.build_manifest(override_sha="0" * 64)
        result = self.run_case(manifest="manifest.json")
        self.assertFalse(result["sources"][0]["manifest_match"])
        self.assertIn("E_MANIFEST_HASH_MISMATCH", result["errors"])
        mismatch = [
            d for d in result["diagnostics"] if d["code"] == "E_MANIFEST_HASH_MISMATCH"
        ][0]
        self.assertEqual(mismatch["detail"]["expected"], "0" * 64)
        self.assertEqual(mismatch["detail"]["actual"], result["sources"][0]["sha256"])

    def test_seal_is_reported_unverified_without_a_key(self):
        self.build_manifest()
        os.environ.pop("EVIDENCE_SEAL_KEY", None)
        result = self.run_case(manifest="manifest.json")
        self.assertEqual(result["manifest"]["seal_state"], "unverified_no_key")
        self.assertIn("E_SEAL_UNVERIFIED", result["errors"])

    def test_bad_seal_is_detected_with_the_key(self):
        path = self.build_manifest()
        body = load_json(path)
        body["sources"][0]["bytes"] = 1  # edit the body, keep the old seal
        self.case_dir.write_json("manifest.json", body)
        os.environ["EVIDENCE_SEAL_KEY"] = "unit-key"
        self.addCleanup(os.environ.pop, "EVIDENCE_SEAL_KEY", None)
        result = self.run_case(manifest="manifest.json")
        self.assertEqual(result["manifest"]["seal_state"], "invalid")
        self.assertIn("E_SEAL_INVALID", result["errors"])

    def test_unlisted_source_is_reported(self):
        self.build_manifest()
        extra = CaseBuilder("h2", (b"\x02" * 32))
        extra.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        extra.event("x1", "b1", 1, mono_ns=1 * S, wall_ns=BASE)
        self.case_dir.write("host_h2.jsonl", extra.render())
        cases = self.case_dir.cases(["host_h1.jsonl", "host_h2.jsonl"], manifest="manifest.json")
        result = run_case(load_cases(cases))
        self.assertIn("E_MANIFEST_MISSING_ENTRY", result["errors"])
        entry = [
            d for d in result["diagnostics"] if d["code"] == "E_MANIFEST_MISSING_ENTRY"
        ][0]
        self.assertEqual(entry["source"], "host_h2")


class ReadOnlyTests(IntegrityHarness):
    def snapshot(self) -> dict[str, str]:
        out = {}
        for name in sorted(os.listdir(self.case_dir.dir)):
            path = os.path.join(self.case_dir.dir, name)
            if os.path.isfile(path):
                out[name] = sha256_file(path)
        return out

    def test_inputs_are_byte_identical_after_a_run(self):
        cases = self.case_dir.cases(["host_h1.jsonl"])
        before = self.snapshot()
        run_case(load_cases(cases))
        run_case(load_cases(cases))
        self.assertEqual(self.snapshot(), before)

    def test_contradictory_input_is_also_left_alone(self):
        builder = CaseBuilder("h9", b"\x09" * 32)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("s", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 10 * S,
                      kind="send", message_id="m")
        builder.event("r", "b1", 2, mono_ns=2 * S, wall_ns=BASE + 1 * S,
                      kind="recv", message_id="m")
        self.case_dir.write("host_h9.jsonl", builder.render())
        cases = self.case_dir.cases(["host_h1.jsonl", "host_h9.jsonl"])
        before = self.snapshot()
        result = run_case(load_cases(cases))
        self.assertEqual(result["status"], "contradiction")
        self.assertEqual(self.snapshot(), before)


class SourceHelperTests(unittest.TestCase):
    def test_read_source_detects_a_changed_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.jsonl")
            with open(path, "wb") as handle:
                handle.write(b"{}\n")
            source, _ = read_source("a", "a.jsonl", tmp)
            self.assertEqual(source.size, 3)
            self.assertEqual(source.digest(), hashlib.sha256(b"{}\n").hexdigest())
            self.assertEqual(slice_bytes(source, 0, 3), b"{}\n")
            self.assertEqual(split_lines(source.data)[0].line, 1)
            with self.assertRaises(ValueError):
                slice_bytes(source, 0, 99)

    def test_read_source_refuses_to_escape_the_root(self):
        from solution.errors import ToolError
        from solution.sources import read_source as read

        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ToolError) as ctx:
                read("outside", "../escape.jsonl", tmp)
            self.assertEqual(ctx.exception.code, "E_PATH_OUTSIDE_ROOT")


if __name__ == "__main__":
    unittest.main()
