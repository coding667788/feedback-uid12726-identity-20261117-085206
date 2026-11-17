"""Malformed, hostile and partially valid input handling.

Each test feeds a specific defect and asserts the specific diagnostic, the
specific event set that survives, and that one bad record never takes the
rest of the batch down with it.
"""

from __future__ import annotations

import json
import unittest

from _support import (
    BASE,
    S,
    SEED_H1,
    SEED_H2,
    CaseBuilder,
    CaseDir,
    sign_record,
    timeline_event,
)

from solution.pipeline import load_cases, run_case


class MalformedInputTests(unittest.TestCase):
    def setUp(self):
        self.case_dir = CaseDir(self)

    def run_one(self, payload: bytes, **kwargs):
        self.case_dir.write("input.jsonl", payload)
        cases = self.case_dir.cases(["input.jsonl"], **kwargs)
        return run_case(load_cases(cases))

    def base_lines(self) -> tuple[list[dict], bytes]:
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("e1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        return builder

    def test_invalid_json_line_is_located_and_skipped(self):
        builder = self.base_lines()
        payload = builder.render() + b'{"type": "event", broken\n'
        result = self.run_one(payload + builder.render().split(b"\n")[-2] + b"\n")
        self.assertIn("E_LINE_JSON", result["errors"])
        diag = [d for d in result["diagnostics"] if d["code"] == "E_LINE_JSON"][0]
        self.assertEqual(diag["line"], 4)
        self.assertEqual([e["id"] for e in result["timeline"]], ["e1"])

    def test_non_utf8_bytes_are_located(self):
        good = self.base_lines()
        payload = good.render() + b'{"type":"event","id":"\xff\xfe"}\n'
        result = self.run_one(payload)
        self.assertIn("E_LINE_ENCODING", result["errors"])
        diag = [d for d in result["diagnostics"] if d["code"] == "E_LINE_ENCODING"][0]
        self.assertEqual(diag["line"], 4)
        self.assertEqual([e["id"] for e in result["timeline"]], ["e1"])

    def test_missing_required_member_is_schema_error(self):
        builder = self.base_lines()
        lines = builder.render().decode().splitlines()
        record = json.loads(lines[2])
        del record["mono_ns"]
        lines[2] = json.dumps(sign_record(record, SEED_H1))
        result = self.run_one(("\n".join(lines) + "\n").encode())
        self.assertIn("E_LINE_SCHEMA", result["errors"])
        self.assertEqual(result["timeline"], [])

    def test_bad_timestamp_keeps_the_other_events(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("ok", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        bad = {
            "type": "event", "id": "bad", "host": "h1", "boot_id": "b1", "seq": 2,
            "mono_ns": 2 * S, "wall": "2026-02-30T00:00:00Z", "kind": "local",
        }
        builder.lines.append(json.dumps(sign_record(bad, SEED_H1)))
        result = self.run_one(builder.render())
        self.assertIn("E_TIMESTAMP", result["errors"])
        self.assertEqual([e["id"] for e in result["timeline"]], ["ok"])

    def test_unknown_record_type_is_rejected(self):
        builder = self.base_lines()
        payload = builder.render() + b'{"type":"mystery","host":"h1"}\n'
        result = self.run_one(payload)
        self.assertIn("E_LINE_SCHEMA", result["errors"])

    def test_bytes_with_a_bom_are_not_silently_accepted(self):
        builder = self.base_lines()
        result = self.run_one(b"\xef\xbb\xbf" + builder.render())
        self.assertIn("E_LINE_JSON", result["errors"])


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.case_dir = CaseDir(self)

    def run_sources(self, builders):
        paths = []
        for i, builder in enumerate(builders):
            name = f"src{i}.jsonl"
            self.case_dir.write(name, builder.render())
            paths.append(name)
        return run_case(load_cases(self.case_dir.cases(paths)))

    def test_tampered_wall_clock_invalidates_the_signature(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("e1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        lines = builder.render().decode().splitlines()
        record = json.loads(lines[2])
        record["wall"] = "2026-01-01T00:00:09Z"
        lines[2] = json.dumps(record)  # signature left from the old content
        self.case_dir.write("src.jsonl", ("\n".join(lines) + "\n").encode())
        result = run_case(load_cases(self.case_dir.cases(["src.jsonl"])))
        self.assertIn("E_SIG_INVALID", result["errors"])
        self.assertEqual(result["timeline"], [])

    def test_re_sign_after_edit_is_accepted(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("e1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        lines = builder.render().decode().splitlines()
        record = json.loads(lines[2])
        record["wall"] = "2026-01-01T00:00:09Z"
        lines[2] = json.dumps(sign_record(record, SEED_H1))
        self.case_dir.write("src.jsonl", ("\n".join(lines) + "\n").encode())
        result = run_case(load_cases(self.case_dir.cases(["src.jsonl"])))
        self.assertEqual(result["errors"], [])
        self.assertEqual(timeline_event(result, "e1")["wall"], "2026-01-01T00:00:09Z")

    def test_unknown_host_key_leaves_signature_unverified(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("e1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        lines = builder.render().decode().splitlines()
        self.case_dir.write("src.jsonl", ("\n".join(lines[1:]) + "\n").encode())
        result = run_case(load_cases(self.case_dir.cases(["src.jsonl"])))
        self.assertIn("E_SIG_UNVERIFIED", result["errors"])
        self.assertEqual(timeline_event(result, "e1")["signature"], "unverified")

    def test_missing_signature_with_known_key_is_an_error(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("e1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S, sign_it=False)
        self.case_dir.write("src.jsonl", builder.render())
        result = run_case(load_cases(self.case_dir.cases(["src.jsonl"])))
        self.assertIn("E_SIG_MISSING", result["errors"])
        self.assertEqual(result["timeline"], [])

    def test_signature_from_a_foreign_key_is_rejected(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        # The host key line announces h1, but this record is signed by another key.
        record = {
            "type": "event", "id": "e1", "host": "h1", "boot_id": "b1", "seq": 1,
            "mono_ns": 1 * S, "wall": "2026-01-01T00:00:01Z", "kind": "local",
        }
        builder.lines.append(json.dumps(sign_record(record, SEED_H2)))
        self.case_dir.write("src.jsonl", builder.render())
        result = run_case(load_cases(self.case_dir.cases(["src.jsonl"])))
        self.assertIn("E_SIG_INVALID", result["errors"])


class StructuralTests(unittest.TestCase):
    def setUp(self):
        self.case_dir = CaseDir(self)

    def run_sources(self, builders):
        paths = []
        for i, builder in enumerate(builders):
            name = f"src{i}.jsonl"
            self.case_dir.write(name, builder.render())
            paths.append(name)
        return run_case(load_cases(self.case_dir.cases(paths)))

    def test_event_without_a_boot_record_is_excluded_with_a_reason(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.event("orphan", "b9", 1, mono_ns=1 * S, wall_ns=BASE)
        result = self.run_sources([builder])
        self.assertIn("E_BOOT_MISSING", result["errors"])
        self.assertEqual(
            result["models"]["excluded_events"],
            [{"id": "orphan", "reason": "E_BOOT_MISSING"}],
        )
        self.assertEqual(result["timeline"], [])

    def test_conflicting_boot_calibration_is_rejected(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.boot("b1", offset_lo_ms=-1000, offset_hi_ms=1000)
        result = self.run_sources([builder])
        self.assertIn("E_BOOT_ID", result["errors"])
        # The first calibration wins and is still usable.
        self.assertEqual(
            result["models"]["boots"][0]["calibration"],
            {"offset_lo_ns": 0, "offset_hi_ns": 0},
        )

    def test_monotonic_counter_going_backwards_is_reported(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("a", "b1", 1, mono_ns=10 * S, wall_ns=BASE + 10 * S)
        builder.event("b", "b1", 2, mono_ns=5 * S, wall_ns=BASE + 11 * S)
        result = self.run_sources([builder])
        self.assertIn("E_MONO_ANOMALY", result["errors"])
        anomaly = [d for d in result["diagnostics"] if d["code"] == "E_MONO_ANOMALY"][0]
        self.assertEqual(anomaly["detail"]["events"], ["a", "b"])
        # The sequence order still holds; only the elapsed-time constraint is dropped.
        entry = [p for p in result["order"]["pairwise"] if p["a"] == "a"][0]
        self.assertEqual(entry["verdict"], "before")

    def test_duplicate_sequence_numbers_stay_unordered(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("a", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        builder.event("b", "b1", 1, mono_ns=2 * S, wall_ns=BASE + 2 * S)
        result = self.run_sources([builder])
        self.assertIn("E_SEQ_DUP", result["errors"])
        # The tie contributed no ordering constraint of its own: the only
        # reason a and b are ordered at all is that their windows are disjoint.
        constraints = result["models"]["constraints"]
        self.assertFalse([c for c in constraints if c["kind"] == "seq"])
        entry = [p for p in result["order"]["pairwise"] if p["a"] == "a"][0]
        self.assertEqual(entry["supporting_constraints"], [])
        self.assertEqual(entry["verdict"], "before")

    def test_duplicate_sequence_with_overlapping_windows_stays_concurrent(self):
        # Same seq AND overlapping windows: nothing may order these two.
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=-1_000, offset_hi_ms=1_000)
        builder.event("a", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        builder.event("b", "b1", 1, mono_ns=2 * S, wall_ns=BASE + 2 * S)
        result = self.run_sources([builder])
        self.assertIn("E_SEQ_DUP", result["errors"])
        entry = [p for p in result["order"]["pairwise"] if p["a"] == "a"][0]
        self.assertEqual(entry["verdict"], "concurrent")

    def test_message_with_two_senders_adds_no_constraint(self):
        h1 = CaseBuilder("h1", SEED_H1)
        h1.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        h1.event("s1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S, kind="send", message_id="m")
        h1.event("s2", "b1", 2, mono_ns=2 * S, wall_ns=BASE + 2 * S, kind="send", message_id="m")
        h1.event("r1", "b1", 3, mono_ns=3 * S, wall_ns=BASE + 3 * S, kind="recv", message_id="m")
        result = self.run_sources([h1])
        self.assertIn("E_MESSAGE_PAIR", result["errors"])
        constraints = [c for c in result["models"]["constraints"] if c["kind"] == "message"]
        self.assertEqual(constraints, [])
        self.assertEqual(result["models"]["messages"], [])

    def test_send_with_no_receive_is_dangling(self):
        h1 = CaseBuilder("h1", SEED_H1)
        h1.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        h1.event("s1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S, kind="send", message_id="m")
        result = self.run_sources([h1])
        self.assertIn("E_DANGLING", result["errors"])
        diag = [d for d in result["diagnostics"] if d["code"] == "E_DANGLING"][0]
        self.assertEqual(diag["detail"], {"message_id": "m", "sends": ["s1"], "receives": []})

    def test_two_receivers_is_a_pairing_error(self):
        h1 = CaseBuilder("h1", SEED_H1)
        h1.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        h1.event("s1", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S, kind="send", message_id="m")
        h1.event("r1", "b1", 2, mono_ns=2 * S, wall_ns=BASE + 2 * S, kind="recv", message_id="m")
        h1.event("r2", "b1", 3, mono_ns=3 * S, wall_ns=BASE + 3 * S, kind="recv", message_id="m")
        result = self.run_sources([h1])
        self.assertIn("E_MESSAGE_PAIR", result["errors"])

    def test_local_event_with_message_id_is_schema_error(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("e", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S,
                      kind="local", message_id="m")
        result = self.run_sources([builder])
        self.assertIn("E_LINE_SCHEMA", result["errors"])
        self.assertEqual(result["timeline"], [])

    def test_reserved_event_id_prefix_is_rejected(self):
        builder = CaseBuilder("h1", SEED_H1)
        builder.boot("b1", offset_lo_ms=0, offset_hi_ms=0)
        builder.event("@epoch", "b1", 1, mono_ns=1 * S, wall_ns=BASE + 1 * S)
        result = self.run_sources([builder])
        self.assertIn("E_LINE_SCHEMA", result["errors"])
        self.assertEqual(
            [e["reason"] for e in result["models"]["excluded_events"]],
            ["E_LINE_SCHEMA"],
        )


class ConsistencyTests(unittest.TestCase):
    """Counts that must agree with each other, on every shipped sample."""

    def test_pair_counts_add_up(self):
        import os

        from _support import ROOT

        samples = []
        base = os.path.join(ROOT, "samples")
        for entry in sorted(os.listdir(base)):
            if entry == "main":
                samples.append(os.path.join(base, entry, "cases.json"))
            elif entry == "scenarios":
                for name in sorted(os.listdir(os.path.join(base, entry))):
                    samples.append(os.path.join(base, entry, name, "cases.json"))
        self.assertGreaterEqual(len(samples), 7)
        for path in samples:
            with self.subTest(sample=os.path.relpath(path, ROOT)):
                result = run_case(load_cases(path))
                order = result["order"]
                n = order["event_count"]
                self.assertEqual(order["pair_count"], n * (n - 1) // 2)
                self.assertEqual(
                    order["comparable_pairs"] + order["concurrent_pairs"],
                    order["pair_count"],
                )
                self.assertEqual(
                    sum(len(v) for v in order["follows"].values()),
                    order["comparable_pairs"],
                )
                self.assertEqual(
                    sum(len(v) for v in order["concurrent"].values()) // 2,
                    order["concurrent_pairs"],
                )
                self.assertEqual(len(result["windows"]), n)
                self.assertEqual(len(result["timeline"]), n)


if __name__ == "__main__":
    unittest.main()
