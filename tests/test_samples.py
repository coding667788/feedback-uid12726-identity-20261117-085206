"""End-to-end tests over the committed sample data.

Two jobs:

1. The samples must stay reproducible: regenerating them produces identical
   bytes, so "fixed seed" is a real property of the project, not a claim.
2. Each shipped sample must keep the forensic property it was built to show,
   asserted on concrete ids, verdicts and core members.
"""

from __future__ import annotations

import importlib.util
import json
import os
import unittest

from _support import ROOT

from solution.pipeline import load_cases, run_case


def load_json_file(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def sample_case(*parts: str) -> str:
    return os.path.join(ROOT, "samples", *parts, "cases.json")


def run_sample(*parts: str) -> dict:
    return run_case(load_cases(sample_case(*parts)))


class SampleReproducibilityTests(unittest.TestCase):
    def test_generator_reproduces_the_committed_bytes(self):
        path = os.path.join(ROOT, "tools", "make_samples.py")
        spec = importlib.util.spec_from_file_location("make_samples_under_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        before = {}
        for base, _dirs, files in os.walk(os.path.join(ROOT, "samples")):
            for name in files:
                full = os.path.join(base, name)
                with open(full, "rb") as handle:
                    before[full] = handle.read()
        self.assertTrue(before, "samples/ must not be empty")

        module.main(quiet=True)

        after = {}
        for base, _dirs, files in os.walk(os.path.join(ROOT, "samples")):
            for name in files:
                full = os.path.join(base, name)
                with open(full, "rb") as handle:
                    after[full] = handle.read()
        self.assertEqual(sorted(before), sorted(after))
        changed = [name for name in before if before[name] != after.get(name)]
        self.assertEqual(changed, [], "regenerating samples changed bytes")

    def test_two_runs_of_the_same_case_agree(self):
        first = run_sample("scenarios", "overlap")
        second = run_sample("scenarios", "overlap")
        self.assertEqual(first, second)


class MainSampleTests(unittest.TestCase):
    def setUp(self):
        self.result = run_sample("main")

    def test_status_conflict_and_error_set(self):
        self.assertEqual(self.result["status"], "conflict")
        self.assertEqual(
            self.result["errors"],
            ["E_DANGLING", "E_DUPLICATE", "E_ID_CONFLICT", "E_SEAL_UNVERIFIED", "E_SIG_INVALID"],
        )

    def test_three_hosts_and_two_boots_are_modelled(self):
        boots = self.result["models"]["boots"]
        self.assertEqual(
            [(b["host"], b["boot_id"]) for b in boots],
            [("db01", "b1"), ("jump01", "b1"), ("web01", "b1"), ("web01", "b2")],
        )

    def test_integrity_is_asserted_on_every_source(self):
        self.assertTrue(self.result["integrity"]["sources_unchanged"])
        digests = {s["id"]: s["sha256"] for s in self.result["sources"]}
        for entry in self.result["sources"]:
            self.assertTrue(entry["manifest_match"], entry["id"])
            with open(os.path.join(ROOT, "samples", "main", entry["path"]), "rb") as handle:
                import hashlib

                self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), digests[entry["id"]])

    def test_tampered_record_is_dropped_not_used(self):
        invalid = [d for d in self.result["diagnostics"] if d["code"] == "E_SIG_INVALID"]
        self.assertEqual(len(invalid), 1)
        self.assertEqual(invalid[0]["source"], "host_jump01_b1_tampered")
        self.assertEqual(invalid[0]["line"], 3)
        # jump01-b1-001 exists only as the untampered copy.
        ids = [e["id"] for e in self.result["timeline"]]
        self.assertIn("jump01-b1-001", ids)
        entry = [e for e in self.result["timeline"] if e["id"] == "jump01-b1-001"][0]
        self.assertEqual(
            [o["source"] for o in entry["occurrences"]],
            ["host_jump01_b1"],
        )

    def test_duplicate_collection_merges_only_identical_content(self):
        duplicates = [d for d in self.result["diagnostics"] if d["code"] == "E_DUPLICATE"]
        self.assertEqual(len(duplicates), 8)
        db_event = [e for e in self.result["timeline"] if e["id"] == "db01-b1-001"][0]
        sources = sorted(o["source"] for o in db_event["occurrences"])
        self.assertEqual(sources, ["host_db01_b1", "host_db01_b1_copy"])

    def test_id_conflict_is_reported_and_excluded(self):
        self.assertEqual(len(self.result["conflicts"]), 1)
        self.assertEqual(self.result["conflicts"][0]["id"], "web01-b1-001")
        self.assertEqual(self.result["conflicts"][0]["variant_count"], 2)
        self.assertEqual(
            self.result["models"]["excluded_events"],
            [{"id": "web01-b1-001", "reason": "E_ID_CONFLICT"}],
        )
        self.assertNotIn("web01-b1-001", [e["id"] for e in self.result["timeline"]])

    def test_known_ordering_facts(self):
        pairs = {(p["a"], p["b"]): p for p in self.result["order"]["pairwise"]}
        # db01 received m-101 after web01 sent it.
        self.assertEqual(pairs[("db01-b1-001", "web01-b1-002")]["verdict"], "after")
        # web01 received the reply after db01 sent it.
        self.assertEqual(pairs[("db01-b1-002", "web01-b1-003")]["verdict"], "before")
        self.assertEqual(
            pairs[("db01-b1-002", "web01-b1-003")]["reason"], "message_causality"
        )
        # Same boot, increasing seq.
        self.assertEqual(pairs[("web01-b1-002", "web01-b1-003")]["verdict"], "before")
        self.assertEqual(
            pairs[("web01-b1-002", "web01-b1-003")]["reason"], "same_boot_sequence"
        )

    def test_partial_overlap_stays_concurrent(self):
        pairs = {(p["a"], p["b"]): p for p in self.result["order"]["pairwise"]}
        entries = [pairs[("jump01-b1-001", "web01-b1-003")],
                   pairs[("jump01-b1-002", "web01-b1-003")]]
        for entry in entries:
            self.assertEqual(entry["verdict"], "concurrent")
        # Their possible windows really do overlap.
        ids = {e["id"]: e for e in self.result["timeline"]}
        jump = ids["jump01-b1-001"]["possible_interval"]
        web = ids["web01-b1-003"]["possible_interval"]
        self.assertLessEqual(jump["lo_ns"], web["hi_ns"])
        self.assertLessEqual(web["lo_ns"], jump["hi_ns"])

    def test_unsatisfiable_message_is_linked_to_the_dangling_send(self):
        dangling = [d for d in self.result["diagnostics"] if d["code"] == "E_DANGLING"]
        self.assertEqual(len(dangling), 1)
        self.assertEqual(dangling[0]["detail"]["message_id"], "m-103")

    def test_topological_display_is_stable_and_certified(self):
        topo = self.result["order"]["topological"]
        self.assertEqual(topo["status"], "ok")
        self.assertEqual(len(topo["sequence"]), len(self.result["timeline"]))
        self.assertEqual(topo["certificate"]["edges_in_violation"], [])
        self.assertEqual(
            topo["certificate"]["edges_checked"],
            topo["certificate"]["edges_implied"],
        )
        self.assertEqual(topo["certificate"]["concurrent_pairs"], 4)
        self.assertGreater(topo["certificate"]["concurrent_pairs_broken_by_tie_break"], 0)


class ScenarioSampleTests(unittest.TestCase):
    def test_clock_rollback_core_mentions_the_elapsed_time(self):
        result = run_sample("scenarios", "clock_rollback")
        self.assertEqual(result["status"], "contradiction")
        first = result["unsat_cores"][0]
        kinds = [m["constraint"]["kind"] for m in first["constraints"]]
        self.assertIn("mono_elapsed", kinds)
        self.assertTrue(result["cross_check"]["ok"])

    def test_reboot_windows_and_order(self):
        result = run_sample("scenarios", "reboot")
        self.assertEqual(result["status"], "ok")
        pairs = {(p["a"], p["b"]): p for p in result["order"]["pairwise"]}
        self.assertEqual(pairs[("reboot-b2-002", "reboot-b3-001")]["reason"],
                         "declared_reboot_order")
        self.assertEqual(pairs[("reboot-b1-002", "reboot-b2-001")]["reason"],
                         "declared_reboot_order")

    def test_duplicate_sample_merges_two_of_three_copies(self):
        result = run_sample("scenarios", "duplicate")
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(len(result["timeline"]), 1)  # dup-002 survives

    def test_send_recv_sample_has_exactly_one_core(self):
        result = run_sample("scenarios", "send_recv")
        self.assertEqual(result["status"], "contradiction")
        self.assertEqual(len(result["unsat_cores"]), 1)
        members = {
            e["id"]
            for m in result["unsat_cores"][0]["constraints"]
            for e in m["events"]
        }
        self.assertEqual(members, {"sr-db-send-bad", "sr-web-recv-bad"})

    def test_overlap_sample_is_concurrent(self):
        result = run_sample("scenarios", "overlap")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["order"]["concurrent"], {"ovl-db-001": ["ovl-web-001"],
                                                         "ovl-web-001": ["ovl-db-001"]})

    def test_core_minimal_sample_is_smaller_than_the_system(self):
        result = run_sample("scenarios", "core_minimal")
        core = result["unsat_cores"][0]
        self.assertEqual(core["size"], 3)
        self.assertLess(core["size"], len(result["models"]["constraints"]))
        for entry in core["certificate"]:
            self.assertTrue(entry["feasible_without"])


class SignatureSampleTests(unittest.TestCase):
    """Re-verify the shipped sample signatures without the collector.

    This is the "a third party can check the evidence" claim: it reads the
    public keys from ``keys.json``, the raw lines from the sample files, and
    verifies with nothing but the crypto primitive and canonical JSON.
    """

    def test_every_signed_sample_record_verifies(self):
        import hashlib

        from solution.crypto.ed25519 import verify
        from solution.integrity import canonical_json_bytes

        keys = load_json_file(os.path.join(ROOT, "samples", "main", "keys.json"))
        public = {
            host: bytes.fromhex(info["public_key_hex"])
            for host, info in keys["sources"].items()
        }
        base = os.path.join(ROOT, "samples", "main")
        checked = 0
        for name in (
            "host_web01_b1.jsonl",
            "host_web01_b2.jsonl",
            "host_db01_b1.jsonl",
            "host_jump01_b1.jsonl",
            "host_web01_b1_conflict.jsonl",
        ):
            with open(os.path.join(base, name), "rb") as handle:
                for raw in handle:
                    record = json.loads(raw)
                    if "sig" not in record:
                        continue
                    body = {k: v for k, v in record.items() if k != "sig"}
                    self.assertTrue(
                        verify(
                            public[record["host"]],
                            canonical_json_bytes(body),
                            bytes.fromhex(record["sig"]),
                        ),
                        f"{name}: signature failed for {record.get('id', record.get('boot_id'))}",
                    )
                    checked += 1
        self.assertEqual(checked, 18)

    def test_tampered_sample_record_does_not_verify(self):
        from solution.crypto.ed25519 import verify
        from solution.integrity import canonical_json_bytes

        keys = load_json_file(os.path.join(ROOT, "samples", "main", "keys.json"))
        public = bytes.fromhex(keys["sources"]["jump01"]["public_key_hex"])
        path = os.path.join(ROOT, "samples", "main", "host_jump01_b1_tampered.jsonl")
        with open(path, "rb") as handle:
            for raw in handle:
                record = json.loads(raw)
                if record.get("id") != "jump01-b1-001":
                    continue
                body = {k: v for k, v in record.items() if k != "sig"}
                self.assertFalse(
                    verify(public, canonical_json_bytes(body), bytes.fromhex(record["sig"]))
                )
                return
        self.fail("tampered sample is missing jump01-b1-001")


class SchemaTests(unittest.TestCase):
    def test_result_has_the_documented_top_level_keys(self):
        result = run_sample("main")
        expected = {
            "schema", "tool", "case", "status", "sources", "manifest", "integrity",
            "models", "timeline", "windows", "order", "graph", "conflicts",
            "unsat_cores", "quarantine", "cross_check", "diagnostics", "errors",
        }
        self.assertEqual(set(result), expected)

    def test_timeline_entries_carry_the_documented_fields(self):
        result = run_sample("main")
        entry = result["timeline"][0]
        for key in (
            "id", "host", "boot_id", "seq", "kind", "message_id", "wall", "wall_ns",
            "mono_ns", "possible_interval", "signature", "occurrences",
            "feasible_window", "witness_t_ns", "witness_t",
        ):
            self.assertIn(key, entry)

    def test_json_is_serialisable_and_round_trips(self):
        result = run_sample("main")
        text = json.dumps(result, ensure_ascii=False)
        self.assertEqual(json.loads(text), result)


if __name__ == "__main__":
    unittest.main()
