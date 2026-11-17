"""Tests for the exported graph view (nodes, edges and Graphviz DOT)."""

from __future__ import annotations

import unittest

from _support import ROOT

from solution.pipeline import load_cases, run_case


def run_sample(*parts: str) -> dict:
    import os

    return run_case(load_cases(os.path.join(ROOT, "samples", *parts, "cases.json")))


class GraphExportTests(unittest.TestCase):
    def setUp(self):
        self.result = run_sample("scenarios", "overlap")

    def test_nodes_cover_every_timeline_event(self):
        graph = self.result["graph"]
        self.assertEqual(
            [n["id"] for n in graph["nodes"]],
            [e["id"] for e in self.result["timeline"]],
        )
        for node in graph["nodes"]:
            self.assertEqual(node["signature"], "valid")
            self.assertLessEqual(
                node["possible_interval_ns"]["lo"], node["possible_interval_ns"]["hi"]
            )

    def test_every_constraint_becomes_an_edge(self):
        graph = self.result["graph"]
        constraints = self.result["models"]["constraints"]
        evidence = [e for e in graph["edges"] if e["kind"] != "precedence"]
        # Every constraint appears exactly once, by id.
        self.assertEqual(
            sorted(e["constraint"] for e in evidence),
            sorted(c["id"] for c in constraints),
        )

    def test_edges_reference_known_endpoints(self):
        graph = self.result["graph"]
        known = {n["id"] for n in graph["nodes"]} | {"@epoch"}
        for edge in graph["edges"]:
            self.assertIn(edge["from"], known)
            self.assertIn(edge["to"], known)

    def test_precedence_edges_match_the_topological_display(self):
        graph = self.result["graph"]
        precedence = {(e["from"], e["to"]) for e in graph["edges"] if e["kind"] == "precedence"}
        topo = {(e["from"], e["to"]) for e in self.result["order"]["topological"]["edges"]}
        self.assertEqual(precedence, topo)

    def test_concurrent_pair_is_drawn_dotted(self):
        dot = self.result["graph"]["dot"]
        self.assertIn('[dir="none", style="dotted"', dot)
        self.assertIn('"ovl-db-001" -> "ovl-web-001"', dot)

    def test_dot_is_deterministic(self):
        again = run_sample("scenarios", "overlap")
        self.assertEqual(self.result["graph"]["dot"], again["graph"]["dot"])

    def test_dot_parses_as_a_simple_digraph(self):
        dot = self.result["graph"]["dot"]
        self.assertTrue(dot.startswith("digraph evidence {"))
        self.assertTrue(dot.rstrip().endswith("}"))
        self.assertEqual(dot.count("{"), dot.count("}"))
        # Every node id used by an edge is also declared as a node or epoch.
        declared = {
            line.split('"')[1]
            for line in dot.splitlines()
            if line.strip().startswith('"') and "->" not in line
        }
        for line in dot.splitlines():
            if "->" not in line:
                continue
            parts = line.split('"')
            self.assertIn(parts[1], declared | {"@epoch"})
            self.assertIn(parts[3], declared | {"@epoch"})


class GraphOnContradictionTests(unittest.TestCase):
    def test_graph_is_still_exported_without_precedence_edges(self):
        result = run_sample("scenarios", "send_recv")
        graph = result["graph"]
        self.assertEqual([e for e in graph["edges"] if e["kind"] == "precedence"], [])
        # The evidence graph itself is still complete.
        self.assertEqual(
            len([e for e in graph["edges"] if e["kind"] != "precedence"]),
            len(result["models"]["constraints"]),
        )
        self.assertIn("digraph evidence {", graph["dot"])
        self.assertNotIn('label="concurrent"', graph["dot"])


if __name__ == "__main__":
    unittest.main()
