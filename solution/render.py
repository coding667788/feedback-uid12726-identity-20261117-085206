"""Rendering of the event graph in machine readable and human readable forms.

The result JSON already carries the constraints and the pairwise order; this
module adds the two views a reader actually wants to *look* at:

``graph.nodes`` / ``graph.edges``
    A flat edge list.  Edges of kind ``wall_lo`` / ``wall_hi`` / ``seq`` /
    ``message`` / ``boot_order`` / ``mono_elapsed`` are the raw evidence graph;
    edges of kind ``precedence`` are the proven, transitively reduced order.
    Timestamps are shown as integers *and* RFC 3339 so the file is readable
    and machine checkable at once.

``graph.dot``
    The same graph as deterministic Graphviz DOT text (nodes sorted by
    ``host, boot_id, seq, id``; edges sorted the same way; no timestamps in
    node ids), so a reader can render it without any dependency of this tool.
    Concurrent pairs are drawn as dotted edges to make the absence of an order
    visible instead of implied.

Nothing here writes files; the DOT text is a string in the result.
"""

from __future__ import annotations

from typing import Any

from .analysis import Analysis
from .constraints import EPOCH
from .model import Model
from .timeutil import format_rfc3339_ns

#: Constraint kinds that belong to the evidence graph (all of them, plus the
#: derived precedence edges).  Kept explicit so an unknown kind cannot leak in.
EVIDENCE_KINDS = frozenset({"wall_lo", "wall_hi", "seq", "message", "boot_order", "mono_elapsed"})


def _node_id(event_id: str) -> str:
    return f"n:{event_id}"


def build_graph(model: Model, analysis: Analysis) -> dict[str, Any]:
    nodes = []
    for event_id in analysis.order.ids:
        event = model.events[event_id]
        window = model.window(event_id) if analysis.feasible else None
        nodes.append(
            {
                "id": event.id,
                "host": event.host,
                "boot_id": event.boot_id,
                "seq": event.seq,
                "kind": event.kind,
                "message_id": event.message_id,
                "possible_interval_ns": {"lo": event.possible.lo, "hi": event.possible.hi},
                "feasible_window_ns": (
                    {"lo": window.lo, "hi": window.hi} if window is not None else None
                ),
                "wall": format_rfc3339_ns(event.wall_ns),
                "signature": event.signature,
            }
        )

    edges: list[dict[str, Any]] = []
    event_ids = set(analysis.order.ids)
    for constraint in model.solver.constraints:
        if constraint.kind not in EVIDENCE_KINDS:
            continue
        # Wall-clock constraints involve the epoch anchor; represent that with
        # an explicit "@epoch" endpoint rather than dropping the edge.
        edges.append(
            {
                "from": constraint.src if constraint.src != EPOCH else EPOCH,
                "to": constraint.dst if constraint.dst != EPOCH else EPOCH,
                "kind": constraint.kind,
                "weight_ns": constraint.weight,
                "constraint": constraint.cid,
                "events": [e for e in constraint.refs if e in event_ids],
            }
        )

    topo = analysis.topological
    for edge in topo.get("edges", []):
        edges.append(
            {
                "from": edge["from"],
                "to": edge["to"],
                "kind": "precedence",
                "weight_ns": -1,
                "constraint": None,
                "events": [edge["from"], edge["to"]],
            }
        )

    edges.sort(
        key=lambda e: (
            e["kind"] != "precedence",
            _order_key(e["from"], model),
            _order_key(e["to"], model),
            e["constraint"] or "",
        )
    )

    dot = render_dot(model, analysis)
    return {
        "nodes": nodes,
        "edges": edges,
        "edge_counts": _edge_counts(edges),
        "dot": dot,
    }


def _order_key(node: str, model: Model) -> tuple:
    if node == EPOCH:
        return ("\x00", "", "", -1, "")
    event = model.events.get(node)
    if event is None:
        return ("\xff", "", "", 0, node)
    return event.sort_key


def _edge_counts(edges: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for edge in edges:
        counts[edge["kind"]] = counts.get(edge["kind"], 0) + 1
    return dict(sorted(counts.items()))


def render_dot(model: Model, analysis: Analysis) -> str:
    """Deterministic Graphviz DOT for the event graph.

    Concurrency edges are drawn only when the constraint system is feasible:
    on a contradiction the tool knows nothing about any pair, so drawing
    "concurrent" everywhere would assert something it cannot support.
    """
    lines: list[str] = [
        "digraph evidence {",
        '  graph [rankdir="LR"];',
        '  node [shape="box", fontsize="10"];',
        '  "@epoch" [shape="point", label=""];',
    ]
    for event_id in analysis.order.ids:
        event = model.events[event_id]
        label = (
            f"{event.id}\\n{event.host}/{event.boot_id} seq={event.seq} {event.kind}"
        )
        if event.message_id:
            label += f"\\nmsg={event.message_id}"
        colour = "lightgrey" if event.signature != "valid" else "white"
        lines.append(f'  "{event_id}" [label="{label}", style="filled", fillcolor="{colour}"];')

    for constraint in model.solver.constraints:
        if constraint.kind not in EVIDENCE_KINDS:
            continue
        src = constraint.src
        dst = constraint.dst
        src_label = "@epoch" if src == EPOCH else src
        dst_label = "@epoch" if dst == EPOCH else dst
        lines.append(
            f'  "{src_label}" -> "{dst_label}" '
            f'[label="{constraint.kind} {constraint.weight}", fontsize="8", color="grey40"];'
        )

    if analysis.feasible:
        for event_id in analysis.order.ids:
            for later in analysis.order.concurrent[event_id]:
                if event_id < later:
                    lines.append(
                        f'  "{event_id}" -> "{later}" [dir="none", style="dotted", '
                        f'label="concurrent", fontsize="8", color="grey70"];'
                    )

    for edge in analysis.topological.get("edges", []):
        lines.append(
            f'  "{edge["from"]}" -> "{edge["to"]}" [color="black", penwidth="2"];'
        )

    lines.append("}")
    return "\n".join(lines) + "\n"
