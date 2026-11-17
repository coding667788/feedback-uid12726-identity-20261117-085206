"""The end-to-end pipeline: cases.json in, result.json out.

Stages, in order, each of which only ever reads:

1. load ``cases.json`` and validate it;
2. load the collection manifest (if any) and check the optional seal;
3. read every source file **twice**, hash both reads and compare;
4. verify the source digests against the manifest entries (when given);
5. parse every line into typed records while recording line numbers and byte
   ranges, deduplicating only byte-identical content;
6. build the difference-constraint model and solve it exactly;
7. render timeline, partial order, feasible windows, conflicts, minimal cores
   and the deterministic topological display;
8. re-read and re-hash every source **after** all analysis, compare against
   the first read, and write the result JSON atomically.

Nothing in the pipeline opens a source file for writing, and the final hash
check would catch it if something did.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from . import analysis as analysis_mod
from .collect import Collection, collect
from .constraints import bellman_ford
from .errors import Diagnostic, ToolError
from .integrity import sha256_bytes
from .manifest import (
    Manifest,
    digest_of_manifest_body,
    load_manifest,
    manifest_key_from_env,
)
from .manifest import digest_of_manifest_body
from .model import build_model
from .render import build_graph
from .sources import SourceBytes, read_source, resolve_inside
from .verify import check_assignment, floyd_warshall, fourier_motzkin

RESULT_SCHEMA = "evidence-reconstruction/result-v1"
CASES_SCHEMA = "evidence-reconstruction/cases-v1"
TOOL_VERSION = "1.0.0"


@dataclass
class CaseInput:
    path: str
    root: str
    case_id: str | None
    sources: list[dict[str, Any]]
    manifest_path: str | None
    drift_ppm: int
    seed: int
    options: dict[str, Any] = field(default_factory=dict)


def load_cases(path: str) -> CaseInput:
    try:
        with open(path, "rb") as handle:
            raw_bytes = handle.read()
    except FileNotFoundError:
        raise ToolError("E_INPUT_MISSING", f"cases file not found: {path}") from None
    except OSError as exc:
        raise ToolError("E_INPUT_IO", f"cases file could not be read: {exc.strerror or exc}") from None
    try:
        raw = json.loads(raw_bytes.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolError("E_INPUT_JSON", f"cases file is not valid JSON: {exc}") from None
    if not isinstance(raw, dict):
        raise ToolError("E_INPUT_SCHEMA", "cases file must be a JSON object")
    schema = raw.get("schema", CASES_SCHEMA)
    if schema != CASES_SCHEMA:
        raise ToolError(
            "E_INPUT_SCHEMA",
            f"unsupported cases schema {schema!r} (expected {CASES_SCHEMA})",
        )
    sources = raw.get("sources", [])
    if not isinstance(sources, list):
        raise ToolError("E_INPUT_SCHEMA", "'sources' must be an array")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(sources):
        if isinstance(item, str):
            item = {"path": item}
        if not isinstance(item, dict):
            raise ToolError("E_INPUT_SCHEMA", f"sources[{index}] must be a string or object")
        source_path = item.get("path")
        if not isinstance(source_path, str) or not source_path:
            raise ToolError("E_INPUT_SCHEMA", f"sources[{index}] has no 'path'")
        source_id = item.get("id") or os.path.splitext(os.path.basename(source_path))[0]
        if not isinstance(source_id, str) or not source_id:
            raise ToolError("E_INPUT_SCHEMA", f"sources[{index}] has an invalid 'id'")
        normalized.append({"id": source_id, "path": source_path})
    ids = [s["id"] for s in normalized]
    if len(set(ids)) != len(ids):
        raise ToolError("E_INPUT_SCHEMA", "source ids must be unique")
    manifest_path = raw.get("manifest")
    if manifest_path is not None and not isinstance(manifest_path, str):
        raise ToolError("E_INPUT_SCHEMA", "'manifest' must be a string path")
    drift = raw.get("drift_ppm", 0)
    if isinstance(drift, bool) or not isinstance(drift, int) or drift < 0:
        raise ToolError("E_INPUT_SCHEMA", "'drift_ppm' must be a non-negative integer")
    seed = raw.get("seed", 0)
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ToolError("E_INPUT_SCHEMA", "'seed' must be an integer")
    options = raw.get("options") or {}
    if not isinstance(options, dict):
        raise ToolError("E_INPUT_SCHEMA", "'options' must be an object")
    return CaseInput(
        path=os.path.realpath(path),
        root=os.path.dirname(os.path.realpath(path)),
        case_id=raw.get("case_id") if isinstance(raw.get("case_id"), str) else None,
        sources=normalized,
        manifest_path=manifest_path,
        drift_ppm=drift,
        seed=seed,
        options=options,
    )


def run_case(case: CaseInput) -> dict[str, Any]:
    diagnostics: list[Diagnostic] = []
    stage_log: list[dict[str, Any]] = []

    manifest: Manifest | None = None
    if case.manifest_path:
        manifest_path = resolve_inside(case.root, case.manifest_path)
        manifest, manifest_diags = load_manifest(manifest_path, manifest_key_from_env())
        diagnostics.extend(manifest_diags)
        stage_log.append(
            {
                "stage": "manifest",
                "path": manifest_path,
                "entries": len(manifest.entries),
                "seal_state": manifest.seal_state,
            }
        )

    # --- stage: read + hash (first read) --------------------------------
    sources: list[SourceBytes] = []
    source_reports: list[dict[str, Any]] = []
    for spec in case.sources:
        source, _ = read_source(spec["id"], spec["path"], case.root)
        sources.append(source)
    stage_log.append({"stage": "read", "sources": len(sources)})

    # --- stage: manifest cross-check ------------------------------------
    if manifest is not None:
        entry_by_id = {e.id: e for e in manifest.entries}
        entry_by_path = {os.path.normpath(e.path): e for e in manifest.entries}
        for source in sources:
            entry = entry_by_id.get(source.source_id)
            if entry is None:
                rel = os.path.relpath(source.path, case.root).replace(os.sep, "/")
                entry = entry_by_path.get(os.path.normpath(rel))
            report: dict[str, Any] = {
                "id": source.source_id,
                "path": os.path.relpath(source.path, case.root).replace(os.sep, "/"),
                "sha256": source.sha256,
                "bytes": source.size,
                "manifest_match": False,
            }
            if entry is None:
                diagnostics.append(
                    Diagnostic(
                        code="E_MANIFEST_MISSING_ENTRY",
                        message=f"source {source.source_id!r} is not listed in the collection manifest",
                        source_id=source.source_id,
                        detail={"path": source.path},
                    )
                )
            else:
                report["manifest_sha256"] = entry.sha256
                report["manifest_bytes"] = entry.size
                ok = True
                if entry.sha256 is not None and entry.sha256.lower() != source.sha256:
                    ok = False
                    diagnostics.append(
                        Diagnostic(
                            code="E_MANIFEST_HASH_MISMATCH",
                            message=(
                                f"source {source.source_id!r} hashes to {source.sha256} "
                                f"but the manifest records {entry.sha256}"
                            ),
                            source_id=source.source_id,
                            detail={"actual": source.sha256, "expected": entry.sha256},
                        )
                    )
                if entry.size is not None and entry.size != source.size:
                    ok = False
                    diagnostics.append(
                        Diagnostic(
                            code="E_MANIFEST_HASH_MISMATCH",
                            message=(
                                f"source {source.source_id!r} is {source.size} bytes "
                                f"but the manifest records {entry.size}"
                            ),
                            source_id=source.source_id,
                            detail={"actual_bytes": source.size, "expected_bytes": entry.size},
                        )
                    )
                report["manifest_match"] = ok
            source_reports.append(report)
        analysed = {report["path"] for report in source_reports} | {
            report["id"] for report in source_reports
        }
        for entry in manifest.entries:
            if entry.id in analysed or os.path.normpath(entry.path) in {
                os.path.normpath(path) for path in analysed
            }:
                continue
            diagnostics.append(
                Diagnostic(
                    code="E_MANIFEST_EXTRA_ENTRY",
                    message=(
                        f"the manifest lists {entry.path!r} but it was not among the "
                        "analysed sources; the result does not cover it"
                    ),
                    detail={"entry": entry.to_json()},
                )
            )
    else:
        for source in sources:
            source_reports.append(
                {
                    "id": source.source_id,
                    "path": os.path.relpath(source.path, case.root).replace(os.sep, "/"),
                    "sha256": source.sha256,
                    "bytes": source.size,
                    "manifest_match": None,
                }
            )

    # --- stage: parse + dedupe ------------------------------------------
    collection, collect_diags = collect(sources)
    diagnostics.extend(collect_diags)
    stage_log.append(
        {
            "stage": "collect",
            "records": sum(len(n.occurrences) for n in collection.events.values()),
            "events": len(collection.events),
            "conflicts": len(collection.conflicts),
            "sources": [s.source_id for s in sources],
        }
    )

    # --- stage: model + solve -------------------------------------------
    try:
        model = build_model(collection, drift_ppm=case.drift_ppm)
    except ValueError as exc:
        raise ToolError("E_INPUT_SCHEMA", f"cannot build the time model: {exc}") from None
    # ``analyse`` starts from the model diagnostics, so they are not added twice.
    analysis = analysis_mod.analyse(model, collection)
    diagnostics.extend(analysis.diagnostics)
    stage_log.append(
        {
            "stage": "solve",
            "feasible": analysis.feasible,
            "constraints": len(model.solver.constraints),
            "variables": len(model.solver.nodes),
            "cores": len(analysis.cores),
        }
    )

    # --- stage: independent cross-check ---------------------------------
    cross_check = cross_check_model(model, analysis)
    stage_log.append({"stage": "crosscheck", "ok": cross_check["ok"]})

    # --- stage: integrity re-read ---------------------------------------
    integrity = integrity_report(case, sources, manifest)
    stage_log.append({"stage": "integrity", "sources_unchanged": integrity["sources_unchanged"]})

    timeline = analysis_mod.render_timeline(model, analysis.result)
    pairs, total_pairs = analysis_mod.render_pairs(model, analysis)
    windows = analysis_mod.render_windows(model, analysis.result)

    conflicts_json = [c.to_json() for c in collection.conflicts]

    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "tool": {"name": "solution", "version": TOOL_VERSION},
        "case": {
            "case_id": case.case_id,
            "cases_file": os.path.basename(case.path),
            "seed": case.seed,
            "drift_ppm": case.drift_ppm,
            "resolution_ns": 1,
        },
        "status": status_of(analysis, collection, diagnostics),
        "sources": source_reports,
        "manifest": manifest.to_json() if manifest else None,
        "integrity": integrity,
        "models": {
            "boots": [
                b.to_json()
                for b in sorted(model.boots.values(), key=lambda b: (b.host, b.boot_id))
            ],
            "messages": [m.to_json() for m in model.bindings],
            "constraints": [c.to_json() for c in model.solver.constraints],
            "excluded_events": [
                {"id": eid, "reason": code} for eid, code in sorted(model.excluded.items())
            ],
        },
        "timeline": timeline,
        "windows": windows,
        "order": {
            "feasible": analysis.feasible,
            "event_count": len(analysis.order.ids),
            "pair_count": total_pairs,
            "comparable_pairs": analysis.order.comparable_count(),
            "concurrent_pairs": analysis.concurrent_pairs,
            "pairwise": pairs,
            "pairwise_truncated": pairs is None,
            "precedes": {k: v for k, v in sorted(analysis.order.precedes.items())},
            "follows": {k: v for k, v in sorted(analysis.order.follows.items())},
            "concurrent": {k: v for k, v in sorted(analysis.order.concurrent.items())},
            "topological": analysis.topological,
        },
        "graph": build_graph(model, analysis),
        "conflicts": conflicts_json,
        "unsat_cores": analysis.cores,
        "quarantine": analysis.quarantine,
        "cross_check": cross_check,
        "diagnostics": [d.to_json() for d in diagnostics],
        "errors": sorted({d.code for d in diagnostics}),
    }
    return result


def status_of(analysis: "analysis_mod.Analysis", collection: Collection,
              diagnostics: list[Diagnostic]) -> str:
    """Roll the diagnostics up into the one-word status.

    ``E_DUPLICATE`` never downgrades the status: a merged identical copy loses
    nothing.  Everything that removes or weakens evidence does.
    """
    if not analysis.feasible:
        return "contradiction"
    if any(d.fatal for d in diagnostics):
        return "error"
    if collection.conflicts:
        return "conflict"
    if any(d.code in PARTIAL_CODES for d in diagnostics):
        return "partial"
    return "ok"


#: Record-level codes that mean "the timeline is usable but incomplete or
#: partly unverified".  A byte-identical duplicate (``E_DUPLICATE``) is
#: deliberately absent: merging it loses no information.
PARTIAL_CODES = frozenset({
    "E_SIG_INVALID",
    "E_SIG_UNVERIFIED",
    "E_SIG_MISSING",
    "E_BOOT_MISSING",
    "E_DANGLING",
    "E_MESSAGE_PAIR",
    "E_SEQ_DUP",
    "E_MONO_ANOMALY",
    "E_REBOOT_ORDER",
    "E_SEAL_INVALID",
    "E_SEAL_UNVERIFIED",
    "E_MANIFEST_HASH_MISMATCH",
    "E_MANIFEST_MISSING_ENTRY",
    "E_MANIFEST_EXTRA_ENTRY",
})


def cross_check_model(model, analysis) -> dict[str, Any]:
    """Second opinion on feasibility, using independent algorithms."""
    constraints = model.solver.constraints
    if analysis.feasible:
        assignment = dict(analysis.result.solution)
        violations = check_assignment(constraints, assignment)
        fw_ok, fw_dist = floyd_warshall(constraints)
        tight_mismatch = []
        for (u, v), value in sorted(analysis.result.tight.items()):
            other = fw_dist.get((u, v))
            if other != value:
                tight_mismatch.append({"u": u, "v": v, "bellman_ford": value, "floyd_warshall": other})
        point, point_residual = fourier_motzkin(constraints)
        return {
            "ok": not violations and fw_ok and not tight_mismatch and point,
            "bellman_ford_feasible": True,
            "floyd_warshall_feasible": fw_ok,
            "fourier_motzkin_feasible": point,
            "witness_violations": violations,
            "tight_bound_mismatches": tight_mismatch,
            "method": (
                "witness assignment check + Floyd-Warshall closure + "
                "Fourier-Motzkin elimination"
            ),
        }
    bf_ok, _, _ = bellman_ford(constraints)
    fw_ok, _ = floyd_warshall(constraints)
    point, residual = fourier_motzkin(constraints)
    by_id = {c.cid: c for c in constraints}
    core_reports = []
    for core in analysis.cores:
        core_constraints = [by_id[cid] for cid in core["constraint_ids"] if cid in by_id]
        core_feasible, _, _ = bellman_ford(core_constraints, anchored=False)
        core_point, _ = fourier_motzkin(core_constraints)
        deletions = []
        for c in core_constraints:
            sub = [x for x in core_constraints if x.cid != c.cid]
            sub_feasible, _, _ = bellman_ford(sub, anchored=False)
            deletions.append({"remove": c.cid, "feasible_without": sub_feasible})
        core_reports.append(
            {
                "index": core["index"],
                "core_infeasible": not core_feasible,
                "fourier_motzkin_infeasible": not core_point,
                "deletions": deletions,
                "minimal": (not core_feasible) and all(d["feasible_without"] for d in deletions),
            }
        )
    ok = (
        (not bf_ok)
        and (not fw_ok)
        and (not point)
        and bool(core_reports)
        and all(r["minimal"] for r in core_reports)
    )
    return {
        "ok": ok,
        "bellman_ford_feasible": bf_ok,
        "floyd_warshall_feasible": fw_ok,
        "fourier_motzkin_feasible": point,
        "fourier_motzkin_residual": residual if isinstance(residual, str) else None,
        "cores": core_reports,
        "method": (
            "three independent solvers agree the system is infeasible, and every "
            "reported core is re-checked to be minimal"
        ),
    }


def integrity_report(case: CaseInput, sources: list[SourceBytes], manifest: Manifest | None) -> dict[str, Any]:
    after: list[dict[str, Any]] = []
    unchanged = True
    for source in sources:
        try:
            with open(source.path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            unchanged = False
            after.append(
                {
                    "id": source.source_id,
                    "sha256_before": source.sha256,
                    "sha256_after": None,
                    "unchanged": False,
                    "error": str(exc),
                }
            )
            continue
        digest = sha256_bytes(data)
        same = digest == source.sha256
        unchanged = unchanged and same
        after.append(
            {
                "id": source.source_id,
                "sha256_before": source.sha256,
                "sha256_after": digest,
                "bytes_before": source.size,
                "bytes_after": len(data),
                "unchanged": same,
            }
        )
    return {
        "sources_unchanged": unchanged,
        "first_read": [
            {"id": s.source_id, "sha256": s.sha256, "bytes": s.size} for s in sources
        ],
        "last_read": after,
        "manifest_digest": digest_of_manifest_body(manifest) if manifest else None,
        "manifest_seal_state": manifest.seal_state if manifest else None,
        "note": (
            "every source is read twice before analysis and re-hashed after analysis; "
            "sources_unchanged is true only when all hashes agree"
        ),
    }


def write_result(result: dict[str, Any], output_path: str) -> None:
    directory = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(directory, exist_ok=True)
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=False)
    tmp = output_path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.write("\n")
        os.replace(tmp, output_path)
    except OSError as exc:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise ToolError("E_OUTPUT_WRITE", f"cannot write {output_path}: {exc.strerror or exc}") from None


def failure_result(code: str, message: str, detail: dict[str, Any] | None = None,
                   case: CaseInput | None = None) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA,
        "tool": {"name": "solution", "version": TOOL_VERSION},
        "case": {
            "case_id": case.case_id if case else None,
            "cases_file": os.path.basename(case.path) if case else None,
            "seed": case.seed if case else None,
        },
        "status": "error",
        "sources": [],
        "manifest": None,
        "integrity": {"sources_unchanged": None, "first_read": [], "last_read": []},
        "models": {"boots": [], "messages": [], "constraints": [], "excluded_events": []},
        "timeline": [],
        "windows": [],
        "order": {"feasible": False, "pairwise": [], "before": {}, "after": {},
                  "concurrent": {}, "topological": {"status": "unavailable", "sequence": []}},
        "conflicts": [],
        "unsat_cores": [],
        "cross_check": {"ok": False, "skipped": True},
        "diagnostics": [{"code": code, "message": message, "detail": detail or {}}],
        "errors": [code],
    }
