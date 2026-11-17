"""Command line entry point.

    python -m solution --input cases.json --output result.json

Exit codes
----------
``0``  analysis completed and the constraint system is feasible; see
       ``status`` in the result for ``ok`` / ``conflict`` / ``partial``.
``1``  analysis completed but the constraints are contradictory; the result
       contains a minimal unsatisfiable core.
``2``  the input could not be processed at all (fatal error); the result has
       one diagnostic and ``status`` is ``error``.
``3``  the result could not be written.

``--check`` reruns the internal consistency checks and exits with ``1`` when
any of them fails, without writing a result file.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback

from .errors import ToolError
from .pipeline import CaseInput, failure_result, load_cases, run_case, write_result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="Offline forensic event reconstruction over signed host event files.",
    )
    parser.add_argument("--input", required=True, metavar="CASES.json",
                        help="case description (schema evidence-reconstruction/cases-v1)")
    parser.add_argument("--output", required=True, metavar="RESULT.json",
                        help="where to write the reconstruction result")
    parser.add_argument("--check", action="store_true",
                        help="also assert internal consistency and exit 1 if it fails")
    parser.add_argument("--quiet", action="store_true", help="do not print the summary line")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    case: CaseInput | None = None
    exit_code = 0
    try:
        case = load_cases(args.input)
        result = run_case(case)
        status = result["status"]
        if status == "contradiction":
            exit_code = 1
        elif status == "error":
            exit_code = 2
    except ToolError as exc:
        result = failure_result(exc.code, exc.message, exc.detail, case)
        exit_code = 2
    except Exception as exc:  # pragma: no cover - last resort
        detail = {"exception": type(exc).__name__, "traceback": traceback.format_exc(limit=5)}
        result = failure_result("E_INTERNAL", str(exc), detail, case)
        exit_code = 2

    if args.check and not result.get("cross_check", {}).get("ok"):
        exit_code = max(exit_code, 1)

    try:
        write_result(result, args.output)
    except ToolError as exc:
        sys.stderr.write(json.dumps({"code": exc.code, "message": exc.message}, ensure_ascii=False) + "\n")
        return 3

    if not args.quiet:
        summary = {
            "status": result["status"],
            "errors": result.get("errors", []),
            "events": len(result.get("timeline", [])),
            "conflicts": len(result.get("conflicts", [])),
            "unsat_cores": len(result.get("unsat_cores", [])),
            "output": args.output,
        }
        sys.stdout.write(json.dumps(summary, ensure_ascii=False) + "\n")
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
