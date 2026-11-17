"""Offline forensic event reconstruction over signed host event files.

Public entry points:

* ``python -m solution --input cases.json --output result.json``
* :func:`solution.pipeline.run_case`
"""

from .errors import Diagnostic, ToolError
from .pipeline import load_cases, run_case, write_result

__all__ = ["Diagnostic", "ToolError", "load_cases", "run_case", "write_result"]
__version__ = "1.0.0"
