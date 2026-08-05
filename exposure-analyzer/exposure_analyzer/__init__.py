"""exposure-analyzer: gray-box impact-analysis for CVE candidates.

Public API (re-exports from submodules):

    from exposure_analyzer import ExposureAgent, Verdict, VerdictType

For the CLI:

    python -m exposure_analyzer --candidates <path> --host-state <path>
"""

from __future__ import annotations

__version__ = "0.0.1-scaffold"

from .verdicts import Verdict, VerdictType
from .agent import ExposureAgent

__all__ = ["ExposureAgent", "Verdict", "VerdictType", "__version__"]
