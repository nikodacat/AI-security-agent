"""network-prober: external-scan phase of the AI-security-agent gray-box pipeline.

Public API (re-exports from submodules):

    from network_prober import (
        scan_targets,
        parse_banner,
        BANNER_RULES,
        build_port_observation,
        emit_network_state,
    )

For the CLI:

    python -m network_prober scan --target <host> --output <path>
"""

from __future__ import annotations

__version__ = "0.0.1-scaffold"

from .prober import scan_targets
from .parser import parse_banner, BANNER_RULES
from .emitter import build_port_observation, emit_network_state

__all__ = [
    "scan_targets",
    "parse_banner",
    "BANNER_RULES",
    "build_port_observation",
    "emit_network_state",
    "__version__",
]
