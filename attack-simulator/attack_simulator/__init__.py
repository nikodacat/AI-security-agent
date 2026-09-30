"""attack-simulator: per-CONFIRMED-verdict LLM narrative generator.

Public API (re-exports from submodules):

    from attack_simulator import (
        Narrative,
        AttackSimulator,
        narratives_from_verdicts,
        dump_narratives,
        load_narratives,
        render_markdown,
    )

For the CLI:

    python -m attack_simulator narrate --verdicts <path> --output <path>
"""

from __future__ import annotations

__version__ = "0.0.1-scaffold"

from .narratives import (
    Narrative,
    dump_narratives,
    load_narratives,
    render_markdown,
)
from .narrator import AttackSimulator, narratives_from_verdicts

__all__ = [
    "Narrative",
    "AttackSimulator",
    "narratives_from_verdicts",
    "dump_narratives",
    "load_narratives",
    "render_markdown",
    "__version__",
]
