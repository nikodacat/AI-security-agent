"""fix-publisher: per-CONFIRMED-verdict remediation drafter.

Public API:

    from fix_publisher import (
        Remediation,
        FixPublisher,
        remediations_from_verdicts,
        dump_remediations,
        load_remediations,
        render_markdown,
    )

For the CLI:

    python -m fix_publisher publish --verdicts <path> --output <path>
"""

from __future__ import annotations

__version__ = "0.0.1-scaffold"

from .remediations import (
    Remediation,
    dump_remediations,
    load_remediations,
    render_html_section,
    render_markdown,
)
from .publisher import FixPublisher, remediations_from_verdicts

__all__ = [
    "Remediation",
    "FixPublisher",
    "remediations_from_verdicts",
    "dump_remediations",
    "load_remediations",
    "render_html_section",
    "render_markdown",
    "__version__",
]
