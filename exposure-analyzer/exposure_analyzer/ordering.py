"""Which candidates the model sees first when the call budget cannot cover them all.

Candidates arrive grouped by where they came from (CISA KEV inventory, banners, NVD, OSV), so
cutting the list at the budget starves whichever source is built last. This puts them in
priority order instead:

  1. KEV-listed candidates (source `inventory` / `banner`): known to be exploited, always first.
  2. The rest, one source at a time in rotation, each source's own list sorted by CVSS
     descending, so a budget that runs out partway still covers every source.
"""

from __future__ import annotations

from typing import Any

_DISCOVERED = ("nvd-cpe", "osv")


def order_for_budget(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return `candidates` reordered by the rule above; nothing is added or dropped."""
    kev = [c for c in candidates if c.get("source", "inventory") not in _DISCOVERED]
    by_source: dict[str, list[dict[str, Any]]] = {}
    for c in candidates:
        src = c.get("source", "inventory")
        if src in _DISCOVERED:
            by_source.setdefault(src, []).append(c)
    queues = [sorted(group, key=lambda c: -float(c.get("cvss") or 0.0)) for group in by_source.values()]
    rotated: list[dict[str, Any]] = []
    for rank in range(max((len(q) for q in queues), default=0)):
        rotated.extend(q[rank] for q in queues if rank < len(q))
    return kev + rotated
