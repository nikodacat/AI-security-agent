"""Probe library — per-CVE non-destructive verification commands.

Each `ProbeTemplate` describes a single probe: what command to run against
the target, what output pattern indicates the vulnerability, and a hint
Claude uses when interpreting the output.

`KNOWN_PROBES` is a dict keyed by CVE ID. In v1 it's populated by hand
(chunk D adds the first entry; chunk E adds 4-5 more for the demo lab).
v2 will add a Claude-generated fallback for CVEs not in the dict.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProbeTemplate:
    """A single non-destructive verification command for a specific CVE.

    Fields:
      command             : shell command; `{target}` is substituted with the
                            host / container identifier at run time.
      expected_signals    : list of regex fragments; if any match the probe
                            output, the vulnerable code path is likely present.
      interpretation_hint : one-sentence guidance the prompt injects to help
                            Claude reason about the output.
      safe                : True if the probe is guaranteed non-destructive
                            (read-only, no state change). All v1 probes MUST
                            be safe=True. Attempting to add safe=False raises.
    """

    command: str
    expected_signals: list[str] = field(default_factory=list)
    interpretation_hint: str = ""
    safe: bool = True

    def __post_init__(self) -> None:
        if not self.safe:
            raise ValueError(
                "v1 exposure-analyzer only accepts non-destructive probes "
                "(safe=True). Refusing to register a mutating probe."
            )


# CVE-ID -> ProbeTemplate. Empty in the scaffold; chunks D-E populate it.
KNOWN_PROBES: dict[str, ProbeTemplate] = {}


def lookup_probe(cve_id: str) -> ProbeTemplate | None:
    """Return the probe template for a CVE, or None if we have no known probe.

    Callers should treat `None` as "no hardcoded probe; either skip with
    NO_EVIDENCE or fall back to Claude-generated probe (v2)."
    """
    return KNOWN_PROBES.get(cve_id)
