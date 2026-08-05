"""Core analyzer loop — wires probes + prompts + Claude Agent SDK together.

`ExposureAgent.analyze()` is THE entry point every caller reaches for. In v1
it operates in either interactive mode (asks the operator to run each probe
and paste output) or batch mode (auto-answers prompts and runs probes itself
against allow-listed targets).

Chunks D-F fill in the real behavior. This file gives chunk C a stable
interface to wire the report generator against.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .verdicts import Verdict, VerdictType


@dataclass
class AgentConfig:
    """Runtime configuration for a single analyzer session.

    Fields:
      interactive       : if True, prompt the operator to confirm each probe;
                          if False, auto-run (batch mode).
      subscription_backed : if True, use `claude-agent-sdk` in subscription
                          mode via the Claude Code CLI (no API key needed);
                          if False, use ANTHROPIC_API_KEY. Default True.
      claude_cli_path   : override path to the `claude` binary; if None,
                          the SDK uses $CLAUDE_CLI_PATH or PATH.
    """

    interactive: bool = True
    subscription_backed: bool = True
    claude_cli_path: str | None = None


class ExposureAgent:
    """The analyzer's Claude Agent SDK wrapper.

    Typical use::

        agent = ExposureAgent(AgentConfig(interactive=False))
        for candidate in candidates:
            verdict = await agent.analyze(candidate, host_state)
            verdicts.append(verdict)
    """

    def __init__(self, config: AgentConfig | None = None) -> None:
        self.config = config or AgentConfig()

    async def analyze(
        self,
        candidate: dict[str, Any],
        host_state: dict[str, Any],
    ) -> Verdict:
        """Produce a verdict for a single CVE candidate.

        Args:
            candidate:  one entry from cve-matcher's `kev_findings` array
                        (see cve_matcher.matcher for the exact shape).
            host_state: the full host-scanner output for the target.

        Returns:
            A `Verdict` with the analyzer's decision + evidence.

        Raises:
            NotImplementedError: chunk D implements the real loop.
        """
        raise NotImplementedError(
            "ExposureAgent.analyze is implemented in chunk D "
            "(see ../docs/ROADMAP.md)."
        )

    async def analyze_batch(
        self,
        candidates: list[dict[str, Any]],
        host_state: dict[str, Any],
    ) -> list[Verdict]:
        """Analyze many candidates in sequence.

        Default implementation just loops over `analyze`. Subclasses could
        override for parallelism, but the Claude subscription rate limits
        make serial the safer default for v1.
        """
        results: list[Verdict] = []
        for cand in candidates:
            results.append(await self.analyze(cand, host_state))
        return results
