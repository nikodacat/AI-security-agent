"""AttackSimulator orchestration.

`AttackSimulator` reads verdicts, filters to CONFIRMED, calls `narrator_fn`
per verdict, collects `Narrative` records. `narrator_fn` is a swappable
callable so tests can inject a fake and production can inject a
Claude-backed one (populated in 9d).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Protocol

from .narratives import Narrative
from .prompts import scan_for_tool_invocations


class NarratorFn(Protocol):
    """Callable protocol for the swappable narrator backend.

    Args:
        verdict: one CONFIRMED verdict dict from exposure-analyzer.

    Returns:
        the narrative text (recon → discovery → exploitation).
    """

    def __call__(self, verdict: dict) -> str: ...


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class AttackSimulator:
    """Per-CONFIRMED-verdict narrative generator.

    Filtering + orchestration only; the narrator_fn does the actual LLM
    call (or the fake for tests). Failures from narrator_fn on one verdict
    do NOT abort the batch — the affected narrative is stashed with an
    error marker in its body so the operator sees which one failed.
    """

    def __init__(
        self,
        narrator_fn: NarratorFn,
        *,
        target: str = "",
        model: str = "",
    ) -> None:
        self._narrator_fn = narrator_fn
        self._target = target
        self._model = model

    def narrate_all(self, verdicts: list[dict]) -> list[Narrative]:
        """Filter to CONFIRMED verdicts and narrate each.

        Non-CONFIRMED verdicts are skipped entirely (no narrative
        generated). The output list preserves the order of the input
        verdicts.
        """
        out: list[Narrative] = []
        for v in verdicts:
            if v.get("verdict") != "CONFIRMED":
                continue
            cve_id = v.get("cve_id", "CVE-UNKNOWN")
            reason = v.get("reason", "")
            try:
                text = self._narrator_fn(v)
            except Exception as e:  # pragma: no cover - one-off error path
                text = (
                    f"[narrator error: {type(e).__name__}: {e}]\n"
                    "The narrator backend raised while producing this narrative. "
                    "See the analyzer verdict above for the underlying evidence."
                )
            narrative_body = text.strip()
            hits = scan_for_tool_invocations(narrative_body)
            if hits:
                narrative_body = (
                    narrative_body
                    + "\n\n> ⚠️ **guardrail warning:** narrator output matched forbidden patterns: "
                    + ", ".join(hits)
                    + ". Review before publishing."
                )
            out.append(
                Narrative(
                    cve_id=cve_id,
                    target=self._target,
                    narrative=narrative_body,
                    source_verdict_reason=reason,
                    generated_at=_now_iso(),
                    model=self._model,
                )
            )
        return out


def narratives_from_verdicts(
    verdicts: list[dict],
    narrator_fn: NarratorFn,
    *,
    target: str = "",
    model: str = "",
) -> list[Narrative]:
    """Convenience: build the simulator and run narrate_all in one call."""
    return AttackSimulator(narrator_fn, target=target, model=model).narrate_all(verdicts)


def fake_narrator_fn(verdict: dict) -> str:
    """Canned narrator for offline tests and --engine=fake.

    Produces a deterministic three-section outline that references the
    verdict's own evidence so tests can assert on both the shape and the
    fact that verdict data flowed through.
    """
    cve_id = verdict.get("cve_id", "CVE-UNKNOWN")
    reason = verdict.get("reason", "").strip()
    evidence = verdict.get("evidence", {}) or {}
    net_hint = evidence.get("network_state", "") if isinstance(evidence, dict) else ""
    version_hint = evidence.get("package_version", "") if isinstance(evidence, dict) else ""

    return (
        f"### Recon\n"
        f"An external attacker enumerates the target host and identifies "
        f"the service linked to {cve_id}. External-scan evidence: "
        f"{net_hint or '(no network_state evidence recorded)'}.\n\n"
        f"### Discovery\n"
        f"The attacker fingerprints the affected component and confirms "
        f"the vulnerable version is present: {version_hint or '(no package_version recorded)'}. "
        f"They cross-reference the analyzer's finding: {reason or '(no reason recorded)'}\n\n"
        f"### Exploitation\n"
        f"Given the CONFIRMED verdict, the attacker's next step is to trigger the vulnerability class "
        f"associated with {cve_id}. Concrete tooling is intentionally not detailed — this narrative "
        f"is advisory only, and the operator should treat the finding as reachable-and-exploitable "
        f"without further evidence needed."
    )


def build_claude_narrator_fn(model: str = "sonnet") -> NarratorFn:
    """Build a NarratorFn backed by claude-agent-sdk.

    Deferred import: importing at module load would break tests on machines
    without the SDK installed. Call this only from CLI paths that intend
    to hit Claude for real.

    Wraps the SDK's async `query()` inside a sync `narrator_fn` so the rest
    of attack-simulator stays synchronous — attack-simulator is a
    post-processor (one Claude call per CONFIRMED verdict, no concurrency
    orchestration needed) and the async propagation from exposure-analyzer
    would be dead weight here.
    """
    try:
        from claude_agent_sdk import query, ClaudeAgentOptions  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "claude-agent-sdk is not installed. Install it with "
            "`pip install claude-agent-sdk` and ensure the `claude` CLI is "
            "on PATH (or set CLAUDE_CLI_PATH)."
        ) from e

    import asyncio
    from .prompts import SYSTEM_PROMPT, build_narrative_prompt

    async def _call(user_prompt: str) -> str:
        options = ClaudeAgentOptions(system_prompt=SYSTEM_PROMPT, model=model)
        chunks: list[str] = []
        async for msg in query(prompt=user_prompt, options=options):
            text = _extract_text(msg)
            if text:
                chunks.append(text)
        return "".join(chunks)

    def narrator(verdict: dict) -> str:
        user_prompt = build_narrative_prompt(verdict)
        return asyncio.run(_call(user_prompt))

    return narrator


def _extract_text(msg) -> str:  # pragma: no cover -- exercised only in live runs
    content = getattr(msg, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            t = getattr(block, "text", None)
            if isinstance(t, str):
                parts.append(t)
        return "".join(parts)
    text = getattr(msg, "text", None)
    return text if isinstance(text, str) else ""
