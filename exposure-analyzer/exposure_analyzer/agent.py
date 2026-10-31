"""Core analyzer loop -- wires probes + prompts + LLM together.

`ExposureAgent.analyze()` is THE entry point every caller reaches for.

Design note: the LLM call is a swappable `verdict_fn` dependency so the
orchestration is testable without any SDK installed. In production
`build_claude_verdict_fn()` returns a callable backed by claude-agent-sdk;
tests inject a fake.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol

from .hitl import (
    ApprovalGate,
    Decision,
    append_learned_probe,
    argv_hash,
    build_probe_argv,
    make_learned_record,
)
from .probes import ProbeTemplate, lookup_probe
from .prompts import SYSTEM_PROMPT, build_verdict_prompt
from .proposal import _TEXT_ONLY, ProbeProposer, ProposalValidationError, parse_proposal
from .verdicts import Verdict, VerdictType


# A verdict_fn takes (system_prompt, user_prompt) and returns the model's
# raw response text (expected to be a JSON object matching the schema in
# SYSTEM_PROMPT). Async so a real Claude SDK impl can await network I/O.
VerdictFn = Callable[[str, str], Awaitable[str]]


class ProbeRunner(Protocol):
    """Executes a probe command and returns (command, stdout+stderr)."""

    def __call__(self, template: ProbeTemplate) -> tuple[str, str]: ...


@dataclass
class AgentConfig:
    """Runtime configuration for a single analyzer session.

    Fields:
      run_probes          : if False, skip probe execution entirely.
      probe_timeout_sec   : wall-clock cap for a single probe.
      max_output_chars    : cap on captured probe output.

    Design note (chunk F): earlier versions carried an `interactive` field
    intended to gate "run this probe? [y/N]" prompts before each probe. It
    was removed because `ProbeTemplate.__post_init__` already refuses to
    register any probe with safe=False, so v1's KNOWN_PROBES is safe by
    construction and per-probe confirmation is redundant friction. If v2
    adds higher-risk probes (writes state, non-loopback network calls),
    re-introduce the gate at THAT point with a specific threat model in
    mind, not preemptively.
    """

    run_probes: bool = True
    probe_timeout_sec: float = 10.0
    max_output_chars: int = 4000


class BudgetExceeded(RuntimeError):
    """A CallBudget limit was reached; no further model call is made."""


@dataclass
class CallBudget:
    """Hard limits on model calls for one run. ``None`` means no limit on that axis.

    `check()` runs before every call, so the call that would exceed a limit is never
    sent. A run can still overshoot `max_cost_usd` by the cost of one call, because
    cost is only known after the reply. Cost is whatever the SDK reports; engines that
    report none (local models) are limited by `max_calls` only.
    """

    max_calls: int | None = None
    max_cost_usd: float | None = None
    calls: int = 0
    cost_usd: float = 0.0

    def check(self) -> None:
        if self.max_calls is not None and self.calls >= self.max_calls:
            raise BudgetExceeded(f"call limit {self.max_calls} reached")
        if self.max_cost_usd is not None and self.cost_usd >= self.max_cost_usd:
            raise BudgetExceeded(f"cost limit ${self.max_cost_usd:.2f} reached (spent ${self.cost_usd:.2f})")

    def record(self, cost_usd: float | None) -> None:
        self.calls += 1
        self.cost_usd += cost_usd or 0.0


class ExposureAgent:
    """The analyzer's Claude wrapper.

    Typical use::

        agent = ExposureAgent(verdict_fn=build_claude_verdict_fn())
        verdicts = await agent.analyze_batch(candidates, host_state)
    """

    def __init__(
        self,
        verdict_fn: VerdictFn,
        config: AgentConfig | None = None,
        probe_runner: ProbeRunner | None = None,
        probe_proposer: ProbeProposer | None = None,
        approval_gate: ApprovalGate | None = None,
        learned_probes_path: Path | None = None,
        target_container: str | None = None,
    ) -> None:
        self.verdict_fn = verdict_fn
        self.config = config or AgentConfig()
        self.probe_runner = probe_runner or _default_probe_runner(self.config)
        self.probe_proposer = probe_proposer
        self.approval_gate = approval_gate
        self.learned_probes_path = learned_probes_path
        self.target_container = target_container
        self.last_batch_errors: list[tuple[str, str]] = []
        self.stopped_by_budget: str = ""

    async def analyze(
        self,
        candidate: dict[str, Any],
        host_state: dict[str, Any],
        network_state: list[dict[str, Any]] | None = None,
    ) -> Verdict:
        """Produce a verdict for a single CVE candidate.

        ``network_state`` (v2 addition): list of PortObservation dicts from
        network-prober conforming to docs/schemas/network_state.schema.json.
        None (default) preserves v1 behavior — the prompt omits the
        External-attacker view entirely, so v1-vs-v2 verdict-delta baselines
        are directly comparable by just running the analyzer twice with and
        without the argument.
        """
        cve_id = candidate.get("cve_id", "CVE-UNKNOWN")
        template = lookup_probe(cve_id) if self.config.run_probes else None

        probe_command, probe_output = ("", "")
        proposed_probe: dict[str, Any] | None = None
        probe_proposal_error: str = ""

        if template is not None:
            probe_command, probe_output = self.probe_runner(template)
        elif self.probe_proposer is not None and self.config.run_probes:
            try:
                raw_proposal = await self.probe_proposer(candidate, host_state)
                probe = parse_proposal(raw_proposal)
                proposed_probe = probe.to_dict()
                if self.approval_gate is not None:
                    decision, approved_by = self.approval_gate.decide(probe, cve_id)
                    if decision == Decision.APPROVE:
                        argv = build_probe_argv(probe, self.target_container)
                        display_cmd = " ".join([probe.binary, *probe.args])
                        probe_command, probe_output = _run_argv(
                            argv, display_cmd=display_cmd, config=self.config
                        )
                        h = argv_hash(probe.binary, probe.args)
                        if (
                            self.learned_probes_path is not None
                            and h not in self.approval_gate.learned
                        ):
                            rec = make_learned_record(probe, cve_id, approved_by)
                            append_learned_probe(self.learned_probes_path, rec)
                            self.approval_gate.learned[h] = rec
            except ProposalValidationError as e:
                probe_proposal_error = str(e)
            except Exception as e:
                probe_proposal_error = str(e) or type(e).__name__

        user_prompt = build_verdict_prompt(
            candidate,
            host_state,
            probe_command=probe_command,
            probe_output=probe_output,
            network_state=network_state,
        )

        raw = await self.verdict_fn(SYSTEM_PROMPT, user_prompt)
        parsed = _parse_verdict_response(raw)

        return Verdict(
            cve_id=cve_id,
            verdict=parsed["verdict"],
            reason=parsed["reason"],
            evidence=parsed.get("evidence", {}),
            probe_command=probe_command,
            probe_output=probe_output,
            proposed_probe=proposed_probe,
            probe_proposal_error=probe_proposal_error,
        )

    async def analyze_batch(
        self,
        candidates: list[dict[str, Any]],
        host_state: dict[str, Any],
        network_state: list[dict[str, Any]] | None = None,
    ) -> list[Verdict]:
        """Analyze many candidates serially (subscription rate limits).

        ``network_state`` is passed through unchanged to every candidate's
        :meth:`analyze` call — the filtering to "observations relevant to
        this CVE" happens inside :func:`prompts.build_verdict_prompt`.

        One candidate failing does not abort the batch. An unparseable model
        reply (``ValueError``) is retried once, since small local models
        occasionally emit a malformed JSON object; a candidate that still
        fails is left out of the result and recorded in
        ``self.last_batch_errors`` as ``(cve_id, message)``. It is never
        replaced by a made-up verdict: a silent ``NO_EVIDENCE`` would read as
        an analysis result when none exists.

        A :class:`BudgetExceeded` from ``verdict_fn`` ends the batch: the verdicts
        so far are returned, ``self.stopped_by_budget`` says why, and the
        remaining candidates get no verdict.
        """
        results: list[Verdict] = []
        self.last_batch_errors = []
        self.stopped_by_budget = ""
        for cand in candidates:
            cve_id = cand.get("cve_id", "CVE-UNKNOWN")
            try:
                try:
                    verdict = await self.analyze(cand, host_state, network_state=network_state)
                except ValueError:
                    verdict = await self.analyze(cand, host_state, network_state=network_state)
            except BudgetExceeded as e:
                self.stopped_by_budget = str(e)
                break
            except Exception as e:
                self.last_batch_errors.append((cve_id, f"{type(e).__name__}: {e}"))
                continue
            results.append(verdict)
        return results


def _parse_verdict_response(raw: str) -> dict[str, Any]:
    """Extract the verdict JSON object from the model's response.

    Tolerates a code fence or leading/trailing prose -- pulls out the first
    top-level {...} block that contains a "verdict" key.

    Raises:
        ValueError: if no parseable verdict object is found or the verdict
                    string isn't one of the five allowed values.
    """
    text = raw.strip()
    # Strip code fences if present.
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
        text = text.strip()

    obj: dict[str, Any] | None = None
    try:
        candidate = json.loads(text)
        if isinstance(candidate, dict) and "verdict" in candidate:
            obj = candidate
    except json.JSONDecodeError:
        pass

    if obj is None:
        # Fallback: scan for the first { ... } that decodes and has "verdict".
        for start in _brace_starts(text):
            for end in range(len(text), start, -1):
                snippet = text[start:end]
                try:
                    cand = json.loads(snippet)
                except json.JSONDecodeError:
                    continue
                if isinstance(cand, dict) and "verdict" in cand:
                    obj = cand
                    break
            if obj is not None:
                break

    if obj is None:
        raise ValueError(f"no verdict JSON object found in model response: {raw!r}")

    verdict = obj.get("verdict")
    if not isinstance(verdict, str):
        raise ValueError(f"verdict field is not a string: {verdict!r}")
    try:
        VerdictType(verdict)
    except ValueError as e:
        raise ValueError(f"unknown verdict value: {verdict!r}") from e

    reason = obj.get("reason", "")
    if not isinstance(reason, str):
        reason = str(reason)

    evidence = obj.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {"raw_evidence": str(evidence)}

    return {"verdict": verdict, "reason": reason, "evidence": evidence}


def _brace_starts(text: str) -> list[int]:
    return [i for i, ch in enumerate(text) if ch == "{"]


def _run_argv(argv: list[str], display_cmd: str, config: AgentConfig) -> tuple[str, str]:
    """Execute an argv, capture combined stdout+stderr, apply size/timeout caps.

    display_cmd is what gets shown to Claude / recorded in the Verdict --
    typically the probe template's raw command string, NOT the wrapped argv,
    so a docker-exec-wrapped probe still shows `ssh -V` in the report.
    """
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=config.probe_timeout_sec,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        out = f"(command not found: {argv[0]})"
    except subprocess.TimeoutExpired:
        out = f"(probe timed out after {config.probe_timeout_sec}s)"
    except Exception as e:
        out = f"(probe error: {type(e).__name__}: {e})"

    if len(out) > config.max_output_chars:
        out = out[: config.max_output_chars] + "\n... [truncated]"
    return display_cmd, out


def _default_probe_runner(config: AgentConfig) -> ProbeRunner:
    """Run probes on the local machine. Used when the analyzer runs on the target."""

    def run(template: ProbeTemplate) -> tuple[str, str]:
        argv = shlex.split(template.command)
        return _run_argv(argv, template.command, config)

    return run


def docker_exec_probe_runner(container: str, config: AgentConfig | None = None) -> ProbeRunner:
    """Run probes inside a running docker container via `docker exec`.

    Used when the analyzer runs on a coordinator machine and probes need to
    execute against a container target (e.g. the eval-lab).

    The probe's `template.command` is passed through unchanged as far as
    Claude and the Verdict are concerned -- only the actual subprocess call
    is wrapped in `docker exec <container> ...`.
    """
    cfg = config or AgentConfig()

    def run(template: ProbeTemplate) -> tuple[str, str]:
        argv = ["docker", "exec", container] + shlex.split(template.command)
        return _run_argv(argv, template.command, cfg)

    return run


def build_claude_verdict_fn(budget: CallBudget | None = None) -> VerdictFn:
    """Return a VerdictFn backed by claude-agent-sdk.

    With a `budget`, every call is checked against it first and its cost
    (``total_cost_usd`` from the SDK's result message) is recorded after.

    Deferred import: importing at module load would break tests on machines
    without the SDK installed. Call this only from CLI paths that intend to
    hit Claude for real.
    """
    try:
        from claude_agent_sdk import query, ClaudeAgentOptions  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "claude-agent-sdk is not installed. Install it with "
            "`pip install claude-agent-sdk` and ensure the `claude` CLI is "
            "on PATH (or set CLAUDE_CLI_PATH)."
        ) from e

    async def _call(system_prompt: str, user_prompt: str) -> str:
        if budget is not None:
            budget.check()
        options = ClaudeAgentOptions(system_prompt=system_prompt, **_TEXT_ONLY)
        chunks: list[str] = []
        cost: float | None = None
        try:
            async for msg in query(prompt=user_prompt, options=options):
                # Different SDK message types expose text on .content or .text.
                text = _extract_text(msg)
                if text:
                    chunks.append(text)
                if type(msg).__name__ == "ResultMessage":
                    cost = getattr(msg, "total_cost_usd", None)
        finally:
            if budget is not None:  # a failed call may still have been billed
                budget.record(cost)
        return "".join(chunks)

    return _call


def build_openai_compatible_verdict_fn(
    base_url: str,
    model: str,
    api_key: str | None = None,
    timeout: float = 60.0,
    max_tokens: int = 2048,
) -> VerdictFn:
    """Return a VerdictFn backed by any OpenAI-compatible chat-completions
    endpoint (llama-server, vLLM, LM Studio, Ollama's OpenAI shim, etc.).

    Non-streaming: posts one request, returns ``choices[0].message.content``
    whole. Used for the v3 "does scaffolding matter more with a weaker
    backend" comparison — points this at a local model instead of Claude
    while ExposureAgent's orchestration (probes, schema, HITL) is unchanged.

    Deferred import mirrors build_claude_verdict_fn's pattern: httpx isn't
    required on machines that only ever use the claude engine.
    """
    try:
        import httpx  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "httpx is not installed. Install it with `pip install httpx`."
        ) from e

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async def _call(system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            # A verdict is a short JSON object. Without a cap a small local
            # model can loop on one prompt, hold a single-slot server for many
            # minutes, and keep generating after the client has timed out.
            "max_tokens": max_tokens,
        }
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(base_url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        return data["choices"][0]["message"]["content"]

    return _call


def _extract_text(msg: Any) -> str:  # pragma: no cover -- exercised only in live runs
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
