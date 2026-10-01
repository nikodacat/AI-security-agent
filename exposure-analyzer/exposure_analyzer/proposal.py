"""Dynamic probe proposal — LLM proposes structured argv when no KNOWN_PROBES match.

v2-7 machinery. The LLM is asked to produce a `{binary, args[]}` probe (never
a shell string) for a CVE that has no hardcoded ProbeTemplate. The proposal
is validated + stashed in the Verdict for later human review (v2-8 adds the
HITL execution gate). v2-7 NEVER executes a proposed probe.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

# ---- Prompt ----------------------------------------------------------------

SYSTEM_PROMPT_PROPOSE = """\
You are a defensive security assistant. The operator will describe a CVE
candidate and the current host inventory. Your job is to propose a SINGLE
non-destructive command that would collect additional evidence about
whether this CVE is actually exploitable on this host.

RULES:
1. STRUCTURED ARGV ONLY. Return {"binary": "<name>", "args": ["<a1>", ...]}.
   Never a shell string. Never `sh -c "..."` or `bash -c "..."`.
2. NON-DESTRUCTIVE. Read-only inspection commands only. No writes, no state
   changes, no network exploits, no fuzzing. Version banners, config dumps,
   filesystem-existence checks, and read-only queries are allowed.
3. NO SHELL METACHARACTERS in any arg. That includes `;`, `|`, `>`, `<`, `&`,
   backticks, `$()`, `$(`, newlines. If you would want to pipe two commands
   together, pick the more informative single command instead.
4. BINARY NAME is a plain executable name, no path. `httpd`, `redis-cli`,
   `ssh`, `find`, `dpkg`, `openssl`. If the binary is a shell wrapper
   (`sh`, `bash`, `dash`, `zsh`, `csh`, `ksh`), your proposal is invalid.
5. ARGUMENT LIMITS. Each arg <= 200 chars, total <= 10 args.

If NO safe probe would meaningfully advance the verdict, return
{"binary": "", "args": [], "rationale": "no useful probe available",
 "expected_signals": []}.

RESPONSE SHAPE:
Return ONLY a single JSON object, no prose before or after:
{
  "binary": "<string, or empty string>",
  "args": ["<string>", ...],
  "rationale": "<one-sentence why this probe helps>",
  "expected_signals": ["<regex fragment>", ...]
}

`expected_signals` are regex fragments that, if matched in the probe output,
would indicate the vulnerable code path is present.

EXAMPLES OF GOOD PROPOSALS:
- Apache banner check:   {"binary": "httpd", "args": ["-v"], "rationale": "banner reveals if version is in affected 2.4.49/50 range", "expected_signals": ["Apache/2\\\\.4\\\\.(49|50)"]}
- Redis version check:   {"binary": "redis-cli", "args": ["-h", "127.0.0.1", "INFO", "server"], "rationale": "INFO server exposes redis_version + build info", "expected_signals": ["redis_version:6\\\\.2\\\\.[0-6]"]}
- Log4j filesystem scan: {"binary": "find", "args": ["/", "-maxdepth", "8", "-name", "log4j-core-*.jar"], "rationale": "confirms/denies log4j-core presence on disk", "expected_signals": ["log4j-core-2\\\\.(0|[1-9]|1[0-4])"]}
"""

# ---- Validation constants --------------------------------------------------

SHELL_WRAPPERS = frozenset({"sh", "bash", "dash", "zsh", "csh", "ksh", "fish", "tcsh"})
_BINARY_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")
# Chars that let an arg escape into shell semantics if a later runner ever
# passes argv through a shell. Belt-and-braces: our runner uses argv arrays
# directly, but the model may not know that, and defense in depth is cheap.
_SHELL_METACHARS = frozenset(";|><&`\n\r\t")
_MAX_ARG_LEN = 200
_MAX_ARGS = 10
_MAX_RATIONALE_LEN = 500
_MAX_SIGNAL_LEN = 200
_MAX_SIGNALS = 10

# ---- Types -----------------------------------------------------------------

@dataclass(frozen=True)
class ProposedProbe:
    """A validated LLM-proposed probe. Binary/args are safe to STORE (not run).

    Execution is deferred to v2-8's HITL gate. This dataclass exists so a
    proposal can round-trip through Verdict.to_dict/from_dict cleanly.
    """
    binary: str
    args: tuple[str, ...]
    rationale: str
    expected_signals: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "args": list(self.args),
            "rationale": self.rationale,
            "expected_signals": list(self.expected_signals),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProposedProbe":
        return cls(
            binary=d["binary"],
            args=tuple(d.get("args", [])),
            rationale=d.get("rationale", ""),
            expected_signals=tuple(d.get("expected_signals", [])),
        )


class ProposalValidationError(ValueError):
    """Raised when a proposal fails schema/policy validation."""


# ProbeProposer = async fn (candidate, host_state) -> raw model response text.
# Kept as a separate type from VerdictFn even though the signature is close,
# because the caller-side prompt is different and mixing them is a footgun.
ProbeProposer = Callable[[dict[str, Any], dict[str, Any]], Awaitable[str]]


# ---- Parsing + validation --------------------------------------------------

def parse_proposal(raw: str) -> ProposedProbe:
    """Parse and validate a raw model response into a ProposedProbe.

    Tolerates code fences and leading/trailing prose (same pattern as
    prompts._parse_verdict_response). Raises ProposalValidationError with
    a specific human-readable reason on any schema or policy failure.
    """
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text).strip()

    obj: dict[str, Any] | None = None
    try:
        cand = json.loads(text)
        if isinstance(cand, dict) and "binary" in cand:
            obj = cand
    except json.JSONDecodeError:
        pass
    if obj is None:
        # Fallback: scan for the first {...} that decodes AND has "binary".
        for start, ch in enumerate(text):
            if ch != "{":
                continue
            for end in range(len(text), start, -1):
                try:
                    cand = json.loads(text[start:end])
                except json.JSONDecodeError:
                    continue
                if isinstance(cand, dict) and "binary" in cand:
                    obj = cand
                    break
            if obj is not None:
                break
    if obj is None:
        raise ProposalValidationError(f"no JSON object with 'binary' key found in response: {raw!r}")

    binary = obj.get("binary")
    args = obj.get("args")
    rationale = obj.get("rationale", "")
    signals = obj.get("expected_signals", [])

    if not isinstance(binary, str):
        raise ProposalValidationError(f"'binary' must be a string, got {type(binary).__name__}")
    if not isinstance(args, list):
        raise ProposalValidationError(f"'args' must be a list, got {type(args).__name__}")
    if not isinstance(rationale, str):
        raise ProposalValidationError(f"'rationale' must be a string, got {type(rationale).__name__}")
    if not isinstance(signals, list):
        raise ProposalValidationError(f"'expected_signals' must be a list, got {type(signals).__name__}")

    # Empty-binary sentinel = "no useful probe available"; must also have empty args.
    if binary == "":
        if args:
            raise ProposalValidationError("empty binary requires empty args (declined-probe sentinel)")
    else:
        if not _BINARY_RE.match(binary):
            raise ProposalValidationError(
                f"binary {binary!r} contains illegal characters; only [A-Za-z0-9_.-] allowed"
            )
        if binary in SHELL_WRAPPERS:
            raise ProposalValidationError(f"binary {binary!r} is a shell wrapper; refused")

    if len(args) > _MAX_ARGS:
        raise ProposalValidationError(f"too many args ({len(args)} > {_MAX_ARGS})")
    for i, a in enumerate(args):
        if not isinstance(a, str):
            raise ProposalValidationError(f"args[{i}] must be a string, got {type(a).__name__}")
        if len(a) > _MAX_ARG_LEN:
            raise ProposalValidationError(f"args[{i}] longer than {_MAX_ARG_LEN} chars")
        bad = [c for c in a if c in _SHELL_METACHARS]
        if bad:
            raise ProposalValidationError(f"args[{i}]={a!r} contains shell metacharacter(s) {bad!r}")

    if len(rationale) > _MAX_RATIONALE_LEN:
        raise ProposalValidationError(f"rationale longer than {_MAX_RATIONALE_LEN} chars")

    if len(signals) > _MAX_SIGNALS:
        raise ProposalValidationError(f"too many expected_signals ({len(signals)} > {_MAX_SIGNALS})")
    for i, s in enumerate(signals):
        if not isinstance(s, str):
            raise ProposalValidationError(f"expected_signals[{i}] must be a string, got {type(s).__name__}")
        if len(s) > _MAX_SIGNAL_LEN:
            raise ProposalValidationError(f"expected_signals[{i}] longer than {_MAX_SIGNAL_LEN} chars")

    return ProposedProbe(
        binary=binary,
        args=tuple(args),
        rationale=rationale,
        expected_signals=tuple(signals),
    )


def build_proposer_user_prompt(candidate: dict[str, Any], host_state: dict[str, Any]) -> str:
    """Construct the per-CVE user turn asking the model for a probe proposal.

    Kept simple: candidate metadata + host_state slice. The system prompt
    already carries the rules, examples, and response shape.
    """
    from .prompts import _candidate_summary, _render_json, _HOST_STATE_CHAR_LIMIT
    parts = [
        f"Candidate: {candidate.get('cve_id', 'CVE-UNKNOWN')}",
        "",
        "CVE metadata:",
        _render_json(_candidate_summary(candidate)),
        "",
        "Host inventory (from host-scanner):",
        _render_json(host_state, limit=_HOST_STATE_CHAR_LIMIT),
        "",
        "Propose a probe per the RULES in the system prompt, or an empty-binary "
        "sentinel if no useful probe exists. Respond with the JSON object only.",
    ]
    return "\n".join(parts)


def build_claude_proposer_fn() -> ProbeProposer:
    """Return a ProbeProposer backed by claude-agent-sdk.

    Mirrors agent.build_claude_verdict_fn — deferred SDK import so tests
    don't need it installed.
    """
    try:
        from claude_agent_sdk import query, ClaudeAgentOptions  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "claude-agent-sdk is not installed. Install with "
            "`pip install claude-agent-sdk`."
        ) from e

    async def _call(candidate: dict[str, Any], host_state: dict[str, Any]) -> str:
        from .agent import _extract_text  # reuse the extractor
        options = ClaudeAgentOptions(system_prompt=SYSTEM_PROMPT_PROPOSE)
        user_prompt = build_proposer_user_prompt(candidate, host_state)
        chunks: list[str] = []
        async for msg in query(prompt=user_prompt, options=options):
            t = _extract_text(msg)
            if t:
                chunks.append(t)
        return "".join(chunks)

    return _call
