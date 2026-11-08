"""FixPublisher orchestration.

`FixPublisher` reads verdicts, filters to CONFIRMED, calls `publisher_fn`
per verdict, collects `Remediation` records. `publisher_fn` is a swappable
callable — fake for tests, Claude-backed for production.

Failures from `publisher_fn` on one verdict do NOT abort the batch — the
affected remediation record carries an error marker in its `explanation`
field so the operator sees which one failed.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Protocol

from .debver import compare as compare_versions
from .remediations import Remediation

# One-shot text completion: no tools, no settings files, one turn. Without this the
# Agent SDK sends Claude Code's tool definitions with every call (measured: 33,542 input
# tokens for a ~2,000-token prompt; 3,321 with these options, same reply).
_TEXT_ONLY = {"tools": [], "setting_sources": [], "max_turns": 1}



class PublisherFn(Protocol):
    """Callable protocol for the swappable publisher backend.

    Args:
        verdict: one CONFIRMED verdict dict from exposure-analyzer.

    Returns:
        parsed remediation dict with keys apt_command, config_diff,
        service_restart, explanation.
    """

    def __call__(self, verdict: dict) -> dict: ...


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def non_apt_origin(verdict: dict) -> str:
    """Why this verdict's software is NOT apt-managed, or "" if apt may apply / unknown.

    Decided in Python from the candidate's recorded origin, not by the model: an
    apt pin for a source-built binary or a library on disk is wrong advice.

    - OSV candidates are libraries found on disk (the source field holds a path).
    - Otherwise the package's own source decides: anything that is not "dpkg..."
      (e.g. "unmanaged-binary") was not installed by apt.
    - Banner-sourced candidates carry "dpkg" when an apt package has the banner's
      version, otherwise a marker saying it was not found in the apt package list.
    - Verdicts with no origin recorded are left to the model: we do not know.
    """
    candidate_source = str(verdict.get("candidate_source") or "")
    package_source = str(verdict.get("package_source") or "")
    if candidate_source == "osv":
        return f"library found at {package_source or 'an unknown path'}, not a Debian package"
    if candidate_source == "banner":
        if package_source.startswith("banner (version not in"):
            return "its version was seen on the network but no apt package has that version (built from source or bundled)"
        return ""
    if package_source and not package_source.lower().startswith("dpkg"):
        return f"installed as '{package_source}', not through apt"
    return ""


_PIN_RE = re.compile(r"(?<=\S)=(\S+)")


def pin_not_newer(apt_command: str, installed_version: str) -> str:
    """The first pinned version in `apt_command` that is not newer than the
    installed one ("" if every pin is newer, or either side is unknown).

    An apt pin at or below what is installed is not an upgrade: apt would keep
    or downgrade the package, and the CVE would stay open.
    """
    installed = (installed_version or "").strip()
    if not installed or not apt_command:
        return ""
    for pin in _PIN_RE.findall(apt_command):
        if compare_versions(pin, installed) <= 0:
            return pin
    return ""


class FixPublisher:
    """Per-CONFIRMED-verdict remediation generator.

    Filtering + orchestration only; the publisher_fn does the actual LLM
    call (or the fake for tests).
    """

    def __init__(
        self,
        publisher_fn: PublisherFn,
        *,
        target: str = "",
        model: str = "",
    ) -> None:
        self._publisher_fn = publisher_fn
        self._target = target
        self._model = model

    def publish_all(self, verdicts: list[dict]) -> list[Remediation]:
        """Filter to CONFIRMED verdicts and remediate each.

        Non-CONFIRMED verdicts are skipped entirely. Output preserves the
        input order.
        """
        out: list[Remediation] = []
        for v in verdicts:
            if v.get("verdict") != "CONFIRMED":
                continue
            cve_id = v.get("cve_id", "CVE-UNKNOWN")
            reason = v.get("reason", "")
            not_apt = non_apt_origin(v)
            try:
                # The hint lets the model write a config mitigation or manual steps;
                # the override below is what actually guarantees no apt command.
                data = self._publisher_fn({**v, "not_apt_managed": not_apt} if not_apt else v)
                apt = str(data.get("apt_command", "")).strip()
                cfg = str(data.get("config_diff", "")).strip()
                restart = str(data.get("service_restart", "")).strip()
                explanation = str(data.get("explanation", "")).strip()
                if not_apt:
                    apt = ""
                    explanation = (
                        f"[Not apt-managed: {not_apt}. Manual patch required; "
                        f"no apt command is given.] {explanation}"
                    ).strip()
                else:
                    installed = str(v.get("installed_version") or v.get("package_version") or "")
                    stale = pin_not_newer(apt, installed)
                    if stale:
                        explanation = (
                            f"[Version check failed: the suggested version {stale} is not newer than the "
                            f"installed {installed}, so it would not fix this. No apt command "
                            f"is given; look up the fixed version for your Debian release.] {explanation}"
                        ).strip()
                        apt = ""
            except Exception as e:  # pragma: no cover - one-off error path
                apt = ""
                cfg = "no config change needed"
                restart = "no restart needed"
                explanation = (
                    f"[publisher error: {type(e).__name__}: {e}] "
                    "The publisher backend raised while producing this "
                    "remediation. See the analyzer verdict above for "
                    "the underlying evidence."
                )
            out.append(
                Remediation(
                    cve_id=cve_id,
                    target=self._target,
                    apt_command=apt,
                    config_diff=cfg or "no config change needed",
                    service_restart=restart or "no restart needed",
                    explanation=explanation,
                    source_verdict_reason=reason,
                    generated_at=_now_iso(),
                    model=self._model,
                )
            )
        return out


def remediations_from_verdicts(
    verdicts: list[dict],
    publisher_fn: PublisherFn,
    *,
    target: str = "",
    model: str = "",
) -> list[Remediation]:
    """Convenience: build FixPublisher and run publish_all in one call."""
    return FixPublisher(publisher_fn, target=target, model=model).publish_all(verdicts)


def fake_publisher_fn(verdict: dict) -> dict:
    """Canned publisher for offline tests and --engine=fake.

    Produces a deterministic remediation shape that references the
    verdict's evidence, so tests can assert both shape and data flow.
    """
    cve_id = verdict.get("cve_id", "CVE-UNKNOWN")
    reason = verdict.get("reason", "").strip()
    evidence = verdict.get("evidence", {}) or {}
    pkg_hint = evidence.get("package_version", "") if isinstance(evidence, dict) else ""

    package_name = verdict.get("package_name", "") or _guess_package_from_cve(cve_id)
    apt_command = (
        f"apt install {package_name}=<pinned-version>"
        if package_name
        else "apt install <package>=<pinned-version>"
    )
    if verdict.get("not_apt_managed"):
        apt_command = ""

    return {
        "apt_command": apt_command,
        "config_diff": "no config change needed",
        "service_restart": "no restart needed",
        "explanation": (
            f"Update {package_name or 'the affected package'} to a version outside "
            f"the affected range for {cve_id}. Version evidence: "
            f"{pkg_hint or '(no package_version recorded)'}. "
            f"Verdict summary: {reason or '(no reason recorded)'}"
        ),
    }


def _guess_package_from_cve(cve_id: str) -> str:
    """Rough hint used by the fake publisher only. Not used in real paths."""
    # Intentionally boring — the real Claude publisher figures this out from
    # kev_product / package_name; the fake just needs SOMETHING for tests.
    return ""


def build_claude_publisher_fn(model: str = "sonnet") -> PublisherFn:
    """Build a PublisherFn backed by claude-agent-sdk.

    Deferred import: the SDK isn't required for tests. The returned
    callable wraps the async `query()` inside a sync function so the rest
    of fix-publisher stays synchronous. Each call runs `parse_remediation`
    on the model's response so the caller receives a validated dict, not
    raw text; validation failures propagate as RemediationValidationError.
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
    from .prompts import SYSTEM_PROMPT, build_remediation_prompt, parse_remediation

    async def _call(user_prompt: str) -> str:
        options = ClaudeAgentOptions(system_prompt=SYSTEM_PROMPT, model=model, **_TEXT_ONLY)
        chunks: list[str] = []
        async for msg in query(prompt=user_prompt, options=options):
            text = _extract_text(msg)
            if text:
                chunks.append(text)
        return "".join(chunks)

    def publisher(verdict: dict) -> dict:
        user_prompt = build_remediation_prompt(verdict)
        raw = asyncio.run(_call(user_prompt))
        return parse_remediation(raw)

    return publisher


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
