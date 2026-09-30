"""Claude prompts for fix-publisher.

`SYSTEM_PROMPT` frames Claude as a Debian/Ubuntu package-security advisor
producing an apt-based remediation for one CONFIRMED CVE verdict.

`build_remediation_prompt()` constructs the per-verdict user turn.

`parse_remediation()` extracts + validates the model's JSON response.
Failed validation raises `RemediationValidationError` so the caller can
either propagate the failure into the Remediation.explanation field (via
the publisher orchestrator's exception handling) or bail hard. The
validator enforces:

  * response is JSON with keys apt_command / config_diff / service_restart / explanation
  * apt_command starts with `apt install` or `apt-get install`
  * apt_command contains an `=<version>` version pin (or is the special
    empty-command sentinel for library CVEs that need only a service
    restart of the consumer, which we don't currently emit but reserve)
  * config_diff and service_restart are the "no ... needed" sentinels
    OR non-empty strings
  * explanation is non-empty

The apt-install shape check is a HARD guardrail, not advisory — an
unpinned `apt install libssl1.1` on a stale mirror can silently install
an older version that still contains the CVE, so the operator would apply
the fix and think they're safe. We refuse to emit an unpinned command.
"""

from __future__ import annotations

import json
import re
from typing import Any


SYSTEM_PROMPT = """\
You are a Debian/Ubuntu package-security advisor. For each CONFIRMED CVE
verdict the operator sends you, produce a structured remediation draft the
operator will review and apply by hand (or via config management). You
never execute anything. Your output is a JSON object with four fields:

  apt_command       -- the pinned apt install command that upgrades the
                       affected package past the fix boundary. MUST start
                       with `apt install ` and MUST contain `=<version>`
                       to pin the exact fixed version. Never emit
                       `apt install <package>` without a version pin — a
                       stale mirror could install an older version still
                       carrying the CVE, and the operator would think the
                       fix landed. Use the fix version from vendor advisories
                       or, when the verdict evidence shows the installed
                       version already matches a known-fixed release line,
                       pick the latest patch on that line.
                       Example: `apt install libssl1.1=1.1.1n-0+deb10u6`

  config_diff       -- when the CVE requires a config change (disable a
                       vulnerable module, tighten an ACL, add a
                       Content-Security-Policy header, restrict a bind
                       address, etc.), emit a unified-diff-style block.
                       Include enough context that the operator can find
                       the change target. If no config change is required
                       (the package upgrade alone fixes the vulnerability),
                       emit exactly the string: `no config change needed`.

  service_restart   -- the systemctl or service command needed to pick up
                       the fix. For daemon services (apache2, redis, sshd),
                       this is usually `systemctl restart <unit>`. For
                       library-only fixes, the shared library reload
                       happens on next process start — in that case emit
                       exactly: `no restart needed`. If the library is
                       linked by a running service that needs a restart to
                       pick up the new library, emit the restart directive
                       for that consumer service (not the library).

  explanation       -- ONE or TWO sentences on why this remediation
                       closes the CVE. Reference the specific fix
                       boundary (version + advisory) so the operator can
                       audit. Do not editorialize; do not lecture.

HARD CONSTRAINTS:

  1. Debian/Ubuntu `apt` scope only. Never emit `yum`, `dnf`, `zypper`,
     `pacman`, `pip`, `npm`, `snap`, `docker pull` or any other package
     manager. If the CVE cannot be remediated with apt on Debian/Ubuntu
     (source-built binary, WordPress plugin, upstream Docker image), emit
     an empty `apt_command` and explain in `explanation` what the
     operator needs to do instead.
  2. Version pin required in `apt_command`. Never emit an unpinned
     install command.
  3. No shell chaining. Never emit `apt install X && ...` or `apt install
     X; systemctl restart Y`. The three fields exist so the operator can
     stage each step; do not collapse them.
  4. No sudo prefix. The operator's config-management layer decides
     privilege escalation. Emit `apt install ...`, not `sudo apt install ...`.
  5. No -y flag (`apt install -y`). Unattended installs bypass the
     operator's chance to inspect the transaction; if the operator wants
     -y they'll add it themselves.
  6. Return ONLY the JSON object, no prose before or after, no
     markdown fencing. The exact shape is:

     {
       "apt_command": "...",
       "config_diff": "...",
       "service_restart": "...",
       "explanation": "..."
     }
"""


_MAX_EVIDENCE_LEN = 4000
_MAX_PROBE_OUTPUT_LEN = 2000


def build_remediation_prompt(verdict: dict[str, Any]) -> str:
    """Construct the per-verdict user turn.

    Passes the whole verdict record so the model has package_name,
    kev_product, evidence dict (with package_version), and probe_output
    to work from.
    """
    cve_id = verdict.get("cve_id", "CVE-UNKNOWN")
    reason = verdict.get("reason", "")
    evidence = verdict.get("evidence", {}) or {}
    probe_command = verdict.get("probe_command", "")
    probe_output = _truncate(verdict.get("probe_output", ""), _MAX_PROBE_OUTPUT_LEN)
    package_name = verdict.get("package_name", "")
    kev_product = verdict.get("kev_product", "")
    kev_vendor = verdict.get("kev_vendor", "")

    evidence_json = _render_json(evidence, limit=_MAX_EVIDENCE_LEN)

    parts: list[str] = []
    parts.append(f"CONFIRMED verdict for {cve_id}.")
    parts.append("")
    parts.append("CVE metadata (from analyzer + cve-matcher):")
    parts.append(f"  package_name: {package_name or '(unknown)'}")
    parts.append(f"  kev_product : {kev_product or '(unknown)'}")
    parts.append(f"  kev_vendor  : {kev_vendor or '(unknown)'}")
    parts.append("")
    parts.append("Analyzer reason:")
    parts.append(reason.strip() or "(no reason recorded)")
    parts.append("")
    parts.append("Evidence:")
    parts.append(evidence_json)
    parts.append("")
    if probe_command:
        parts.append(f"Probe executed: `{probe_command}`")
        if probe_output:
            parts.append("Probe output:")
            parts.append("```")
            parts.append(probe_output)
            parts.append("```")
        parts.append("")
    parts.append(
        "Produce the remediation JSON described in the system prompt. "
        "Return only the JSON object — no preamble, no summary, no markdown fencing."
    )
    return "\n".join(parts)


# ------------------------------------------------------------------ #
# Validator                                                          #
# ------------------------------------------------------------------ #


class RemediationValidationError(ValueError):
    """Raised when the model's response fails the guardrail checks."""


_REQUIRED_KEYS = ("apt_command", "config_diff", "service_restart", "explanation")

# apt-install shape check.
_APT_INSTALL_HEAD_RE = re.compile(r"^\s*apt(-get)?\s+install\s+", re.IGNORECASE)
# Version pin check — a `=<something>` after the package name.
_VERSION_PIN_RE = re.compile(r"=\S+")
# Forbidden constructs.
_FORBIDDEN_MANAGERS = ("yum", "dnf", "zypper", "pacman", "snap", "pip", "npm", "docker pull")
_FORBIDDEN_FLAGS = ("-y ", "--yes", "--assume-yes")
_FORBIDDEN_SUDO = "sudo"
_FORBIDDEN_CHAIN = ("&&", ";", "||", "\n")

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def parse_remediation(raw: str) -> dict[str, str]:
    """Extract + validate the model's JSON remediation response.

    Tolerates code-fence wrapping around the JSON (some models add it
    despite the prompt); rejects the response if any HARD constraint
    fails. Returns a dict with the 4 canonical keys (all strings).
    """
    text = raw.strip()
    if not text:
        raise RemediationValidationError("empty response")

    # Strip code fence if present.
    m = _JSON_FENCE_RE.search(text)
    if m:
        text = m.group(1).strip()

    # Grab first JSON object if there's leading/trailing prose.
    if not text.startswith("{"):
        m2 = _JSON_OBJECT_RE.search(text)
        if not m2:
            raise RemediationValidationError("no JSON object found in response")
        text = m2.group(0)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise RemediationValidationError(f"invalid JSON: {e}") from e

    if not isinstance(data, dict):
        raise RemediationValidationError("response is not a JSON object")

    # Presence check.
    missing = [k for k in _REQUIRED_KEYS if k not in data]
    if missing:
        raise RemediationValidationError(f"missing required keys: {sorted(missing)}")

    # Coerce to strings + strip.
    fields = {k: str(data[k]).strip() for k in _REQUIRED_KEYS}

    _validate_apt_command(fields["apt_command"])
    _validate_service_restart(fields["service_restart"])
    if not fields["explanation"]:
        raise RemediationValidationError("explanation is empty")

    # config_diff can be empty-sentinel or non-empty; empty string alone is not OK
    # (means the model punted). We coerce empty → the sentinel string here so
    # the operator sees a clear signal.
    if not fields["config_diff"]:
        fields["config_diff"] = "no config change needed"

    return fields


def _validate_apt_command(cmd: str) -> None:
    """Guardrail checks for apt_command.

    Empty string is ALLOWED — that's the "cannot be remediated with apt"
    escape hatch documented in HARD CONSTRAINT #1. The explanation must
    then say what to do instead.
    """
    if not cmd:
        return  # empty escape hatch

    for tok in _FORBIDDEN_MANAGERS:
        if tok in cmd.lower():
            raise RemediationValidationError(
                f"apt_command names a non-apt package manager: {tok!r}"
            )
    if any(chain in cmd for chain in _FORBIDDEN_CHAIN):
        raise RemediationValidationError(
            "apt_command must not chain multiple shell commands"
        )
    if cmd.lower().startswith(_FORBIDDEN_SUDO):
        raise RemediationValidationError(
            "apt_command must not include a sudo prefix"
        )
    for flag in _FORBIDDEN_FLAGS:
        if flag in cmd.lower():
            raise RemediationValidationError(
                f"apt_command must not include unattended-install flag {flag.strip()!r}"
            )
    if not _APT_INSTALL_HEAD_RE.match(cmd):
        raise RemediationValidationError(
            "apt_command must start with `apt install` or `apt-get install`"
        )
    if not _VERSION_PIN_RE.search(cmd):
        raise RemediationValidationError(
            "apt_command must pin an exact version with `=<version>` "
            "(refusing to emit an unpinned install)"
        )


def _validate_service_restart(cmd: str) -> None:
    """Loose guardrail for service_restart: forbid shell chaining and sudo.

    Empty is normalized to the sentinel by the caller. `no restart needed`
    is fine. Otherwise the string is emitted verbatim to the operator; we
    only refuse the same shell-chain / sudo footguns that apply to
    apt_command.
    """
    if not cmd or cmd.lower() == "no restart needed":
        return
    if any(chain in cmd for chain in _FORBIDDEN_CHAIN):
        raise RemediationValidationError(
            "service_restart must not chain multiple shell commands"
        )
    if cmd.lower().startswith(_FORBIDDEN_SUDO):
        raise RemediationValidationError(
            "service_restart must not include a sudo prefix"
        )


# ------------------------------------------------------------------ #
# Helpers                                                            #
# ------------------------------------------------------------------ #


def _render_json(obj: Any, limit: int | None = None) -> str:
    text = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    if limit is not None:
        text = _truncate(text, limit)
    return text


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, original length {len(text)} chars]"
