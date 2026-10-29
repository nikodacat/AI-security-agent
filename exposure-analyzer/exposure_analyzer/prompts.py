"""Claude prompts for the exposure-analyzer.

`SYSTEM_PROMPT` frames Claude's role as a gray-box impact analyst.
`build_verdict_prompt()` constructs a per-candidate user turn from the CVE
metadata + host state + optional probe output.

The prompt design is informed by PentestGPT (Deng et al., 2023) -- see
`../docs/DESIGN.md` section 3 for the citation.
"""

from __future__ import annotations

import json
from typing import Any


SYSTEM_PROMPT = """\
You are a gray-box security-assessment advisor. For each CVE candidate the
operator gives you, decide whether it is currently exploitable on THIS host
given the evidence provided, and produce a structured verdict.

You have five verdict values available:
  CONFIRMED            - vulnerable version + service running + reachable + config does not mitigate
  MITIGATED_BY_CONFIG  - the attack is blocked by a code- or config-level factor. This
                         INCLUDES the case where the installed package version is post-fix
                         (i.e. NOT in any affected range) -- the "config" is the choice of
                         patched package version. See "Version-based rule" below.
  MITIGATED_BY_EXPOSURE - vulnerable version + running, but not reachable (loopback / firewalled)
  NOT_RUNNING          - vulnerable version installed but the service is stopped.
                         ONLY use this for services/daemons (sshd, httpd, redis-server).
                         Libraries (openssl, bash, glibc, ghostscript) are always "running"
                         if installed -- do not label a library-only CVE as NOT_RUNNING.
  NO_EVIDENCE          - insufficient data to decide; recommend human review.
                         DO NOT use this when the CVE metadata already resolves the
                         question -- e.g. an explicit "not in any affected range" verdict
                         from the vendor-patch check is evidence, not absence of it.

Version-based rule (applies to most candidates the operator will send you):
- Look at CVE metadata field `verdict_detail`. If it says something like
  "Installed <version> not in any affected range" or "patched", the installed
  package is post-fix. The correct verdict is `MITIGATED_BY_CONFIG` with the
  reason citing the version + fix boundary. Do NOT downgrade to `NO_EVIDENCE`
  because a probe wasn't run -- the version metadata IS the evidence. Do NOT
  use `NOT_RUNNING` for libraries just because host_state lacks a matching
  process (libraries do not appear in process lists).

Service-config rule (applies when host_state has a `services` section):
- host_state.services holds measured facts from inside the host: which process
  owns each listening port and on which address, which Apache modules are
  loaded, key php.ini flags. Prefer these over assumptions. If a CVE needs a
  component that `services` shows is NOT loaded (e.g. an Apache mod_proxy SSRF
  with `mod_proxy_loaded: false`, or a CGI-dependent bug with `mod_cgi_loaded:
  false`), the attack path does not exist -> MITIGATED_BY_CONFIG, citing that
  field. If `services` shows the component present and the version is
  affected, that supports CONFIRMED (together with reachability).
- A candidate with `package_source` such as `unmanaged-binary`, `wordpress-core`,
  `wordpress-plugin`, `composer`, `jar`, `npm` or `pip` came from outside the OS
  package manager. Its version is a measurement of the installed files, so apply
  the Version-based rule to it exactly like a package version. These items have
  no distro backports: an affected version is genuinely unpatched.

External-attacker rule (applies when the "External-attacker view" section is present):
- The `network_state` section, when shown, is what an external attacker on the
  same network measured — which ports responded, banner strings, best-guess
  service+version. Treat this as the ground truth for REACHABILITY, since the
  host's own config is a claim and network_state is a measurement.
- If a CVE's affected service is `reachable: true` externally AND the version
  is affected AND config does not mitigate → CONFIRMED (with reachability
  cited as evidence).
- If host_state says the service is bound to 0.0.0.0 but network_state shows
  `reachable: false` for that port, prefer network_state and downgrade to
  MITIGATED_BY_EXPOSURE (a firewall, container network, or ACL is in the way
  even though the service claims it's listening).
- If network_state is silent about a service (no matching port in the array),
  that is ABSENCE OF EVIDENCE, not evidence of absence — do NOT downgrade to
  MITIGATED_BY_EXPOSURE just because the prober didn't scan the port. Reason
  from host_state + probe evidence instead.
- Library CVEs (openssl, bash, glibc, ghostscript, zlib, libxml2, libcurl,
  and similar shared libraries) are decided by the Version-based rule ABOVE,
  not by network_state. Even if a reachable service (Apache, nginx, sshd)
  links against the library, that reachability does NOT promote a
  patched-version library CVE to CONFIRMED. Worked examples:
    * Heartbleed (CVE-2014-0160) on OpenSSL 1.1.1n (post-fix), reachable
      Apache → MITIGATED_BY_CONFIG. Apache reachability is not evidence the
      vulnerable code path exists.
    * Shellshock (CVE-2014-6278) on bash 5.0 (post-fix), reachable Apache
      with CGI → MITIGATED_BY_CONFIG. Bash version resolves the question.
    * CVE-2022-0778 on OpenSSL 1.1.1d (PRE-fix, vulnerable) + reachable
      Apache serving TLS → CONFIRMED. Library IS in an affected range AND
      the network exposes it — this is the case v2's external leg was built
      for.
  Distinguisher: `verdict_detail` version status, not service reachability.

Other rules:
- Cite the specific evidence you used (config key names, port bindings, probe
  output substrings, `verdict_detail` values, and — when relevant — network_state
  entries like "port 6379 reachable, banner Redis 6.2.6"). Do not speculate
  beyond what the operator gave you.
- Never propose exploitation. You are a defender, not an attacker.
- If evidence is genuinely contradictory (e.g. version says vulnerable AND probe
  says patched), return NO_EVIDENCE and describe the conflict.

Response format:
Return ONLY a single JSON object, no prose before or after, matching this shape:
{
  "verdict": "<one of the five values above>",
  "reason": "<one-paragraph explanation, <= 400 chars>",
  "evidence": {"<field>": "<value>", ...}
}
"""


# Cap host_state serialization so a huge scanner output can't blow the prompt.
_HOST_STATE_CHAR_LIMIT = 8000
# Cap probe_output too -- probes should be small but be defensive.
_PROBE_OUTPUT_CHAR_LIMIT = 4000
# Cap network_state serialization. Even a 3-target, --top-ports 100 scan is
# well under this cap; the ceiling exists so a runaway prober output can't
# blow the prompt.
_NETWORK_STATE_CHAR_LIMIT = 6000


def build_verdict_prompt(
    candidate: dict[str, Any],
    host_state: dict[str, Any],
    probe_command: str = "",
    probe_output: str = "",
    network_state: list[dict[str, Any]] | None = None,
) -> str:
    """Construct the per-candidate user turn.

    Args:
        candidate:      one entry from cve-matcher's `kev_findings` array.
        host_state:     the full host-scanner output for the target.
        probe_command:  the command that was executed (empty if none).
        probe_output:   captured stdout/stderr of the probe (empty if none).
        network_state:  external-scan output from network-prober (v2). List of
                        PortObservation dicts conforming to
                        docs/schemas/network_state.schema.json. None (default)
                        means v1-style analysis with no external leg — the
                        prompt omits the External-attacker view entirely so
                        the model gets the same input as v1 for baseline
                        comparisons.

    Returns:
        A prompt string ready to be sent as the user turn.
    """
    parts: list[str] = []

    cve_id = candidate.get("cve_id", "CVE-UNKNOWN")
    parts.append(f"Candidate: {cve_id}")
    parts.append("")
    parts.append("CVE metadata:")
    parts.append(_render_json(_candidate_summary(candidate)))
    parts.append("")

    parts.append("Relevant host state (from host-scanner):")
    parts.append(_render_json(host_state, limit=_HOST_STATE_CHAR_LIMIT))
    parts.append("")

    if probe_command:
        parts.append(f"Probe executed: `{probe_command}`")
        if probe_output:
            truncated = _truncate(probe_output, _PROBE_OUTPUT_CHAR_LIMIT)
            parts.append("Probe output:")
            parts.append("```")
            parts.append(truncated)
            parts.append("```")
        else:
            parts.append("Probe output: (empty)")
        parts.append("")
    else:
        parts.append("Probe executed: (none)")
        parts.append("")

    if network_state is not None:
        filtered = _relevant_observations(network_state, candidate)
        parts.append("External-attacker view (from network-prober):")
        parts.append(_describe_network_state(filtered, len(network_state)))
        parts.append(_render_json(filtered, limit=_NETWORK_STATE_CHAR_LIMIT))
        parts.append("")

    parts.append(
        "Decide the verdict for this CVE on this host. Respond with the JSON "
        "object described in the system prompt."
    )
    return "\n".join(parts)


def _relevant_observations(
    network_state: list[dict[str, Any]],
    candidate: dict[str, Any],
) -> list[dict[str, Any]]:
    """Filter network_state to observations plausibly relevant to this CVE.

    Heuristic: match if the observation's ``service_guess.product`` or
    ``banner`` contains any token from the CVE's ``kev_product`` /
    ``package_name`` (case-insensitive, min token length 3 to avoid matching
    single letters). If nothing matches we still show a slim "reachable ports"
    slice — better than empty when the prober found something the analyzer
    can consider adjacent (e.g. an unexpected open port on the same host).

    Library CVEs (kev_product like "openssl", "bash", "glibc") tend to match
    no network banners, and that's fine — the External-attacker rule in the
    system prompt tells the model to ignore network_state for those.
    """
    tokens = _service_tokens(candidate)
    if not tokens:
        return [obs for obs in network_state if obs.get("reachable")]

    matched: list[dict[str, Any]] = []
    for obs in network_state:
        hay_parts: list[str] = []
        sg = obs.get("service_guess") or {}
        for k in ("vendor", "product"):
            v = sg.get(k)
            if isinstance(v, str):
                hay_parts.append(v)
        banner = obs.get("banner")
        if isinstance(banner, str):
            hay_parts.append(banner)
        hay = " ".join(hay_parts).lower()
        if any(t in hay for t in tokens):
            matched.append(obs)

    if matched:
        return matched
    # No token match — surface reachable ports so the model can note them
    # (a Redis CVE with only nginx open should say NOT_RUNNING/absent, not
    # blindly assume unreachable).
    return [obs for obs in network_state if obs.get("reachable")]


def _service_tokens(candidate: dict[str, Any]) -> list[str]:
    """Pull match tokens from CVE metadata, lowercased, min length 3.

    Splits on non-alphanumerics so "openssh-server" → ["openssh", "server"]
    and "httpd" stays "httpd". Dedup while preserving order.
    """
    fields = [
        candidate.get("kev_product") or "",
        candidate.get("kev_vendor") or "",
        candidate.get("package_name") or "",
    ]
    seen: set[str] = set()
    ordered: list[str] = []
    for value in fields:
        for raw in _split_alnum(value.lower()):
            if len(raw) >= 3 and raw not in seen:
                seen.add(raw)
                ordered.append(raw)
    return ordered


def _split_alnum(text: str) -> list[str]:
    """Split on runs of non-alphanumeric characters (stdlib-only, no regex import needed)."""
    parts: list[str] = []
    current: list[str] = []
    for ch in text:
        if ch.isalnum():
            current.append(ch)
        elif current:
            parts.append("".join(current))
            current = []
    if current:
        parts.append("".join(current))
    return parts


def _describe_network_state(shown: list[dict[str, Any]], total: int) -> str:
    """One-line preamble to the network_state JSON block."""
    if total == 0:
        return "(prober produced no observations)"
    if len(shown) == total:
        return f"({total} observation(s) from prober, all shown):"
    return (
        f"({len(shown)} of {total} observation(s) shown, "
        "filtered to those matching this CVE's service; "
        "remainder omitted for context size):"
    )


def _candidate_summary(candidate: dict[str, Any]) -> dict[str, Any]:
    """Pull the fields the analyzer actually reasons over."""
    keep = (
        "cve_id",
        "kev_name",
        "kev_vendor",
        "kev_product",
        "kev_description",
        "cwes",
        "package_name",
        "package_version",
        "package_source",
        "source",
        "source_port",
        "banner",
        "verdict",
        "verdict_detail",
        "ransomware_linked",
    )
    return {k: candidate[k] for k in keep if k in candidate}


def _render_json(obj: Any, limit: int | None = None) -> str:
    text = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    if limit is not None:
        text = _truncate(text, limit)
    return text


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, original length {len(text)} chars]"
