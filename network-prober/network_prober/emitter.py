"""Emitter — converts raw python-nmap scan results into PortObservation rows.

Contract: input is the dict returned by :func:`network_prober.prober.scan_targets`
(one entry per target, each with ``tcp`` and ``udp`` port maps keyed by port
number); output is a list conforming to
``docs/schemas/network_state.schema.json``.

Emitter does NOT filter closed ports. Nmap's ``--top-ports N`` scan returns
state for every one of the top N ports, and preserving that in the output
lets the analyzer distinguish "we scanned and confirmed not-listening" from
"we didn't scan this port at all." If closed rows become noisy for the
analyzer prompt in v2-5, filter there — the raw prober output stays honest.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .parser import parse_banner


_STATE_REACHABLE: frozenset[str] = frozenset({"open"})


def build_port_observation(
    target: str,
    port: int,
    protocol: str,
    reachable: bool,
    banner: str | None = None,
    service_guess: dict | None = None,
) -> dict:
    """Construct a single PortObservation dict.

    Optional fields are omitted (not set to null) when absent, to match the
    schema's ``additionalProperties: false`` guarantee — the analyzer prompt
    reads ``"service_guess" in obs`` rather than checking for a null value.
    """
    obs: dict[str, Any] = {
        "target": target,
        "port": int(port),
        "protocol": protocol,
        "reachable": bool(reachable),
    }
    if banner:
        obs["banner"] = banner
    if service_guess:
        obs["service_guess"] = service_guess
    return obs


def _banner_from_nmap_port(port_info: dict) -> str | None:
    """Reconstruct a banner string from python-nmap's per-port dict.

    python-nmap gives us split fields (``product``, ``version``, ``extrainfo``);
    we join the non-empty ones with a single space. Returns None when nothing
    useful is available.
    """
    parts = [
        (port_info.get("product") or "").strip(),
        (port_info.get("version") or "").strip(),
        (port_info.get("extrainfo") or "").strip(),
    ]
    banner = " ".join(p for p in parts if p)
    return banner or None


def observations_from_scan(scan_results: dict) -> list[dict]:
    """Turn :func:`prober.scan_targets`'s output into PortObservation rows.

    Deterministic ordering: targets in the input dict's order, then
    ``tcp`` before ``udp``, then ports ascending. This makes fixture
    round-trips reproducible without a separate sort step.
    """
    observations: list[dict] = []
    for target, data in scan_results.items():
        for proto in ("tcp", "udp"):
            ports = data.get(proto) or {}
            for port in sorted(ports):
                info = ports[port]
                state = (info.get("state") or "").strip()
                reachable = state in _STATE_REACHABLE
                banner = _banner_from_nmap_port(info) if reachable else None
                service_guess = parse_banner(banner) if banner else None
                observations.append(
                    build_port_observation(
                        target=target,
                        port=port,
                        protocol=proto,
                        reachable=reachable,
                        banner=banner,
                        service_guess=service_guess,
                    )
                )
    return observations


def emit_network_state(
    scan_results: dict,
    output_path: str | Path,
    schema_path: str | Path | None = None,
) -> list[dict]:
    """Full emitter pipeline: raw scan → observations → validated JSON on disk.

    When ``schema_path`` is provided, the observations are validated against
    the JSON Schema before write. A validation failure raises
    :class:`jsonschema.ValidationError` and no file is written — the caller
    (the CLI) surfaces this to the operator.
    """
    observations = observations_from_scan(scan_results)
    if schema_path:
        _validate(observations, schema_path)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        json.dump(observations, f, indent=2)
        f.write("\n")
    return observations


def _validate(observations: list[dict], schema_path: str | Path) -> None:
    """Validate ``observations`` against the schema at ``schema_path``.

    Isolated so tests can mock it out without a real schema on disk.
    """
    from jsonschema import Draft202012Validator

    with Path(schema_path).open(encoding="utf-8") as f:
        schema = json.load(f)
    Draft202012Validator(schema).validate(observations)
