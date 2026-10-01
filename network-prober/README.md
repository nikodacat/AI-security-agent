# network-prober

**External-scan phase** of the AI-security-agent gray-box pipeline.

Probes target hosts from an external attacker vantage point, measuring port
reachability, grabbing service banners, and identifying running services.
Runs on the coordinator container (`eval-attacker`) and emits
`network_state.json` consumed by `exposure-analyzer` to cross-reference
insider configuration state with measured external reachability.

See `../docs/DESIGN.md` §1.4 for the architecture.

## Pipeline position

```
network-prober  →  exposure-analyzer  →  HTML report
 (external scan)   (impact analysis)
```

## Output shape

Each entry in `network_state.json` represents a single port observation adhering to `docs/schemas/network_state.schema.json`:

| Field | Meaning |
|---|---|
| `target` | Hostname or IP scanned, as given (e.g. `eval-web-vuln`, `eval-db-exposed`) |
| `port` | Port number scanned (1–65535) |
| `protocol` | Transport protocol (`tcp` or `udp`) |
| `reachable` | `true` if port completed handshake / replied; `false` if closed, filtered, or no reply |
| `banner` | Raw fingerprint string returned by prober/nmap; preserved verbatim as LLM fallback |
| `service_guess` | Parsed `{vendor, product, version}` object from banner-parser table, or absent |

## Status

**v0.0.1-scaffold** — package skeleton only. Real implementation lives in
build chunk v2-4 (Phase 2). Running anything right now will raise
`NotImplementedError` — that's expected.

## Planned CLI (once implemented)

```bash
python -m network_prober scan \
    --target eval-web-vuln \
    --target eval-db-exposed \
    --target eval-cms-plugin \
    --output /prober-output/network_state.json
```

## Development notes

- Package folder is `network-prober/` (hyphenated), python package is `network_prober` (underscored).
- Runs inside the `eval-attacker` container (has nmap installed).
- No LLM calls, deterministic; `python-nmap` handles raw scanning.
- Output validated against `docs/schemas/network_state.schema.json` before write.
