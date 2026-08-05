# exposure-analyzer

**Impact-analysis phase** of the AI-security-agent gray-box pipeline.

For each CVE candidate produced by `cve-matcher`, this module decides
whether the vulnerability actually matters on the specific target host
right now — using non-destructive probes and cross-domain synthesis of
config + exposure + runtime state via a Claude Agent SDK loop.

See `../docs/DESIGN.md` for the full project architecture and rationale.

## Pipeline position

```
host-scanner  →  cve-matcher  →  exposure-analyzer  →  HTML report
   (recon)     (enumeration)     (impact analysis)
```

## Verdicts produced

For each candidate CVE, the analyzer emits one of:

| Verdict | Meaning |
|---|---|
| `CONFIRMED` | Vulnerable version + service running + reachable + config doesn't mitigate |
| `MITIGATED_BY_CONFIG` | Vulnerable version installed, but config setting blocks the attack |
| `MITIGATED_BY_EXPOSURE` | Vulnerable version + running, but not reachable (loopback / firewalled) |
| `NOT_RUNNING` | Vulnerable version installed but service is stopped |
| `NO_EVIDENCE` | Insufficient data — falls back to human review |

## Status

**v0.0.1-scaffold** — module skeleton only. Real implementation lives in
build chunks D-I of `../docs/ROADMAP.md`. Running anything right now will
raise `NotImplementedError` — that's expected.

## Planned CLI (once implemented)

```bash
# Interactive mode: operator confirms each probe
python -m exposure_analyzer \
    --candidates ../cve-matcher/reports/candidates.json \
    --host-state ../host-scanner/reports/host_state.json \
    --output ./reports/verdicts.json

# Batch mode: no prompts
python -m exposure_analyzer ... --batch
```

## Development notes

- Package is called `exposure_analyzer` (underscored), folder is `exposure-analyzer/` (hyphenated).
- Runs against Claude Code CLI's subscription via `claude-agent-sdk` — no API key required if `CLAUDE_CLI_PATH` is set or `claude` is on PATH.
- `verdicts.py` is the data-model canonical source — every other module imports from it.
- `probes.py` starts with an empty `KNOWN_PROBES` dict; chunks D-E populate it.
