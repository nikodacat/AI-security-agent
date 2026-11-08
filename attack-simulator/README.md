# attack-simulator

Per-CONFIRMED-verdict LLM narrative generator. Reads `verdicts.json` from
`exposure-analyzer`, filters to `CONFIRMED` entries, and produces a text
attack-path narrative (recon → discovery → exploitation) for each one.

**Advisory only.** Narratives describe the shape of a plausible attack — the
attacker's likely reconnaissance steps, what they would discover, how they
would move to exploitation. Narratives do NOT include specific attacker-tool
invocations (no `nmap -sV`, no `sqlmap -u ...`, no metasploit modules, no
curl payloads); prompt-adapter fidelity, not tool orchestration.

## Position in the pipeline

```
exposure-analyzer  →  verdicts.json  →  attack-simulator  →  attack_narratives.{json,md}
                                     →  fix-publisher     →  remediation.{json,md}
```

`attack-simulator` and `fix-publisher` are independent post-processors that
both fan out from `verdicts.json`. Neither talks to the target; neither
depends on the other. See `docs/DESIGN.md §1.4.6` for the shape.

## Usage

```
python -m attack_simulator narrate \
    --verdicts path/to/verdicts.json \
    --output   path/to/attack_narratives.json \
    --markdown path/to/attack_narratives.md \
    --engine   claude
```

`--engine=fake` runs a canned narrator for tests and offline development.
Output shape: one narrative per CONFIRMED verdict, plus a human-readable
Markdown companion file.

## Design references

- `docs/DESIGN.md §1.4.6` — attack-simulator + fix-publisher fan-out
- Deng et al. 2023 (PentestGPT) — prompt-adapter reference (not vendored)
