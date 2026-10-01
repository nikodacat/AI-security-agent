# fix-publisher

Per-CONFIRMED-verdict remediation drafter. Reads `verdicts.json` from
`exposure-analyzer`, filters to `CONFIRMED` entries, and produces a
structured remediation record per CVE:

- **`apt_command`** — pinned install block (`apt install libssl1.1=<version>`)
- **`config_diff`** — unified diff of the config change, or `"no config change needed"`
- **`service_restart`** — systemctl restart directive, or `"no restart needed"`
- **`explanation`** — one or two sentences on why this fixes the CVE

**Advisory only.** Nothing is auto-applied. The output is a draft an operator
reads, sanity-checks against their fleet's package pins, and applies by hand
(or feeds into their config-management pipeline). fix-publisher never touches
the target.

## Position in the pipeline

```
exposure-analyzer  →  verdicts.json  →  attack-simulator  →  attack_narratives.{json,md}
                                     →  fix-publisher     →  remediations.{json,md}
```

`fix-publisher` and `attack-simulator` are independent post-processors that
both fan out from `verdicts.json`. Neither talks to the target; neither
depends on the other. See `docs/DESIGN.md §1.4.6` for the shape.

## Scope

- **Package system:** Debian/Ubuntu `apt` only. RPM/DNF/YUM is deferred to
  v3 (see DESIGN.md §1.3 out-of-scope list).
- **Version pinning:** required. The validator rejects `apt install libssl1.1`
  without an `=<version>` clause — an unpinned fix can regress silently when
  the repo's latest lags the vendor's fixed version.
- **Filter:** CONFIRMED verdicts only. Other verdicts don't need remediation.

## Usage

```
python -m fix_publisher publish \
    --verdicts path/to/verdicts.json \
    --output   path/to/remediations.json \
    --markdown path/to/remediations.md \
    --engine   claude
```

`--engine=fake` runs a canned publisher for tests and offline development.
Output shape: one remediation record per CONFIRMED verdict, plus a
human-readable Markdown companion.

## Design references

- `docs/DESIGN.md §1.4.6` — attack-simulator + fix-publisher fan-out
- `PROJECT_STATE.md` — v2-10 chunk log
