# AI Security Agent — thesis workspace

An AI-augmented **gray-box** security assessment tool for school servers.
Combines internal recon (`host-scanner`) with external threat intel
(`cve-matcher` against CISA KEV / NVD) and an AI reasoning layer
(`exposure-analyzer`, backed by Claude Agent SDK) that produces per-CVE
exploitability verdicts without needing actual exploitation.

Undergraduate 畢業專題 (Taiwan). See `docs/DESIGN.md` for the design
rationale, `docs/ROADMAP.md` for the build plan, and `docs/VERIFICATION.md`
for the QA / deployability audit.

## Pipeline

```
    host-scanner        →       cve-matcher       →      exposure-analyzer
    (recon)                    (enumeration)             (impact analysis)

    packages / configs /       KEV catalog match +       AI reasoning over
    services / users /         optional NVD version-     config + exposure +
    ports on THIS host         range check               runtime state → verdict
```

Five verdict values per CVE: `CONFIRMED` / `MITIGATED_BY_CONFIG` /
`MITIGATED_BY_EXPOSURE` / `NOT_RUNNING` / `NO_EVIDENCE`, each with
Claude-authored reasoning + structured evidence.

## What's tracked here

| Folder | Purpose |
|---|---|
| `host-scanner/` | 8 scanners (system / software / network / users / processes / filesystem / startup / hardware) producing a JSON scan of the target host. |
| `cve-matcher/` | KEV-driven vulnerability matcher. Takes an inventory, matches against CISA KEV, optionally NVD version-check. Standalone or importable. |
| `exposure-analyzer/` | AI verdict-synthesis module. Reads cve-matcher output + host state, runs non-destructive probes via Claude Agent SDK loop, emits per-CVE verdicts. |
| `eval-lab/` | Reproducible 3-container Docker Compose lab + eval harness. Ground truth committed pre-analyzer for defensibility. |
| `docs/` | DESIGN.md (architecture), ROADMAP.md (build plan), VERIFICATION.md (QA audit). |
| `scripts/` | Bootstrap + init helpers. `bootstrap-linux.sh` is the one-command install. |
| `紀錄/` | Weekly thesis progress notes (Chinese). |

## What's NOT tracked here (by design)

| Item | Where to get it | Why excluded |
|---|---|---|
| `PentestGPT/` | https://github.com/GreyDGL/PentestGPT @ `6e84be8` | 1.6 GB upstream + GPL stack |
| `auto-pen-bench/` | https://github.com/lucagioacchini/auto-pen-bench @ `9c4890a` | Upstream code |
| `VulnBot/` | https://github.com/KHenryAegis/VulnBot @ `951cbcc` | Upstream code |
| `genai-pentest-paper/` | https://github.com/lucagioacchini/genai-pentest-paper @ `40e01e5` | Upstream PDFs / dataset |
| Real scan output | `*/reports/` (regenerated per run) | Contains data about specific machines |
| API caches | `cve-matcher/cache/` | Regenerated on demand |
| Virtualenvs | `.venv/`, `.venv-*/` | Bootstrapped per host |
| Env files / keys | `.env`, `*.pem`, `id_rsa`, ... | Secrets, see `.gitignore` |

See `UPSTREAM.md` for fork provenance and `SETUP-FORKS.md` for cloning them.

## Quickstart — fresh Linux server (Ubuntu / Debian)

```bash
# 1. Clone
git clone https://github.com/nikodacat/AI-security-agent.git
cd AI-security-agent

# 2. One-command install (creates .venv/ at repo root, installs all deps)
./scripts/bootstrap-linux.sh
# Or, to also install eval-lab harness deps (needs docker):
# ./scripts/bootstrap-linux.sh --with-eval-lab

# 3. (Optional) Authenticate Claude CLI for the AI verdict engine.
#    If you skip this, the pipeline still runs with --engine=fake
#    (deterministic, cve-matcher passthrough, no AI cost).
claude --version && claude login

# 4. (Optional) NVD API key to lift rate limits on version-check pass
export NVD_API_KEY=...

# 5. Run a scan on THIS server
source .venv/bin/activate
cd host-scanner && python main.py        # writes reports/report_*.html

# 6. (Optional) Add the AI verdict layer
cd ../cve-matcher && python -m cve_matcher scan --check-versions   # candidates
cd ../exposure-analyzer && python -m exposure_analyzer analyze \
    --candidates ../cve-matcher/reports/candidates.json \
    --host-state ../host-scanner/reports/raw_*.json \
    --engine claude \
    --report ../host-scanner/reports/report_*.html
```

Steps 5 and 6 are independent. Step 5 is a standalone scan (works with
zero AI dependencies). Step 6 layers Claude reasoning on top for
per-CVE verdicts.

For platform-specific detail: `host-scanner/LINUX.md`.

## Testing + reproducible eval lab

```bash
# Bring up 3 vulnerable containers (Apache 2.4.49, Redis 6.2.6 unauth, WordPress 5.7)
cd eval-lab && docker compose up -d --build

# Run the full chain against one container
./run_full_scan.sh eval-web-vuln --engine=claude

# Run the eval matrix over all 3, diff vs ground_truth.md / .yaml
./run_eval.sh --engine=claude
# Or dry-run without Claude cost:
./run_eval.sh --engine=fake
```

Outputs land in `eval-lab/reports/<container>/` (gitignored) plus
`eval-lab/reports/eval_results.csv` + `eval_summary.md`.

Ground truth was committed **before** any analyzer run and is
audit-trailed in `eval-lab/ground_truth.md`'s revision log.

## Tests

```bash
cd exposure-analyzer && python -m unittest discover -s tests
```

52 tests, ~87% coverage of exposure-analyzer. See
`docs/VERIFICATION.md` for the full QA record.

## Updating the VM

```bash
cd AI-security-agent && git pull
# If any requirements.txt changed:
./scripts/bootstrap-linux.sh    # idempotent, safe to re-run
```

## License

MIT — see `LICENSE` at repo root. Reference forks (PentestGPT, VulnBot,
auto-pen-bench, genai-pentest-paper) live outside this repo and retain
their own upstream licenses.
