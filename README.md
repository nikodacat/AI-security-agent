# AI Security Agent — thesis workspace

This repository holds the AI-augmented security agent built for my thesis,
plus the weekly progress notes. Reference forks of related academic /
industry projects are evaluated alongside this work but are intentionally
kept outside this repo (see `SETUP-FORKS.md`).

## What's tracked here

| Folder | Purpose |
|---|---|
| `host-scanner/` | End-to-end agent: 8 scanners (system, software, network, users, processes, filesystem, startup, hardware) feeding a Claude analysis layer that produces an executive-summary HTML/markdown report. Cross-platform (Windows + Linux). |
| `cve-matcher/` | KEV-driven personal vulnerability scanner. Reads installed packages, matches them against the CISA KEV catalog, optionally hits NVD to decide whether the installed version is in the affected range. Used standalone or imported by `host-scanner`. |
| `紀錄/` | Weekly thesis progress notes (Chinese). |

## What's NOT tracked here (by design)

| Item | Where to get it | Why excluded |
|---|---|---|
| `PentestGPT/` | https://github.com/GreyDGL/PentestGPT @ `6e84be8` | 1.6 GB upstream + GPL stack |
| `auto-pen-bench/` | https://github.com/lucagioacchini/auto-pen-bench @ `9c4890a` | Upstream code, kept separate |
| `VulnBot/` | https://github.com/KHenryAegis/VulnBot @ `951cbcc` | Upstream code, kept separate |
| `genai-pentest-paper/` | https://github.com/lucagioacchini/genai-pentest-paper @ `40e01e5` | Upstream PDFs / dataset |
| Real scan output | `*/reports/` (regenerated per run) | Contains data about specific machines |
| API caches | `cve-matcher/cache/` | Regenerated on demand |
| Virtualenvs | `.venv/`, `.venv-*/` | Bootstrapped per host |
| Env files / keys | `.env`, `*.pem`, `id_rsa`, ... | Secrets, see `.gitignore` for the full list |

See `UPSTREAM.md` for fork provenance details and `SETUP-FORKS.md` for
instructions to clone them into the same working tree if needed.

## Deploying to a Linux server / VM via git pull

On the server:

```bash
# clone the repo
git clone https://github.com/nikodacat/AI-security-agent.git
cd AI-security-agent

# bootstrap the two projects
cd cve-matcher && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && cd ..
cd host-scanner && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && cd ..

# install Claude Code CLI (handles AI analysis layer)
# follow https://docs.claude.com/en/docs/claude-code  then `claude` once to sign in

# optional: lift NVD rate limit
export NVD_API_KEY=...

# run the full agent
cd host-scanner
./run_cli.sh        # markdown + HTML report into reports/
./run_web.sh        # web dashboard on :8000
```

For platform-specific details see `host-scanner/LINUX.md`.

## Updating the VM

```bash
cd AI-security-agent
git pull
# if requirements.txt changed:
cd host-scanner && source .venv/bin/activate && pip install -r requirements.txt && cd ..
```

## License

The projects in this repo (`host-scanner/`, `cve-matcher/`) are
licensed under MIT unless otherwise noted within each folder. Forks live
outside this repo and retain their own upstream licenses.
