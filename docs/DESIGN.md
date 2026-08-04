# AI-security-agent — Design & Decisions

**Project:** Cross-platform gray-box automated security assessment tool for school servers.
**Level:** Undergraduate 畢業專題 (not master's thesis).
**Runway:** ~3 months (12 weeks) as of this document.
**Repo:** https://github.com/nikodacat/AI-security-agent (private).

This document captures the decisions locked in during the grill-me session and serves as the
authoritative reference for future sessions. When you come back to work on this project after
a break, read this file first — it replaces the need to re-grill.

---

## 1. Thesis claim

> An AI-augmented **gray-box** security assessment tool that automates the reasoning
> pentesters do between "we detected a candidate CVE" and "here's whether it actually matters
> on this host." Primary target: school servers. Secondary demo: home Windows desktop.

Gray-box = authorized insider access. Not black-box (external attacker with no info) and not
white-box (full source access). Insider intel (`host-scanner`) is combined with external
threat intel (`cve-matcher` against KEV/NVD) and synthesized by an AI reasoning layer
(`exposure-analyzer`) that produces per-CVE verdicts without needing actual exploitation.

---

## 2. Decision tree (from grill-me session)

Legend: `[ASKED]` = user explicitly decided; `[AUTO]` = filled with a stable default and
accepted at final confirmation.

### Branch: Project constraints

- [ASKED] Timeline: ~3 months (12 weeks) of runway
- [ASKED] Deliverable format: written report + live demo + oral defense
- [ASKED] Primary positioning: 校園伺服器弱點評估工具; home Windows as secondary demo
- [AUTO] Project level: undergrad 畢業專題 (evaluation bar = demo-able system, not research contribution)
- [AUTO] Report language: Traditional Chinese
- [AUTO] Code + commit language: English
- [AUTO] Repo: private, `nikodacat/AI-security-agent`

### Branch: Feature scope

- [ASKED] Build the verification bridge as headline v1 feature: YES
- [ASKED] Nothing else added in v1 — cut items become v2 candidates:
  - [AUTO] Cut → v2: RPM/Fedora support
  - [AUTO] Cut → v2: external `nmap -sV` → CVE bridge
  - [AUTO] Cut → v2: additional scanner categories
  - [AUTO] Cut → v2: web dashboard polish
  - [AUTO] Cut → v2: 5-host lab (using 3-container Docker lab instead)
- [AUTO] Timing model: Claude-paced (~5-6 active weeks + 6-7 weeks buffer)
- [AUTO] Buffer usage: safety margin, not more features

### Branch: Bridge design

- [ASKED] Verifier path: A first (advisor + human-in-loop), evolve toward B (autonomous with allow-list) if time
- [ASKED] Module location: standalone sibling + top-level `run_full_scan.sh` wrapper
- [ASKED] Renames before build:
  - `home-security-ai/` → **`host-scanner/`**
  - `cve-scanner/` → **`cve-matcher/`**
  - `verifier/` (proposed) → **`exposure-analyzer/`**
- [ASKED] Probe generation: hybrid — hardcoded per-CVE for v1, Claude-generated fallback drafted as v2
- [ASKED] Demo mode: interactive default + `--batch` flag for scheduled runs
- [ASKED] Gray-box reframe adopted as the project's thesis claim
  - [AUTO] Verifier's real job = cross-domain synthesis (config + exposure + runtime → per-CVE verdict), not redundant re-scan
- [ASKED] PentestGPT usage: B + D combo now (adapt prompts + design extension hooks); Path C (full `attack-simulator/`) is v2
- [ASKED] "Fix publishment" = interpretation A — a `fix-publisher/` remediation module as v2 stretch
- [AUTO] Verifier input: JSON from cve-matcher + host-scanner output
- [AUTO] Verdict schema: `CONFIRMED` / `MITIGATED_BY_CONFIG` / `MITIGATED_BY_EXPOSURE` / `NOT_RUNNING` / `NO_EVIDENCE` + reasoning + evidence
- [AUTO] Verifier output: appended to host-scanner's existing HTML report
- [AUTO] Claude backend: Claude Code CLI (subscription-backed) via `CLAUDE_CLI_PATH`
- [AUTO] Language: Python, Claude Agent SDK loop pattern

### Branch: Evaluation plan

- [ASKED] Primary metric: TPR / FPR / coverage against ground truth; time-per-verdict secondary
- [ASKED] Numeric baseline: raw cve-matcher output (isolates analyzer's contribution)
- [ASKED] No numeric head-to-head with Nessus/OpenVAS — use a **capability comparison table** instead
- [ASKED] Value framing: v1 proves the AI-augmented reasoning layer; v2's attack-sim + fix-publisher are what pro scanners genuinely don't do
- [ASKED] Lab: Docker Compose, 3 deliberately-vulnerable containers, `ground_truth.md` committed to repo
  - [AUTO] Containers:
    - (a) Ubuntu 22.04 web (vulnerable Apache + config-mitigated OpenSSH)
    - (b) Debian 12 database (exposed Redis + old MySQL)
    - (c) Ubuntu 20.04 CMS (WordPress + vulnerable plugin)
  - [AUTO] Gray-box scanning: `docker exec` the scanner into each container
- [AUTO] Sample size: ~30 CVE evaluations across the 3 containers
- [AUTO] Randomness: single deterministic run (temperature=0); note in "threats to validity"
- [AUTO] Human-analyst baseline: OPTIONAL, only if numeric results feel thin

### Branch: Ship checklist

- [ASKED] Report length: 15-25 pages (target ~20), not 40-60
- [ASKED] Chapter structure: 緒論 / 相關研究 / 系統設計 / 實作 / 評估 / 討論與未來工作 / 結論
- [ASKED] Demo: 5-minute interactive live run in the 3-container Docker lab
- [AUTO] Advisor cadence: bi-weekly demo of latest chunk
- [AUTO] Peer testing: one friend runs `docker compose up && ./run_full_scan.sh` 1 week before defense
- [AUTO] Backup plan: pre-recorded 3-minute demo video 3 days before defense
- [AUTO] Repo visibility: private through defense day
- [AUTO] Version tag: `v1.0-defense` at the exact demoed commit
- [AUTO] Dependency caching: KEV JSON + NVD cache committed to repo day before defense

---

## 3. Architecture (v1 + v2 hooks)

```mermaid
flowchart TB
    subgraph EL["eval-lab/ (Docker Compose)"]
        C1["container: web-vuln<br/>Ubuntu 22.04 + Apache 2.4.49"]
        C2["container: db-exposed<br/>Debian 12 + Redis (no-auth)"]
        C3["container: cms-plugin<br/>Ubuntu 20.04 + WordPress"]
    end

    subgraph V1["v1 pipeline (this project, 12 weeks)"]
        direction TB
        HS["host-scanner/<br/><i>Recon phase</i><br/>packages · configs · services<br/>users · ports · files"]
        CM["cve-matcher/<br/><i>Enumeration phase</i><br/>KEV alias match<br/>+ NVD version-range check"]
        EA["exposure-analyzer/<br/><i>Impact analysis phase</i><br/>Claude Agent SDK loop<br/>probe library (hardcoded)<br/>per-CVE verdict engine<br/>interactive + --batch"]
    end

    subgraph V2["v2 modules (skeletons in v1, real in v2)"]
        AS["attack-simulator/<br/><i>Red-team phase</i><br/>PentestGPT + Claude bridge<br/>attack path suggestions"]
        FP["fix-publisher/<br/><i>Remediation phase</i><br/>generate patch commands<br/>optionally auto-apply"]
    end

    subgraph EXT["External / cached data"]
        KEV[("CISA KEV<br/>daily cached")]
        NVD[("NVD API<br/>30d cache")]
        CC["Claude Code CLI<br/>(subscription-backed<br/>via CLAUDE_CLI_PATH)"]
    end

    C1 -->|"docker exec"| HS
    C2 -->|"docker exec"| HS
    C3 -->|"docker exec"| HS

    HS -->|"host_state.json"| CM
    CM -->|"candidates.json"| EA
    HS -->|"context for synthesis"| EA

    KEV -.->|"catalog"| CM
    NVD -.->|"CPE version ranges"| CM
    CC -.->|"probe reasoning<br/>+ verdict generation"| EA

    EA -->|"verdicts.json"| RPT["Combined HTML/MD report"]
    EA -.->|"extension hook"| AS
    EA -.->|"extension hook"| FP

    style AS stroke-dasharray: 5 5,stroke:#888,color:#666
    style FP stroke-dasharray: 5 5,stroke:#888,color:#666
    style V2 stroke-dasharray: 5 5,stroke:#888
```

Dashed boxes = v2 (skeletons only in v1 build). Solid boxes = v1 must-work by defense day.

---

## 4. v2 roadmap (post-defense)

- **`attack-simulator/`** — full PentestGPT+Claude bridge (Path C). Feeds off host-scanner
  + cve-matcher output; produces attacker-perspective "here's what a real attacker would
  chain together" report alongside the blue-team one.
- **`fix-publisher/`** — generates concrete remediation commands per verified CVE (patch
  install, config change, service restart) and optionally applies them under human
  approval. Closes the loop: assessment → verification → remediation.
- **RPM/Fedora inventory support** in host-scanner.
- **External `nmap -sV` → CVE bridge** for scanning targets the agent can't get shell on.
- **Web dashboard polish** — live progress view during a scan.

---

## 5. Report chapter allocation (~20 pages target)

| # | Chapter | Pages | Focus |
|---|---|---|---|
| 1 | 緒論 (Introduction) | 2 | motivation, professor's ask, scope |
| 2 | 相關研究 (Related Work) | 2 | Nessus/OpenVAS comparison table, PentestGPT, KEV/NVD |
| 3 | 系統設計 (System Design) | 4 | gray-box methodology, three-module architecture, diagrams |
| 4 | 實作 (Implementation) | 3 | interesting design decisions, key snippets, prompt engineering |
| 5 | 評估 (Evaluation) | 5 | lab, methodology, TPR/FPR results, capability comparison, threats to validity |
| 6 | 討論與未來工作 (Discussion & Future Work) | 2 | limitations, v2/v3 roadmap |
| 7 | 結論 (Conclusion) | 1 | wrap-up |
| — | 參考文獻 + 附錄 | 1-3 | key prompts, ground_truth.md excerpt |
| — | **Total** | **~20** | |

---

## 6. Demo script (defense day, 5 minutes)

```
0:00–0:30  Set the scene: "3-container lab representing a school server env"
           docker compose up (already running, no wait time)
0:30–1:30  Run host-scanner against container A
           Show terminal: package inventory, config extraction
1:30–2:30  Run cve-matcher on the inventory
           Show: N candidate CVEs, KEV-matched
2:30–4:00  Run exposure-analyzer INTERACTIVELY
           For 3 CVEs: show proposed probe, hit ENTER, show verdict
           Include one CONFIRMED, one MITIGATED, one NOT_RUNNING
4:00–4:30  Show the final HTML report
           "12 candidates → 3 real risks, actionable"
4:30–5:00  Show attack-simulator skeleton (v2 preview)
           "this is where the red-team module plugs in"
```

---

## 7. Next steps (immediately after this doc lands)

1. Rename `home-security-ai/` → `host-scanner/`, `cve-scanner/` → `cve-matcher/`. Update all
   imports, launchers, gitignore paths, README, LINUX.md, UPSTREAM.md, SETUP-FORKS.md.
   One commit.
2. Scaffold `exposure-analyzer/` sibling directory with package skeleton (prompts.py,
   probes.py, agent.py, report.py) — empty implementations + docstrings only.
3. Invoke `/roadmap-plan` to break the exposure-analyzer build into ordered chunks with
   explicit dependencies.
4. Kick off first chunk via `/build-verify-loop`.

---

*Document generated at the close of the grill-me session that reset this project after a
break. If a future session invalidates any of these decisions, update this file and note
what changed and why.*
