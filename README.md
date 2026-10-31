# AI Security Agent

A gray-box vulnerability assessment tool that answers the question scanners
leave open: **of the CVEs that match this machine's software, which ones can
actually be exploited here?**

Scanners list every CVE whose version range matches. This tool then asks an AI
reasoning layer to check each one against measured facts about the host
(config, loaded modules, listening sockets) and what an outside attacker can
reach, and returns one of five verdicts with its reasoning. It never
exploits anything.

Undergraduate 畢業專題 (Taiwan). Design rationale: `docs/DESIGN.md`. QA record:
`docs/VERIFICATION.md`. Status and open work: `PROJECT_STATE.md`.

> **Status: v3 work in progress.** The KEV pipeline, external prober, banner
> candidates and report stages are tested. NVD discovery (`--nvd-discovery`) is
> **experimental and off by default**. Read [Known limitations](#known-limitations)
> before relying on any verdict.

## How it works

```
 host-scanner / sec-agent-target     network-prober
 (what is installed and configured)  (what an outside attacker can reach)
              |                              |
              v                              v
        cve-matcher  ---- candidates ----> exposure-analyzer ---> verdicts
   CISA KEV match (+ optional           (AI reasons per CVE using host
   NVD discovery, experimental)          facts, probes, network facts)
        ^                                         |
   service banners (v3-1)                         v
                                       attack-simulator   fix-publisher
                                       (attack narrative) (pinned apt fix)
                                                  \         /
                                                   HTML report
```

Verdicts: `CONFIRMED` / `MITIGATED_BY_CONFIG` / `MITIGATED_BY_EXPOSURE` /
`NOT_RUNNING` / `NO_EVIDENCE`, each with structured evidence.

## Modules

| Folder | What it does |
|---|---|
| `host-scanner/` | Reads the host: packages, configs, services, users, ports, application inventory (WordPress, composer, jar, npm, pip), unmanaged binaries. Also posture and leak scanners (sshd, sudoers, SUID, exposed `.env`/`.git`); these are **not yet fed to the analyzer or report**. |
| `target-agent/` | `sec-agent-target`: the scanner as one Linux binary (no Python needed on the target). The default build needs glibc >= 2.28; `build-glibc217.sh` builds a variant for glibc >= 2.17, which is what jessie/stretch-era images such as the Vulhub ones need. Drop it into a container or server and run it. |
| `cve-matcher/` | Matches an inventory against CISA KEV; version-checks against NVD. `nvd_discovery.py` (experimental) asks NVD directly for CVEs affecting each detected product and version. |
| `network-prober/` | nmap-based view from outside: open ports, banners, best-guess service and version. Output is `network_state.json`. |
| `exposure-analyzer/` | The AI layer: per-CVE verdicts, read-only probes, optional LLM-proposed probes behind a human-approval gate. Runs on Claude (Agent SDK) or any OpenAI-compatible endpoint, so it can run on a **local model**. |
| `attack-simulator/` | For CONFIRMED verdicts only: a three-stage attack narrative (recon, discovery, exploitation) written as prose, with a guardrail that flags tool invocations. |
| `fix-publisher/` | For CONFIRMED verdicts only: remediation drafts. Commands must be version-pinned `apt install` lines; shell metacharacters are rejected. For software not managed by apt it may return no apt command and explain why. |
| `eval-lab/` | Three vulnerable Docker containers, the answer key (`ground_truth.yaml`), and the evaluation harness. |
| `docs/` | Design, roadmap, verification record, schemas. |
| `scripts/` | Bootstrap and local-scan helpers. |
| `紀錄/` | Weekly progress notes (Chinese). |

## Quickstart: scan this Linux server

```bash
git clone https://github.com/nikodacat/AI-security-agent.git
cd AI-security-agent
./scripts/bootstrap-linux.sh              # creates .venv/, installs dependencies

# AI verdicts need the Claude CLI logged in. Without it, use --engine=fake
# (deterministic passthrough, no AI) to see the pipeline run.
claude login
export NVD_API_KEY=...                    # optional; lifts NVD rate limits

./scripts/scan-local-host.sh --engine=claude --check-versions
# -> ./scan-results/<hostname>-<timestamp>/
#    scan.json  candidates.json  host_state.json  verdicts.json  report.html
```

Only scan machines you own or are authorized to assess.

## Quickstart: scan a container (full pipeline)

```bash
cd eval-lab
docker compose up -d --build              # Apache 2.4.49, Redis 6.2.6, WordPress 5.7.2

# Everything: scanner, KEV match, prober, analyzer, attack narrative, fixes, report
./run_full_scan.sh eval-web-vuln --engine=claude --v2

# Add banner-sourced candidates and (experimental) NVD discovery:
python run_full_scan.py --container eval-web-vuln --engine claude --v2 \
    --banner-candidates --nvd-discovery --nvd-min-cvss 7.0
```

`--nvd-discovery` adds CVEs from NVD that are not in CISA KEV. Each candidate
costs one model call, so it is bounded by `--nvd-min-cvss` (default 7.0) and
`--nvd-max-candidates` (default 40, highest score first).

## What you get

A run writes these files (`eval-lab/reports/<container>/` for the container
quickstart, `scan-results/<host>-<timestamp>/` for the host one):

| File | Contents |
|---|---|
| `scan.json` | What the scanner read from the target |
| `candidates.json` | CVEs to judge, each with its source (`inventory`, `banner`, `nvd-cpe`) |
| `network_state.json` | What the prober saw from outside (`--v2`) |
| `verdicts.json` | One verdict per candidate, with reason and evidence |
| `attack_narratives.md` | Prose attack path for each `CONFIRMED` (`--v2`) |
| `remediations.md` | Draft fixes for each `CONFIRMED` (`--v2`) |
| `report.html` | Everything above in one page |

A verdict from the Apache 2.4.49 container (`CVE-2021-42013`), reason shortened:

```json
{
  "cve_id": "CVE-2021-42013",
  "verdict": "CONFIRMED",
  "reason": "httpd -v confirms 2.4.49, mod_cgid is loaded enabling the RCE path, and the network-prober independently confirms port 80 is externally reachable. No mitigating config is present."
}
```

The other four verdicts say why a CVE does *not* apply (for example
`MITIGATED_BY_CONFIG`: the vulnerable module is not loaded). `NO_EVIDENCE` means
the data could not settle it; read that as "review by hand", not as "safe".

### Scan a container of your own

The container quickstart above is wired to the three eval containers. For any
other Debian/Ubuntu container, build the scanner once (`target-agent/build.sh`, or
`build-glibc217.sh` for old images; the binary lands in `target-agent/dist/`),
run it inside the container, and feed the JSON to
the same stages that `compare_arms.py` uses:

```bash
docker cp target-agent/dist/sec-agent-target <container>:/tmp/
docker exec <container> /tmp/sec-agent-target > host.json
python eval-lab/compare_arms.py --container <container> --arm now     --host-json host.json --network-state network_state.json --engine claude --out out/
```

`--max-calls` and `--max-cost-usd` on `compare_arms.py` cap model use (default
60 calls, $2). `network_state.json` comes from `network-prober`; see
`eval-lab/run_vulhub_offline.py` for a complete worked example of this sequence
on arbitrary images.

## Run on a local model

Verdicts do not need a hosted model. Any OpenAI-compatible chat endpoint works:

```bash
python -m exposure_analyzer analyze --candidates candidates.json \
    --host-state host_state.json --engine openai \
    --base-url http://localhost:8080/v1/chat/completions --model <name>
```

In our comparison a local Qwen3.5-9B reached the same scores as Claude on the
answer key (see Results). Small models occasionally return malformed JSON; the
analyzer retries once and then reports that CVE as having no verdict instead
of failing the batch.

## Results

Three containers (Apache 2.4.49, Redis 6.2.6, WordPress 5.7.2 + PHP 7.4.21),
24 answer-key entries (6 expected CONFIRMED). `eval-lab/compare_arms.py` runs a
version of the tool against them; `eval-lab/score_arms.py` scores it. Claude
engine; week-9 and "banners" rows are the mean of 2 runs, the NVD row is 1 run.

| Version | Answer-key entries correct (of 24) | Real vulns found (of 6) | False CONFIRMED |
|---|---|---|---|
| Week 9 (KEV on package inventory only) | 7 | 0 | 0 |
| + richer scanner + service banners | 11 | 2 | 0 |
| + NVD discovery (CVSS >= 7.0, experimental) | 13 | 3 | 0 |

- A local Qwen3.5-9B scored the same as Claude on the first two rows (11 of 24).
  The NVD row was **not** completed for Qwen: the local server stalled, so no
  Qwen number is claimed for it.
- **NVD discovery is slow and only partly verified.** It added 30-40
  candidates per container (about 1000 s per container vs about 90 s) and
  produced 28 `CONFIRMED` verdicts on CVEs the answer key does not list. We
  checked 9 of them, the Redis 6.2.6 ones, against the running container's
  configuration (no password, default ACL allows everything, Lua / `RESTORE` /
  HyperLogLog available, port reachable without credentials): all 9 hold, i.e.
  affected version and reachable feature. Nothing was exploited. The other 19
  (6 on Apache 2.4.49, 9 on the WordPress container, 4 on Debian OpenSSL / bash)
  are unreviewed, not known-correct. The checked ones are in
  `eval-lab/adjudicated_confirmed.yaml`, kept apart from the answer key because
  the NVD run itself found them, so counting them as answer-key entries would
  inflate its recall. On the WordPress container 12 candidates got no verdict because
  of model-call errors.
- **Both candidate limits hide real bugs.** Redis CVE-2022-24735 (CVSS 3.9) and
  CVE-2022-24736 (3.3) are in the answer key as real, and a 7.0 cutoff never
  raises them. Separately, the cap of 40 is applied to one global CVSS ranking
  across all software, so on the WordPress container a crowd of high-scoring
  Apache CVEs pushed out OpenSSL CVE-2022-0778 (7.5, an answer-key real vuln;
  it ranks 9th of 25 among OpenSSL's own candidates). CVSS is not a relevance
  score, so lowering the cap would hide more. A lower-cutoff or per-product-cap
  run was not done.
- The answer key was corrected once after results were seen (Redis
  CVE-2022-0543 is not exploitable on the upstream image); see the revision
  log in `eval-lab/ground_truth.md`.
- Sample is small (3 containers, 1-2 runs, key written by the author). Treat
  it as a regression signal.

### Answer key we did not write: Vulhub

Each [Vulhub](https://github.com/vulhub/vulhub) directory exists to demonstrate one
named CVE on a pinned image, so that CVE is an answer key the project did not
author. Five scenarios with a CVE (`eval-lab/vulhub_scenarios.yaml`), Claude
engine, **1 run each**, scored only on whether that CVE came out `CONFIRMED`:

| Scenario | Expected | KEV + banners | + NVD discovery |
|---|---|---|---|
| PHP 5.4.1 (CGI) | CVE-2012-1823 | CONFIRMED | not run |
| Struts2 2.3.30 | CVE-2017-5638 | CONFIRMED | not run |
| Solr 8.11.0 (Log4Shell) | CVE-2021-44228 | CONFIRMED | not run |
| nginx 1.13.2 | CVE-2017-7529 | not a candidate | CONFIRMED |
| bash 4.3 (Shellshock) | CVE-2014-6271 | not a candidate | **MITIGATED_BY_CONFIG (wrong)** |

3 of 5 with KEV and banners, 4 of 5 with NVD discovery on nginx and bash; the
NVD arm was not run on the other three. Only nginx is found *because of* NVD
discovery. Notes:

- **The bash miss is real.** That image replaces `/bin/bash` with a vulnerable
  4.3.0 build but leaves dpkg saying `4.3-11+deb8u1`, the patched Debian
  revision. The tool trusts the package database, so it judged the bug patched
  (while calling the sibling CVE-2014-6277 `CONFIRMED`). Checking the actual
  binary's version would catch it; that is not implemented.
- Other `CONFIRMED` verdicts on these images (for example three more Struts2
  CVEs, and OpenSSL ones on nginx) have no answer key and are unreviewed.
- A Solr run before the service finished starting reported nothing reachable
  and judged it mitigated. That was our test harness, not the tool; it was
  fixed (the harness now waits for the port) and redone, and the first run is not
  counted.
- Cost: all six scenarios on KEV and banners about $0.7; the nginx and bash NVD
  runs about $1.8 (63 model calls). Run caps exist (`--max-calls`,
  `--max-cost-usd`).

## Known limitations

- **Coverage depends on the candidate source.** CISA KEV lists only CVEs seen
  exploited, so most CVEs are invisible to the default path. NVD discovery
  widens this but is experimental, and a severity cutoff can hide real
  low-severity bugs (see Results).
- **Distro backports.** Debian fixes CVEs without changing the upstream
  version, so a version inside NVD's affected range does not prove a Debian
  package is unpatched. These candidates are marked `unknown`; the analyzer
  has no distro fix-version data, so for them it judges from what the model
  remembers about Debian's fix versions, which this project has not verified.
  Debian's security tracker no longer publishes data for buster or bullseye
  (EOL), the releases of our test containers, so the check cannot be made
  with it. In the NVD run these Debian-revisioned packages were 74 of 132
  candidates, and their `CONFIRMED` verdicts rest on that recollection.
- **Configuration-dependent bugs can be over-confirmed.** Example: a bug that
  needs specific `mod_rewrite` rules was judged CONFIRMED because the module
  was loaded, although no rewrite rules exist.
- **Local privilege escalations** can be presented as remotely reachable.
- **Posture and leak findings** (sshd, sudoers, SUID, exposed secrets) are
  collected but not yet part of the verdicts or the report.
- **Small evaluation.** Three self-built containers and an answer key written
  by the project author. The key has already needed one correction (see
  `eval-lab/ground_truth.md`, revision log). Treat the scores as a regression
  signal, not an independent benchmark.
- Linux targets only. Debian/Ubuntu is the tested family.

## Responsible use

This tool assesses systems you own or are authorized to test. It does not
exploit, brute-force, or modify the target: probes are read-only and
allow-listed, and any LLM-proposed probe requires human approval.
`attack-simulator` writes prose about how a confirmed weakness could be
abused, to explain risk to defenders; its prompt prohibits tool command lines
and a post-check flags any that slip through, but this is a safeguard, not a
guarantee. Do not point it at systems you do not have permission to assess.

## Tests

```bash
for m in host-scanner exposure-analyzer network-prober attack-simulator fix-publisher cve-matcher; do
  (cd $m && python -m pytest -q)
done
```

481 tests across the six packages at the time of writing (host-scanner 91,
exposure-analyzer 189, network-prober 35, attack-simulator 67, fix-publisher
84, cve-matcher 15).

## Not tracked here

| Item | Why |
|---|---|
| `PentestGPT/`, `VulnBot/`, `auto-pen-bench/`, `genai-pentest-paper/` | Upstream projects evaluated during the thesis; clone them per `SETUP-FORKS.md`, provenance in `UPSTREAM.md`. They keep their own licenses. |
| Real scan output (`*/reports/`, `scan-results/`) | Describes specific machines. |
| API caches (`cve-matcher/cache/`) | Regenerated on demand. |
| Virtualenvs, `.env`, keys | Local only; see `.gitignore`. |

## License

MIT, see `LICENSE`.
