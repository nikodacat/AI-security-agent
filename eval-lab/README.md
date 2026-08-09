# eval-lab

Reproducible Docker Compose lab for evaluating the AI-security-agent
pipeline (host-scanner → cve-matcher → exposure-analyzer) against known
vulnerable software.

## Containers

| Container         | Base image             | Purpose                                                                 |
|-------------------|------------------------|-------------------------------------------------------------------------|
| `eval-web-vuln`   | `httpd:2.4.49`         | Apache HTTP Server 2.4.49 — CVE-2021-42013 (path traversal + RCE)       |
| `eval-db-exposed` | `redis:6.2.6`          | Redis 6.2.6, no auth, bound to all interfaces — exposure + CVE-2022-0543 |
| `eval-cms-plugin` | `wordpress:5.7-apache` | WordPress 5.7 stack — bundles vulnerable apache2 / openssl / wp-core    |

Each image adds `python3` plus a minimal scanner-dep subset
(`psutil rapidfuzz httpx pyyaml rich`) and copies in the `host-scanner/`
tree so a self-scan can run via `docker exec`.

## Usage

Build + start everything:

```bash
docker compose up -d --build
```

Run a scan inside a container (writes JSON to stdout):

```bash
docker exec eval-web-vuln   python /opt/host-scanner/scan_target.py > /tmp/web-vuln.json
docker exec eval-db-exposed python /opt/host-scanner/scan_target.py > /tmp/db-exposed.json
docker exec eval-cms-plugin python /opt/host-scanner/scan_target.py > /tmp/cms-plugin.json
```

Feed the JSON into cve-matcher + exposure-analyzer from the host (that
part is chunk I `run_full_scan.sh`).

Tear down:

```bash
docker compose down -v
```

## Design notes

- **Why `scan_target.py` and not the full `main.py`?** The full CLI drives
  Claude analysis + HTML report render, which needs external services and
  is redundant inside a target container. `scan_target.py` runs only the
  scanners that make sense self-hosted (system, software, users, processes,
  startup, hardware) and emits raw JSON. External-perspective scans (nmap,
  banner grabbing) belong on the host.

- **Why volume-mount `scan_output`?** So chunk I's `run_full_scan.sh` can
  pull scan outputs off each container without shell heredocs. The volume
  is empty by default; write to `/scan-output/` inside a container if you
  want durable output.

- **Why the WordPress DB env vars if we don't run MySQL?** WordPress's
  entrypoint reads them at start but does not require a reachable DB for
  the *packages* to be installed. Scanning finds the vulnerable packages
  regardless of whether WordPress can serve pages.

## Ground truth

Per-container CVE ground truth + expected verdicts live in
`ground_truth.md` (chunk H, not yet written).
