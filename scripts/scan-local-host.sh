#!/usr/bin/env bash
# Scan THIS host end-to-end and produce Claude-analyzed CVE verdicts.
#
# Real-server equivalent of eval-lab/run_full_scan.sh -- probes run
# directly on the local machine instead of via `docker exec` into a
# container. Use this on the box you actually want to assess.
#
# Usage:
#   ./scripts/scan-local-host.sh [--engine=claude|fake] [--check-versions]
#                                [--out-dir=<path>]
#
# Prereqs:
#   - ./scripts/bootstrap-linux.sh has been run (deps installed in .venv/)
#   - For --engine=claude: `claude` CLI installed + authenticated
#   - For --check-versions: reachable NVD (optional NVD_API_KEY env)
#
# Produces (in --out-dir, default ./scan-results/<hostname>-<ts>/):
#   scan.json         raw host-scanner output
#   candidates.json   cve-matcher findings in exposure-analyzer's shape
#   host_state.json   squeezed host state for the analyzer
#   verdicts.json     final per-CVE verdicts
#   report.html       host-scanner HTML report with verdicts appended

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Activate the shared venv from bootstrap-linux.sh
if [ ! -f .venv/bin/activate ]; then
    echo "[scan] ERROR: .venv/ not found. Run ./scripts/bootstrap-linux.sh first." >&2
    exit 1
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# Defaults
ENGINE="claude"
CHECK_VERSIONS=""
OUT_DIR=""

for arg in "$@"; do
    case "$arg" in
        --engine=*)         ENGINE="${arg#*=}" ;;
        --check-versions)   CHECK_VERSIONS="1" ;;
        --out-dir=*)        OUT_DIR="${arg#*=}" ;;
        -h|--help)
            grep -E "^#" "$0" | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *)
            echo "[scan] unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

HOSTNAME_SAFE=$(hostname | tr '/' '_' | tr ':' '_')
TS=$(date +%Y%m%d_%H%M%S)
OUT_DIR="${OUT_DIR:-./scan-results/${HOSTNAME_SAFE}-${TS}}"
mkdir -p "$OUT_DIR"

echo "[scan] Target: $(hostname)"
echo "[scan] Engine: $ENGINE"
echo "[scan] Output: $OUT_DIR"

# Delegate the actual work to a small Python driver so we can reuse the
# adapters from eval-lab/run_full_scan.py without duplicating them.
export PYTHONIOENCODING=utf-8
python "$REPO_ROOT/scripts/scan_local_host.py" \
    --engine "$ENGINE" \
    ${CHECK_VERSIONS:+--check-versions} \
    --out-dir "$OUT_DIR"
