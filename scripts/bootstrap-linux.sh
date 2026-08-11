#!/usr/bin/env bash
# One-shot bootstrap for a fresh Linux server (Ubuntu / Debian).
#
# Installs the three module dependencies + the eval-lab harness into a
# shared venv at .venv/ at the repo root. Idempotent -- safe to re-run.
#
# Usage:  ./scripts/bootstrap-linux.sh [--with-eval-lab]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "[bootstrap] Repo root: $REPO_ROOT"

# Sanity: Python 3.9+
python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
required="3.9"
if [ "$(printf '%s\n' "$required" "$python_version" | sort -V | head -n1)" != "$required" ]; then
    echo "[bootstrap] ERROR: Python $required or later required (found $python_version)" >&2
    exit 1
fi
echo "[bootstrap] Python $python_version detected"

# Create venv if missing
if [ ! -d .venv ]; then
    echo "[bootstrap] Creating .venv/"
    python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --quiet --upgrade pip

echo "[bootstrap] Installing host-scanner deps"
pip install -r host-scanner/requirements.txt

echo "[bootstrap] Installing cve-matcher deps"
pip install -r cve-matcher/requirements.txt

echo "[bootstrap] Installing exposure-analyzer deps"
pip install -r exposure-analyzer/requirements.txt

if [ "${1:-}" = "--with-eval-lab" ]; then
    echo "[bootstrap] Installing eval-lab harness deps"
    pip install -r eval-lab/requirements.txt
    echo "[bootstrap] Note: eval-lab also needs docker + docker compose."
    echo "[bootstrap] Verify: docker --version && docker compose version"
fi

echo
echo "[bootstrap] Done. Activate with:  source .venv/bin/activate"
echo "[bootstrap] Try a scan:            cd host-scanner && python main.py"
echo
if command -v claude >/dev/null 2>&1; then
    echo "[bootstrap] claude CLI found: $(claude --version 2>&1 | head -1)"
else
    echo "[bootstrap] Note: 'claude' CLI not on PATH -- install for --engine=claude runs;"
    echo "           pipeline still works with --engine=fake (deterministic, no AI)."
fi
