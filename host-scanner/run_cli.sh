#!/usr/bin/env bash
# HomeSecAI - CLI scan on Linux/macOS.
# Usage: ./run_cli.sh
#
# Mirrors run_cli.ps1: locate Claude CLI (PATH or $CLAUDE_CLI_PATH), activate
# venv if present, force UTF-8 I/O, then run main.py.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# ----- Locate the Claude CLI -----------------------------------------------
claude_path=""
if [[ -n "${CLAUDE_CLI_PATH:-}" && -x "${CLAUDE_CLI_PATH}" ]]; then
    claude_path="${CLAUDE_CLI_PATH}"
elif command -v claude >/dev/null 2>&1; then
    claude_path="$(command -v claude)"
fi

if [[ -z "$claude_path" ]]; then
    echo "[ERROR] Claude CLI not found." >&2
    if [[ -n "${CLAUDE_CLI_PATH:-}" ]]; then
        echo "  CLAUDE_CLI_PATH = ${CLAUDE_CLI_PATH} (not executable or does not exist)" >&2
    else
        echo "  CLAUDE_CLI_PATH is not set" >&2
    fi
    echo "  'claude' is not on PATH either" >&2
    echo "" >&2
    echo "Install Claude Code:  https://docs.claude.com/en/docs/claude-code" >&2
    echo "Either add it to PATH or export CLAUDE_CLI_PATH=/path/to/claude" >&2
    echo "Then run 'claude' once to sign in." >&2
    exit 1
fi
echo "Using Claude CLI: $claude_path"

# ----- Activate the project's venv if it exists ----------------------------
if [[ -f "$PROJECT_ROOT/.venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "$PROJECT_ROOT/.venv/bin/activate"
fi

# ----- Force UTF-8 I/O so Rich renders Unicode cleanly ---------------------
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

python main.py "$@"
