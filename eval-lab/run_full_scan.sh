#!/usr/bin/env bash
# End-to-end scan+match+analyze wrapper for one eval-lab container.
#
# Usage:  ./run_full_scan.sh <container> [--engine=claude|fake] [--check-versions] [--no-probes]
#
# Delegates all real work to run_full_scan.py -- this shell wrapper exists
# because the roadmap lists it by name and it's a slightly friendlier entry
# point than remembering the full python invocation.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <container> [--engine=...] [--check-versions] [--no-probes]" >&2
  echo "example: $0 eval-web-vuln --engine=claude" >&2
  exit 2
fi

CONTAINER="$1"
shift

HERE="$(cd "$(dirname "$0")" && pwd)"

# MSYS_NO_PATHCONV so git-bash on Windows leaves /opt/... paths alone when
# they are passed onward to docker exec.
export MSYS_NO_PATHCONV=1
export PYTHONIOENCODING=utf-8

exec python "$HERE/run_full_scan.py" --container "$CONTAINER" "$@"
