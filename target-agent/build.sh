#!/usr/bin/env bash
# Build sec-agent-target binary using manylinux2014 for broad glibc compat.
#
# Output:
#   target-agent/dist/sec-agent-target  (Linux x86_64 ELF, glibc >= 2.17)
#
# Runs via Docker so it works on Linux hosts, WSL, and Windows+Docker-Desktop
# alike. The build container is pulled on first run (~800MB) and cached.
#
# Usage:  ./build.sh

set -euo pipefail

cd "$(dirname "$0")"

# Debian 10 buster: glibc 2.28. Vulhub's older containers (httpd 2.4.49,
# anything from the 2017-2020 era) are built on buster, and a bullseye-built
# binary (glibc 2.31) refuses to launch there. buster's broader compat is
# worth sticking with Python 3.9 -- host-scanner is 3.9-compatible.
# manylinux2014 would give even older glibc (2.17), but its Python is
# statically linked and PyInstaller refuses it.
IMAGE="python:3.9-slim-buster"
PYBIN="python3"

# MSYS2 / Git-Bash on Windows mangles any argv that looks like a Linux path.
# Suppress that for the docker call so -v and -w land correctly inside the
# Linux container. No-op on Linux hosts.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

echo "[build] using image: $IMAGE"
echo "[build] host-scanner path: $(pwd)/../host-scanner"

docker run --rm \
    -v "$(pwd):/work/target-agent" \
    -v "$(pwd)/../host-scanner:/work/host-scanner" \
    -w /work/target-agent \
    "$IMAGE" \
    bash -euxc "
        # buster's deb.debian.org repos are EOL; the archive still serves it.
        sed -i -e 's|deb.debian.org/debian|archive.debian.org/debian|g' \
               -e 's|deb.debian.org/debian-security|archive.debian.org/debian-security|g' \
               -e '/debian-security buster\\/updates/d' \
               -e '/buster-updates/d' \
               /etc/apt/sources.list
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends binutils
        ${PYBIN} -m pip install --quiet --upgrade pip
        ${PYBIN} -m pip install --quiet pyinstaller
        ${PYBIN} -m PyInstaller sec-agent-target.spec --clean --noconfirm
        chmod +x dist/sec-agent-target
        ls -lh dist/sec-agent-target
    "

echo
echo "[build] done -> $(pwd)/dist/sec-agent-target"
