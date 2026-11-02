#!/usr/bin/env bash
# Build sec-agent-target for musl libc (Alpine Linux), which the glibc builds cannot start on:
# the loader they ask for (/lib64/ld-linux-x86-64.so.2) does not exist there, so `exec` fails
# with "no such file or directory". Alpine is the base of many real container images
# (grafana, postgres:*-alpine, zabbix, nginx:alpine, ...).
#
# PyInstaller ships no prebuilt bootloader for musl, so pip compiles it from source inside
# the build container (gcc + musl-dev + zlib-dev); this is why the first build takes a few
# minutes.
#
# Output: target-agent/dist/sec-agent-target-musl
# Needs: Docker, the python:3.9-alpine3.12 image (pulled on first run), network access for apk/pip.
#
# Usage:  ./build-musl.sh

set -euo pipefail
cd "$(dirname "$0")"

# Built on an OLD Alpine on purpose: a binary links against the musl it was built with, and a
# newer musl bundled into the executable segfaults on an older host. Alpine 3.12 (musl 1.1.24)
# is the oldest release with a Python 3.9 image and runs on newer Alpines too.
IMAGE="python:3.9-alpine3.12"

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

docker run --rm \
    -v "$(pwd):/work/target-agent" \
    -v "$(pwd)/../host-scanner:/work/host-scanner" \
    -w /work/target-agent \
    "$IMAGE" \
    sh -euxc "
        apk add --no-cache build-base zlib-dev binutils
        python3 -m pip install --quiet --upgrade pip
        python3 -m pip install --quiet pyinstaller
        python3 -m PyInstaller sec-agent-target.spec --clean --noconfirm \
            --distpath dist-musl --workpath build-musl
        mv dist-musl/sec-agent-target dist/sec-agent-target-musl
        rmdir dist-musl
        chmod +x dist/sec-agent-target-musl
        ls -lh dist/sec-agent-target-musl
    "

echo "[build] done -> $(pwd)/dist/sec-agent-target-musl"
