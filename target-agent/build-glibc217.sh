#!/usr/bin/env bash
# Build sec-agent-target for glibc >= 2.17 (Debian 8 jessie, Debian 9 stretch,
# RHEL/CentOS 7 ...), which the buster-built binary from build.sh cannot start on.
#
# Why this exists: manylinux2014's bundled Python is statically linked and
# PyInstaller refuses it (see build.sh). Here we compile our own CPython 3.9
# with --enable-shared inside the manylinux2014 image (CentOS 7, glibc 2.17)
# and run PyInstaller with that.
#
# The `ssl` module is skipped: CentOS 7 ships OpenSSL 1.0.2, which Python 3.9
# will not build against, and the self-scan scanners do not use TLS.
#
# Output: target-agent/dist/sec-agent-target-glibc217
# Needs: Docker, and the quay.io/pypa/manylinux2014_x86_64 image (pulled on
# first run) plus network access to fetch the CPython source tarball.
#
# Usage:  ./build-glibc217.sh

set -euo pipefail
cd "$(dirname "$0")"

PYVER="3.9.19"
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

docker run --rm \
    -v "$(pwd):/work/target-agent" \
    -v "$(pwd)/../host-scanner:/work/host-scanner" \
    -w /work/target-agent \
    quay.io/pypa/manylinux2014_x86_64 \
    bash -euxc "
        yum install -y -q zlib-devel bzip2-devel libffi-devel readline-devel xz-devel sqlite-devel
        cd /tmp
        curl -sSLO https://www.python.org/ftp/python/${PYVER}/Python-${PYVER}.tgz
        tar xzf Python-${PYVER}.tgz
        cd Python-${PYVER}
        ./configure --prefix=/opt/py39shared --enable-shared \
            LDFLAGS='-Wl,-rpath,/opt/py39shared/lib' --without-ensurepip -q
        make -j\$(nproc) -s
        make install -s
        export LD_LIBRARY_PATH=/opt/py39shared/lib
        # Our shared Python has no ssl, so it cannot run pip itself. Fetch PyInstaller
        # (wheels bundle the bootloader) with the image's own Python, then run it
        # from the shared interpreter via PYTHONPATH.
        /opt/python/cp39-cp39/bin/pip install -q --target /tmp/pyi pyinstaller
        cd /work/target-agent
        export SAT_EXTRA_LIBS=\$(ls /usr/local/lib/libcrypt.so.2 /usr/lib64/libcrypt.so.2 /lib64/libcrypt.so.2 2>/dev/null | head -1)
        test -n \"\$SAT_EXTRA_LIBS\" || { echo 'libcrypt.so.2 not found in build image' >&2; exit 1; }
        echo \"extra libs: \$SAT_EXTRA_LIBS\"
        PYTHONPATH=/tmp/pyi /opt/py39shared/bin/python3 -m PyInstaller sec-agent-target.spec --clean --noconfirm \
            --distpath dist-glibc217 --workpath build-glibc217
        mv dist-glibc217/sec-agent-target dist/sec-agent-target-glibc217
        rmdir dist-glibc217
        chmod +x dist/sec-agent-target-glibc217
        ls -lh dist/sec-agent-target-glibc217
    "

echo "[build] done -> $(pwd)/dist/sec-agent-target-glibc217"
