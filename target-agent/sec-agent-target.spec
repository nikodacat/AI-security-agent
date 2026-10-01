# PyInstaller spec for sec-agent-target.
#
# Builds a single-file Linux x86_64 executable that bundles host-scanner's
# self-scan subset. Build inside quay.io/pypa/manylinux2014_x86_64 so the
# resulting binary links against glibc 2.17 and runs on every Vulhub /
# Debian-stable / RHEL-7+ target we care about.

import os

HOST_SCANNER = os.path.abspath(os.path.join(os.getcwd(), '..', 'host-scanner'))

a = Analysis(
    ['target_agent_main.py'],
    pathex=[HOST_SCANNER],
    binaries=[],
    datas=[],
    # importlib.import_module() is dynamic -- PyInstaller cannot follow it
    # from static analysis, so every scanner module gets listed explicitly.
    hiddenimports=[
        'scanners',
        'scanners.base',
        'scanners.system',
        'scanners.software',
        'scanners.users',
        'scanners.processes',
        'scanners.startup',
        'scanners.hardware',
    ],
    hookspath=[],
    runtime_hooks=[],
    # Coordinator-only deps that host-scanner's requirements.txt lists but
    # that no self-scan scanner imports. Explicit excludes shave MB off
    # the final binary and prove the dependency boundary.
    excludes=[
        'fastapi',
        'uvicorn',
        'jinja2',
        'rich',
        'rapidfuzz',
        'yaml',
        'httpx',
        'python_multipart',
        'weasyprint',
        'anyio',
        'starlette',
    ],
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='sec-agent-target',
    debug=False,
    bootloader_ignore_signals=False,
    # strip is normally desirable but python:3.9-slim-buster doesn't ship
    # binutils and buster's apt repos are EOL (moved to archive.debian.org),
    # so we skip strip rather than pull from archive. ~2MB penalty.
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
