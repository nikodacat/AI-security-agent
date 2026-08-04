#requires -Version 5.1
<#
.SYNOPSIS
  Installs deliberately-outdated versions of common consumer software so the
  cve-matcher KEV engine has real findings to flag. RUN INSIDE A DISPOSABLE
  WINDOWS VM ONLY.

.DESCRIPTION
  Pulls installer binaries straight from each vendor's archive (no Chocolatey
  dependency — Chocolatey is unreliable for pinning very old versions).
  Every entry below maps to a known KEV CVE so you get predictable results
  when validating host-scanner + cve-matcher end-to-end.

  Target apps (all 64-bit):
    7-Zip 22.01              CVE-2025-0411   (Mark-of-the-Web bypass)
    Notepad++ 8.6.4          CVE-2025-15556  (updater integrity)
    Mozilla Firefox 115.5.0  CVE-2024-9680   (ransomware-linked UAF)
    WinRAR 6.10              CVE-2023-38831  (Russian APT delivery)

.NOTES
  - Requires admin to install per-machine MSIs/EXEs. Right-click "Run as Admin".
  - Disables Notepad++ auto-update post-install so 8.6.4 doesn't replace itself.
  - Firefox's installer will auto-update on first launch unless you also set
    `app.update.enabled=false` in about:config; that's separate.
  - Run scripts\collect-windows.ps1 (in cve-matcher) AFTER install to grab the
    inventory snapshot, then feed it to cve-matcher via --inventory.

.WARNING
  These versions have *known, actively-exploited vulnerabilities*. DO NOT run
  this on a machine you use for real work, banking, or anything sensitive.
  Use a VirtualBox / Hyper-V snapshot you can revert.
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Sanity check: refuse to run on the host's primary Windows install.
$confirm = $env:HOMESEC_TEST_VM_CONFIRM
if ($confirm -ne 'YES_I_AM_IN_A_DISPOSABLE_VM') {
    Write-Host '' -ForegroundColor Yellow
    Write-Host 'SAFETY GATE' -ForegroundColor Red
    Write-Host '-----------' -ForegroundColor Red
    Write-Host 'This script installs software with known active CVEs.' -ForegroundColor Yellow
    Write-Host 'It is intended for a disposable Windows VM, not your day-to-day PC.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'If you are CERTAIN you are inside a disposable VM, run:' -ForegroundColor Yellow
    Write-Host '  $env:HOMESEC_TEST_VM_CONFIRM = "YES_I_AM_IN_A_DISPOSABLE_VM"' -ForegroundColor Cyan
    Write-Host '  .\install-vulnerable-apps.ps1' -ForegroundColor Cyan
    Write-Host ''
    exit 2
}

# Check admin.
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( `
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[ERROR] Must run as Administrator.' -ForegroundColor Red
    exit 2
}

$downloadDir = Join-Path $env:TEMP 'homesec-test-installers'
New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null

$apps = @(
    [PSCustomObject]@{
        Name        = '7-Zip 22.01 (x64)'
        Url         = 'https://www.7-zip.org/a/7z2201-x64.exe'
        File        = '7z2201-x64.exe'
        InstallArgs = @('/S')
        CVE         = 'CVE-2025-0411'
    },
    [PSCustomObject]@{
        Name        = 'Notepad++ 8.6.4 (x64)'
        Url         = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.4/npp.8.6.4.Installer.x64.exe'
        File        = 'npp.8.6.4.Installer.x64.exe'
        InstallArgs = @('/S')
        CVE         = 'CVE-2025-15556'
    },
    [PSCustomObject]@{
        Name        = 'Mozilla Firefox 115.5.0 ESR'
        Url         = 'https://archive.mozilla.org/pub/firefox/releases/115.5.0esr/win64/en-US/Firefox%20Setup%20115.5.0esr.exe'
        File        = 'FirefoxSetup-115.5.0esr.exe'
        InstallArgs = @('/S', '/InstallDirectoryName=Mozilla Firefox 115.5.0 ESR')
        CVE         = 'CVE-2024-9680'
    },
    [PSCustomObject]@{
        Name        = 'WinRAR 6.10 (x64)'
        Url         = 'https://www.rarlab.com/rar/winrar-x64-610.exe'
        File        = 'winrar-x64-610.exe'
        InstallArgs = @('/S')
        CVE         = 'CVE-2023-38831'
    }
)

Write-Host '' -ForegroundColor Cyan
Write-Host '=== Installing deliberately-vulnerable test apps ===' -ForegroundColor Cyan
Write-Host ''

foreach ($app in $apps) {
    $target = Join-Path $downloadDir $app.File
    Write-Host "[+] $($app.Name)" -ForegroundColor Yellow
    Write-Host "    Maps to $($app.CVE)" -ForegroundColor DarkGray

    if (-not (Test-Path $target)) {
        Write-Host "    Downloading: $($app.Url)" -ForegroundColor DarkGray
        try {
            Invoke-WebRequest -Uri $app.Url -OutFile $target -UseBasicParsing
        } catch {
            Write-Host "    [SKIP] Download failed: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    } else {
        Write-Host '    (installer already cached)' -ForegroundColor DarkGray
    }

    Write-Host "    Running silent install..." -ForegroundColor DarkGray
    try {
        $p = Start-Process -FilePath $target -ArgumentList $app.InstallArgs -Wait -PassThru
        if ($p.ExitCode -ne 0) {
            Write-Host "    [WARN] Installer exited with $($p.ExitCode)" -ForegroundColor Yellow
        } else {
            Write-Host '    [OK] Installed' -ForegroundColor Green
        }
    } catch {
        Write-Host "    [SKIP] Install failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ''
}

# Pin Notepad++ auto-update OFF so 8.6.4 doesn't quietly replace itself.
$nppPaths = @(
    "${env:ProgramFiles}\Notepad++\updater\GUP.exe",
    "${env:ProgramFiles(x86)}\Notepad++\updater\GUP.exe"
)
foreach ($p in $nppPaths) {
    if (Test-Path $p) {
        try {
            Rename-Item $p "$p.disabled" -ErrorAction Stop
            Write-Host "[+] Disabled Notepad++ auto-updater: $p" -ForegroundColor Green
        } catch {}
    }
}

Write-Host ''
Write-Host 'Done. To verify, run cve-matcher against the live inventory:' -ForegroundColor Cyan
Write-Host '  cd C:\Users\<you>\project\cve-matcher' -ForegroundColor White
Write-Host '  python -m cve_matcher scan --check-versions --no-explain' -ForegroundColor White
Write-Host ''
Write-Host 'Expected findings (verdict=vulnerable):' -ForegroundColor Cyan
foreach ($app in $apps) {
    Write-Host "  - $($app.CVE)  <- $($app.Name)" -ForegroundColor White
}
Write-Host ''
