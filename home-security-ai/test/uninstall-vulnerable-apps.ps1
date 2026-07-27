#requires -Version 5.1
<#
.SYNOPSIS
  Uninstalls the deliberately-vulnerable test apps put in by
  install-vulnerable-apps.ps1. Reverting the VM snapshot is usually simpler
  and safer; this script is provided as a backup.

.NOTES
  Each entry tries the vendor's silent-uninstall pattern. If that fails the
  script falls back to looking up the registry Uninstall key and invoking
  whatever UninstallString it provides.
#>

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole( `
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[ERROR] Must run as Administrator.' -ForegroundColor Red
    exit 2
}

$targets = @(
    @{ Match = '^7-Zip 22\.01';        Label = '7-Zip 22.01' },
    @{ Match = '^Notepad\+\+ \(64-bit'; Label = 'Notepad++' },
    @{ Match = '^Mozilla Firefox 115'; Label = 'Firefox 115.5.0 ESR' },
    @{ Match = '^WinRAR 6\.10';        Label = 'WinRAR 6.10' }
)

$paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$entries = foreach ($p in $paths) {
    Get-ItemProperty $p -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName }
}

foreach ($t in $targets) {
    $match = $entries | Where-Object { $_.DisplayName -match $t.Match } | Select-Object -First 1
    if (-not $match) {
        Write-Host "[--] $($t.Label) not found" -ForegroundColor DarkGray
        continue
    }
    $uninst = $match.QuietUninstallString
    if (-not $uninst) { $uninst = $match.UninstallString }
    if (-not $uninst) {
        Write-Host "[??] $($t.Label) has no UninstallString" -ForegroundColor Yellow
        continue
    }
    Write-Host "[-] Uninstalling: $($match.DisplayName) ($($match.DisplayVersion))" -ForegroundColor Yellow
    Write-Host "    $uninst" -ForegroundColor DarkGray
    try {
        # Wrap in cmd /c because some uninstall strings have quoted paths.
        Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $uninst, '/S' -Wait -ErrorAction Stop
        Write-Host '    [OK]' -ForegroundColor Green
    } catch {
        Write-Host "    [WARN] Uninstall command failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host 'Reverting to a clean VM snapshot is strongly recommended over silent uninstall.' -ForegroundColor Cyan
