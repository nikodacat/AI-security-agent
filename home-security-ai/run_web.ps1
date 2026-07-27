# HomeSecAI - Launch web dashboard
# Usage: .\run_web.ps1

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot

Set-Location $projectRoot

# Verify the Claude CLI (Claude Code) is installed and reachable.
# Two ways the CLI can be located, in priority order:
#   1. CLAUDE_CLI_PATH env var pointing to claude.exe / claude.cmd
#   2. `claude` on PATH
$claudeCmd = Get-Command claude -ErrorAction SilentlyContinue
$claudeEnv = $env:CLAUDE_CLI_PATH
$claudeEnvOk = $claudeEnv -and (Test-Path $claudeEnv)

if (-not $claudeCmd -and -not $claudeEnvOk) {
    Write-Host "[ERROR] Claude CLI not found." -ForegroundColor Red
    if ($claudeEnv) {
        Write-Host "  CLAUDE_CLI_PATH = $claudeEnv (file does not exist)" -ForegroundColor DarkGray
    } else {
        Write-Host "  CLAUDE_CLI_PATH is not set" -ForegroundColor DarkGray
    }
    Write-Host "  'claude' is not on PATH either" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Install Claude Code: https://docs.claude.com/en/docs/claude-code" -ForegroundColor Yellow
    Write-Host "Either add it to PATH or set CLAUDE_CLI_PATH:" -ForegroundColor Yellow
    Write-Host "  [System.Environment]::SetEnvironmentVariable('CLAUDE_CLI_PATH','C:\path\to\claude.exe','User')" -ForegroundColor Cyan
    Write-Host "Then run 'claude' once to sign in." -ForegroundColor Yellow
    exit 1
}

if ($claudeEnvOk) {
    Write-Host "Using Claude CLI from CLAUDE_CLI_PATH: $claudeEnv" -ForegroundColor DarkGray
} else {
    Write-Host "Using Claude CLI from PATH: $($claudeCmd.Source)" -ForegroundColor DarkGray
}


# Activate venv if present
$venv = Join-Path $projectRoot ".venv\Scripts\Activate.ps1"
if (Test-Path $venv) { & $venv }

Write-Host ""
Write-Host "  HomeSecAI Web Dashboard" -ForegroundColor Cyan
Write-Host "  Open: http://localhost:8000" -ForegroundColor Green
Write-Host "  Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host ""

python -m uvicorn frontend.app:app --host 0.0.0.0 --port 8000 --reload
