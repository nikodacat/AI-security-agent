# HomeSecAI - First-time setup
# Creates a virtual environment and installs dependencies.
# Usage: .\setup.ps1

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
Set-Location $projectRoot

Write-Host "Creating virtual environment..." -ForegroundColor Cyan
python -m venv .venv

Write-Host "Activating and installing dependencies..." -ForegroundColor Cyan
& ".venv\Scripts\Activate.ps1"
pip install --upgrade pip
pip install -r requirements.txt

Write-Host ""
Write-Host "Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Install Claude Code (if you haven't already):"
Write-Host "       https://docs.claude.com/en/docs/claude-code"
Write-Host "     Then run 'claude' once and sign in with your Claude subscription."
Write-Host "  2. Web dashboard:     .\run_web.ps1"
Write-Host "  3. CLI scan:          .\run_cli.ps1"
Write-Host ""
Write-Host "No ANTHROPIC_API_KEY needed - analysis runs through the local claude CLI." -ForegroundColor Green
