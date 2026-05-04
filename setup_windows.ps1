<#
  SentinelView — pip install + import check.
  Requires Python 3.10+ on PATH (py -3, py, or python).

  Usage:  cd ...\SentinelView ; .\setup_windows.ps1
#>

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Runner = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $Runner = "py-3" }
}
if (-not $Runner -and (Get-Command py -ErrorAction SilentlyContinue)) {
    py -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $Runner = "py" }
}
if (-not $Runner -and (Get-Command python -ErrorAction SilentlyContinue)) {
    python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $Runner = "python" }
}

function Run-Py {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    switch ($Runner) {
        "py-3" { & py -3 @Args }
        "py" { & py @Args }
        default { & python @Args }
    }
}

if (-not $Runner) {
    Write-Host "Python 3.10+ not found. Install from https://www.python.org/downloads/ (add to PATH)." -ForegroundColor Yellow
    exit 1
}

Write-Host "Python OK ($Runner). Installing dependencies..." -ForegroundColor Green
Run-Py -m pip install --upgrade pip
Run-Py -m pip install -r "$Root\requirements.txt"

Write-Host "Verifying core modules..." -ForegroundColor Cyan
Run-Py -c "import analysis, audit_evidence_package, client_profile, client_workspace, ingest_engine, event_db, onboarding_policy, onboarding_wizard_state, policy_generator, policy_generation_engine, policy_evidence_bridge, settings_loader, trust_center_ui; print('Core imports OK.')"

$dataDir = Join-Path $Root "ingest_inbox\sentinelview_data"
$settings = Join-Path $Root "settings.yaml"

Write-Host ""
Write-Host "Sample data: $Root\ingest_inbox" -ForegroundColor Green
Write-Host ""
Write-Host "Terminal A (ingestion):" -ForegroundColor Cyan
Write-Host "  Set-Location '$Root'"
switch ($Runner) {
    "py-3" {
        Write-Host "  py -3 ingest_engine.py"
        $dashCmd = "py -3 -m streamlit run dashboard.py"
    }
    "py" {
        Write-Host "  py ingest_engine.py"
        $dashCmd = "py -m streamlit run dashboard.py"
    }
    default {
        Write-Host "  python ingest_engine.py"
        $dashCmd = "python -m streamlit run dashboard.py"
    }
}
Write-Host ""
Write-Host "Terminal B (dashboard):" -ForegroundColor Cyan
Write-Host "  Set-Location '$Root'"
Write-Host "  $dashCmd"
Write-Host ""
Write-Host "Dashboard sidebar:" -ForegroundColor White
Write-Host "  Event data folder  -> $dataDir"
Write-Host "  settings.yaml path -> $settings"
