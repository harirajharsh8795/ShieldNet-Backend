$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPath = Join-Path $ProjectRoot ".shieldnet-venv"
$Python = Join-Path $VenvPath "Scripts\python.exe"

Write-Host "Installing ShieldNet desktop runtime..."
if (-not (Test-Path $Python)) {
    python -m venv $VenvPath
}

& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $ProjectRoot "requirements.txt")
& $Python -m pip install -r (Join-Path $PSScriptRoot "requirements.txt")

Write-Host "Starting ShieldNet. The browser will open on the local dashboard."
& $Python (Join-Path $PSScriptRoot "launcher.py")