<#
.SYNOPSIS
ShieldNet Sovereign Desktop Agent & Defense Runtime One-Line Installer (Ollama-style)
Runs seamlessly via:
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/harirajharsh8795/ShieldNet-Backend/main/desktop/install.ps1 | iex"
#>

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "     SHIELDNET SOVEREIGN DEFENSE AGENT · OLLAMA-STYLE ONE-LINE INSTALLER   " -ForegroundColor Cyan
Write-Host "      National Technical Research Organisation (NTRO) · SIH 26153        " -ForegroundColor DarkGray
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

# Determine target directory
$TargetDir = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { Join-Path $HOME "ShieldNet" }

Write-Host "[1/4] Checking ShieldNet Runtime at: $TargetDir" -ForegroundColor Yellow

if (-not (Test-Path $TargetDir)) {
    Write-Host "Cloning official ShieldNet Sovereign Defense Repository from GitHub..." -ForegroundColor Green
    git clone https://github.com/harirajharsh8795/ShieldNet-Backend.git $TargetDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Git clone failed. Downloading lightweight release archive..." -ForegroundColor Yellow
        $ZipPath = Join-Path $HOME "shieldnet_release.zip"
        Invoke-WebRequest -Uri "https://github.com/harirajharsh8795/ShieldNet-Backend/archive/refs/heads/main.zip" -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath $HOME -Force
        Rename-Item -Path (Join-Path $HOME "ShieldNet-Backend-main") -NewName "ShieldNet" -Force
        Remove-Item $ZipPath -Force
    }
} else {
    Write-Host "Existing ShieldNet installation detected. Verifying offline assets..." -ForegroundColor Green
}

Set-Location $TargetDir

Write-Host "[2/4] Verifying Python Environment..." -ForegroundColor Yellow
$PythonCmd = Get-Command python -ErrorAction SilentlyContinue

if (-not $PythonCmd) {
    Write-Host "Python not found in PATH! Please install Python 3.10+ from python.org" -ForegroundColor Red
    exit 1
}

# Check or create virtualenv
$VenvPath = Join-Path $TargetDir ".shieldnet-venv"
$PythonExe = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    Write-Host "Creating dedicated virtual environment..." -ForegroundColor DarkGray
    python -m venv $VenvPath
}

if (Test-Path $PythonExe) {
    $RunPython = $PythonExe
} else {
    $RunPython = "python"
}

Write-Host "[3/4] Installing Required Neural & Defense Dependencies..." -ForegroundColor Yellow
& $RunPython -m pip install -q --upgrade pip
& $RunPython -m pip install -q -r (Join-Path $TargetDir "requirements.txt")
& $RunPython -m pip install -q -r (Join-Path $TargetDir "desktop\requirements.txt")

Write-Host "[4/4] Installation Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  🛡️  AIR-GAP LOCAL DEFENSE: http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host "  🖥️  REACT SOC DASHBOARD:   http://localhost:5173" -ForegroundColor Cyan
Write-Host "  📊  STREAMLIT ANALYTICS:   http://127.0.0.1:8501" -ForegroundColor Cyan
Write-Host "  🌐  CLOUD FLAGSHIP SOC:    https://shieldnet-sih.vercel.app/" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

$Prompt = Read-Host "Launch ShieldNet Desktop Defense Agent Now? [Y/n]"
if ($Prompt -ne 'n' -and $Prompt -ne 'N') {
    Write-Host "Starting Sovereign Defense Agent GUI..." -ForegroundColor Green
    & $RunPython (Join-Path $TargetDir "desktop\desktop_agent.py")
}