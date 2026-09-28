# ShieldNet Windows Service Installer (PowerShell)
# Requires Administrator privileges

$ServiceName = "ShieldNetDaemon"
$PythonExe = "D:\sih-backend\shieldnet_daemon\.venv\Scripts\python.exe"
$ScriptPath = "D:\sih-backend\shieldnet_daemon\daemon\windows_service.py"
$ProjectDir = "D:\sih-backend\shieldnet_daemon"
$StdoutLog = "D:\sih-backend\shieldnet_daemon\data\service_stdout.log"
$StderrLog = "D:\sih-backend\shieldnet_daemon\data\service_stderr.log"

Write-Host "[1/2] Verifying NSSM..." -ForegroundColor Cyan
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Warning "NSSM is not installed in PATH. Please install nssm via Chocolatey (choco install nssm) or Scoop (scoop install nssm)."
    exit 1
}

Write-Host "[2/2] Registering $ServiceName with NSSM..." -ForegroundColor Cyan
nssm install $ServiceName $PythonExe "$ScriptPath run"
nssm set $ServiceName AppDirectory $ProjectDir
nssm set $ServiceName DisplayName "ShieldNet Network Detection Daemon"
nssm set $ServiceName Description "Continuous offline network threat detection and cryptographic ledger"
nssm set $ServiceName Start SERVICE_AUTO_START
nssm set $ServiceName AppStdout $StdoutLog
nssm set $ServiceName AppStderr $StderrLog
nssm start $ServiceName

Write-Host "[SUCCESS] $ServiceName registered and started successfully!" -ForegroundColor Green
