@echo off
REM ================================================================
REM ShieldNet Windows Service Installer (NSSM Wrapper)
REM Run this script as Administrator to install and start the service
REM ================================================================

echo [1/3] Checking Administrator privileges...
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges.
    echo Please right-click this file and select 'Run as administrator'.
    pause
    exit /b 1
)

echo [2/3] Checking NSSM availability...
where nssm >nul 2>&1
if %errorLevel% neq 0 (
    echo [NOTICE] 'nssm' executable not found in PATH.
    echo To register as a native Windows Service surviving logoff, download NSSM:
    echo https://nssm.cc/download
    echo Alternatively, run: python windows_service.py run
    pause
    exit /b 1
)

echo [3/3] Registering ShieldNetDaemon service...
REM --- ShieldNet NSSM Windows Service Registration ---
nssm install ShieldNetDaemon "D:\sih-backend\shieldnet_daemon\.venv\Scripts\python.exe" "D:\sih-backend\shieldnet_daemon\daemon\windows_service.py run"
nssm set ShieldNetDaemon AppDirectory "D:\sih-backend\shieldnet_daemon"
nssm set ShieldNetDaemon DisplayName "ShieldNet Network Detection Daemon"
nssm set ShieldNetDaemon Description "Continuous offline network threat detection and cryptographic ledger"
nssm set ShieldNetDaemon Start SERVICE_AUTO_START
nssm set ShieldNetDaemon AppStdout "D:\sih-backend\shieldnet_daemon\data\service_stdout.log"
nssm set ShieldNetDaemon AppStderr "D:\sih-backend\shieldnet_daemon\data\service_stderr.log"
nssm set ShieldNetDaemon AppRotateFiles 1
nssm set ShieldNetDaemon AppRotateOnline 1
nssm set ShieldNetDaemon AppRotateBytes 5242880
nssm start ShieldNetDaemon

echo [SUCCESS] ShieldNet Windows Service installed and started!
pause
