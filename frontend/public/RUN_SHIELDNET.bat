@echo off
title ShieldNet // Sovereign AI World Model Defense Center
color 0B

echo.
echo ==========================================================================
echo        SHIELDNET SOVEREIGN DEFENSE AGENT - 1-CLICK LAUNCHER
echo      National Technical Research Organisation (NTRO) - SIH 26153
echo ==========================================================================
echo.

set "ROOT_DIR=%~dp0"
if exist "%ROOT_DIR%ShieldNet\shieldnet_daemon\cli.py" (
    set "PROJECT_DIR=%ROOT_DIR%ShieldNet"
) else if exist "%ROOT_DIR%shieldnet_daemon\cli.py" (
    set "PROJECT_DIR=%ROOT_DIR%"
) else (
    echo [ERROR] ShieldNet directory not found!
    pause
    exit /b 1
)

cd /d "%PROJECT_DIR%"

rem Determine Python executable
if exist "%PROJECT_DIR%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%\venv\Scripts\python.exe"
) else if exist "%PROJECT_DIR%\shieldnet_daemon\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%\shieldnet_daemon\.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo [*] Using Python: %PYTHON_EXE%
echo [*] Launching Decoupled Dashboard at http://127.0.0.1:8080 ...

start "" %PYTHON_EXE% "%PROJECT_DIR%\shieldnet_daemon\cli.py" dashboard --port 8080 --open-browser

echo.
echo ==========================================================================
echo   [1] Local Dashboard URL:      http://127.0.0.1:8080
echo   [2] Live Vercel Cloud Center: https://shieldnet-sih.vercel.app/
echo   [3] Air-Gap Status:           100%% OFFLINE (ZERO CLOUD EGRESS)
echo   [4] Official BSA Certificate: OFFICIAL_SECTION_63_BSA_CERTIFICATE.html
echo ==========================================================================
echo.
echo Options:
echo   [V] Open Live Vercel Cloud Defense Center in Browser
echo   [S] Inject Simulated Attack Traffic (PortScan / DDoS)
echo   [A] Run Cryptographic Hash-Chain Ledger Audit
echo   [C] Open Official Section 63 BSA Legal Certificate
echo   [Q] Quit Launcher
echo.

:MENU
set /p choice="Select an action [V/S/A/C/Q]: "
if /i "%choice%"=="V" goto VERCEL
if /i "%choice%"=="S" goto SIMULATE
if /i "%choice%"=="A" goto AUDIT
if /i "%choice%"=="C" goto CERT
if /i "%choice%"=="Q" goto EXIT
goto MENU

:VERCEL
echo [*] Opening Live Vercel Cloud Defense Center (https://shieldnet-sih.vercel.app/)...
start "" "https://shieldnet-sih.vercel.app/"
echo.
goto MENU

:SIMULATE
echo [*] Injecting 20 PortScan packets into World Model...
%PYTHON_EXE% "%PROJECT_DIR%\shieldnet_daemon\cli.py" simulate --scenario portscan --count 20
echo [*] Refresh your browser at http://127.0.0.1:8080 to see the new alert!
echo.
goto MENU

:AUDIT
echo [*] Running SHA-256 Merkle Chain Integrity Audit...
%PYTHON_EXE% "%PROJECT_DIR%\shieldnet_daemon\cli.py" audit
echo.
goto MENU

:CERT
echo [*] Opening Official Section 63 BSA Forensic Certificate in Browser...
if exist "%ROOT_DIR%OFFICIAL_SECTION_63_BSA_CERTIFICATE.html" (
    start "" "%ROOT_DIR%OFFICIAL_SECTION_63_BSA_CERTIFICATE.html"
) else if exist "%PROJECT_DIR%\docs\OFFICIAL_SECTION_63_BSA_CERTIFICATE.html" (
    start "" "%PROJECT_DIR%\docs\OFFICIAL_SECTION_63_BSA_CERTIFICATE.html"
)
echo.
goto MENU

:EXIT
echo Exiting ShieldNet launcher.
exit /b 0
