@echo off
title ShieldNet Sovereign Air-Gapped Launch System
color 0A

echo ===============================================================================
echo                SHIELDNET -- AUTONOMOUS PREDICTIVE CYBER DEFENSE
echo                 Problem Statement SIH26153 (NTRO / NCIIPC)
echo                  100%% Offline Air-Gapped Production Launch
echo ===============================================================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3 is not found in PATH. Please install Python 3.10+ and retry.
    pause
    exit /b 1
)

:: Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not found in PATH. Please install Node.js 18+ and retry.
    pause
    exit /b 1
)

echo [1/3] Starting ShieldNet FastAPI Backend ^& SIERL Blockchain Ledger on Port 8000...
start "ShieldNet Backend Engine" cmd /k "python -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000"

echo [2/3] Starting ShieldNet Modern SOC Dashboard on Port 5173...
start "ShieldNet Frontend Dashboard" cmd /k "cd frontend && npm run dev"

echo [3/3] Waiting for servers to initialize...
timeout /t 3 >nul

echo Opening browser at http://localhost:5173 ...
start http://localhost:5173

echo.
echo ===============================================================================
echo  [READY] ShieldNet is now fully operational!
echo  - Backend API: http://127.0.0.1:8000 (Swagger docs at /docs)
echo  - SecOps Dashboard: http://localhost:5173
echo.
echo  Default SecOps Logins:
echo    admin@shieldnet.local   / Admin@123   (Administrator)
echo    analyst@shieldnet.local / Analyst@123 (SOC Tier-2 Analyst)
echo    auditor@shieldnet.local / Auditor@123 (Forensic Auditor)
echo ===============================================================================
echo.
