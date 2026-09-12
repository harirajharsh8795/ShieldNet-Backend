#!/usr/bin/env bash
# ShieldNet Sovereign Air-Gapped Launch System for Linux/macOS
# Problem Statement SIH26153 (NTRO / NCIIPC)

set -e

echo "==============================================================================="
echo "               SHIELDNET -- AUTONOMOUS PREDICTIVE CYBER DEFENSE"
echo "                Problem Statement SIH26153 (NTRO / NCIIPC)"
echo "                 100% Offline Air-Gapped Production Launch"
echo "==============================================================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 could not be found. Please install Python 3.10+."
    exit 1
fi

# Check Node
if ! command -v node &> /dev/null; then
    echo "[ERROR] node could not be found. Please install Node.js 18+."
    exit 1
fi

echo "[1/3] Starting ShieldNet FastAPI Backend on Port 8000..."
python3 -m uvicorn src.api.server:app --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

echo "[2/3] Starting ShieldNet Modern SOC Dashboard on Port 5173..."
(cd frontend && npm run dev) &
FRONTEND_PID=$!

echo "[3/3] System initializing..."
sleep 3

echo ""
echo "==============================================================================="
echo " [READY] ShieldNet is now operational!"
echo " - Backend API: http://127.0.0.1:8000 (Swagger docs at /docs)"
echo " - SecOps Dashboard: http://localhost:5173"
echo ""
echo " Default SecOps Logins:"
echo "   admin@shieldnet.local   / Admin@123   (Administrator)"
echo "   analyst@shieldnet.local / Analyst@123 (SOC Tier-2 Analyst)"
echo "   auditor@shieldnet.local / Auditor@123 (Forensic Auditor)"
echo "==============================================================================="
echo "Press Ctrl+C to terminate both servers."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT
wait
