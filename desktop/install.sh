#!/usr/bin/env bash
# ShieldNet Sovereign Desktop Agent & Defense Runtime One-Line Installer (Linux/macOS)
# Run via: curl -fsSL https://raw.githubusercontent.com/harirajharsh8795/ShieldNet-Backend/main/desktop/install.sh | bash

set -e

echo -e "\033[1;36m==========================================================================\033[0m"
echo -e "\033[1;36m     SHIELDNET SOVEREIGN DEFENSE AGENT · ONE-LINE UNIX INSTALLER         \033[0m"
echo -e "\033[0;90m      National Technical Research Organisation (NTRO) · SIH 26153        \033[0m"
echo -e "\033[1;36m==========================================================================\033[0m"

TARGET_DIR="${HOME}/ShieldNet"

if [ ! -d "$TARGET_DIR" ]; then
    echo -e "\033[1;33m[1/4] Cloning ShieldNet Repository from GitHub...\033[0m"
    git clone https://github.com/harirajharsh8795/ShieldNet-Backend.git "$TARGET_DIR"
else
    echo -e "\033[1;32m[1/4] Existing ShieldNet installation detected at $TARGET_DIR\033[0m"
fi

cd "$TARGET_DIR"

echo -e "\033[1;33m[2/4] Setting up Python virtual environment...\033[0m"
if [ ! -d ".shieldnet-venv" ]; then
    python3 -m venv .shieldnet-venv
fi

source .shieldnet-venv/bin/activate

echo -e "\033[1;33m[3/4] Installing dependencies...\033[0m"
pip install -q --upgrade pip
pip install -q -r requirements.txt
pip install -q -r desktop/requirements.txt

echo -e "\033[1;32m[4/4] ShieldNet Defense Agent is ready!\033[0m"
echo -e "--------------------------------------------------------------------------"
echo -e "  🛡️  AIR-GAP LOCAL DEFENSE: http://127.0.0.1:8000"
echo -e "  🖥️  REACT SOC DASHBOARD:   http://localhost:5173"
echo -e "  📊  STREAMLIT ANALYTICS:   http://127.0.0.1:8501"
echo -e "  🌐  CLOUD FLAGSHIP SOC:    https://shieldnet-sih.vercel.app/"
echo -e "--------------------------------------------------------------------------"

python3 desktop/desktop_agent.py