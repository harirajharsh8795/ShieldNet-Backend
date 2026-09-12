#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PATH="$PROJECT_ROOT/.shieldnet-venv"
PYTHON="$VENV_PATH/bin/python"

echo "Installing ShieldNet desktop runtime..."
if [[ ! -x "$PYTHON" ]]; then
  python3 -m venv "$VENV_PATH"
fi

"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -r "$PROJECT_ROOT/requirements.txt"
"$PYTHON" -m pip install -r "$PROJECT_ROOT/desktop/requirements.txt"

echo "Starting ShieldNet. The browser will open on the local dashboard."
exec "$PYTHON" "$PROJECT_ROOT/desktop/launcher.py"