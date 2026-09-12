"""Start the local ShieldNet API and offline dashboard."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen


PROJECT_ROOT = Path(__file__).resolve().parent.parent
API_HOST = "127.0.0.1"
API_PORT = 8000
DASHBOARD_PORT = 8501


def _python_module_command(module: str, *args: str) -> list[str]:
    return [sys.executable, "-m", module, *args]


def _wait_for_api(timeout_seconds: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    health_url = f"http://{API_HOST}:{API_PORT}/api/health"
    while time.monotonic() < deadline:
        try:
            with urlopen(health_url, timeout=2) as response:
                return response.status == 200
        except (OSError, URLError):
            time.sleep(0.5)
    return False


def _start_process(command: list[str]) -> subprocess.Popen:
    return subprocess.Popen(command, cwd=PROJECT_ROOT, env=os.environ.copy())


def main() -> int:
    parser = argparse.ArgumentParser(description="Start ShieldNet locally.")
    parser.add_argument("--api-only", action="store_true", help="Start only the FastAPI control plane.")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser window.")
    args = parser.parse_args()

    api_process = _start_process(
        _python_module_command(
            "uvicorn",
            "src.api.server:app",
            "--host",
            API_HOST,
            "--port",
            str(API_PORT),
        )
    )
    dashboard_process: subprocess.Popen | None = None

    try:
        if not _wait_for_api():
            print("ShieldNet API did not become healthy within 60 seconds.", file=sys.stderr)
            return 1

        print(f"ShieldNet API: http://{API_HOST}:{API_PORT}/docs")
        print("Runtime mode: SIMULATION/REPLAY only; no host firewall rules are applied.")

        if not args.api_only:
            dashboard_process = _start_process(
                _python_module_command(
                    "streamlit",
                    "run",
                    "src/dashboard/app.py",
                    "--server.address",
                    API_HOST,
                    "--server.port",
                    str(DASHBOARD_PORT),
                    "--server.headless",
                    "true",
                )
            )
            print(f"ShieldNet dashboard: http://{API_HOST}:{DASHBOARD_PORT}")

        if not args.no_browser:
            webbrowser.open(
                f"http://{API_HOST}:{API_PORT}/docs" if args.api_only
                else f"http://{API_HOST}:{DASHBOARD_PORT}"
            )

        print("Press Ctrl+C to stop ShieldNet.")
        while api_process.poll() is None:
            if dashboard_process is not None and dashboard_process.poll() is not None:
                print("ShieldNet dashboard stopped; API remains available.", file=sys.stderr)
                dashboard_process = None
            time.sleep(1)
        return api_process.returncode or 0
    except KeyboardInterrupt:
        return 0
    finally:
        for process in (dashboard_process, api_process):
            if process is not None and process.poll() is None:
                process.terminate()
        for process in (dashboard_process, api_process):
            if process is not None and process.poll() is None:
                process.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())