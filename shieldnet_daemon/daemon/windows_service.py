"""
ShieldNet Windows Service Wrapper & Process Manager.

Provides CLI commands to run, monitor, stop, and configure the ShieldNet daemon
as a persistent background Windows Service (via NSSM or native subprocess):
- 'run': Launches the daemon headless in the current process.
- 'status': Inspects PID, health heartbeat, memory/CPU usage, and alerts.
- 'stop': Signals the running daemon process to stop cleanly.
- 'install-nssm': Generates NSSM service configuration commands.
- 'generate-scripts': Emits batch (.bat) and PowerShell (.ps1) service scripts.
"""

from pathlib import Path
from typing import Optional, Dict, Any
import argparse
import json
import logging
import os
import signal
import sys
import time
import psutil

# Path resolution
DAEMON_DIR = Path(__file__).resolve().parent
PROJECT_DIR = DAEMON_DIR.parent
PYTHON_EXE = sys.executable

if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from daemon.service import ShieldNetDaemon, DaemonConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [ShieldNet] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("WindowsService")


def get_status_file() -> Path:
    return PROJECT_DIR / "data" / "daemon_status.json"


def check_status() -> Dict[str, Any]:
    """Inspects daemon status from disk and validates PID liveness."""
    status_path = get_status_file()
    if not status_path.exists():
        return {"status": "STOPPED", "message": "No status file found (daemon has not run)."}

    try:
        with open(status_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        return {"status": "UNKNOWN", "message": f"Error reading status file: {exc}"}

    pid = data.get("pid")
    is_alive = False
    if pid and psutil.pid_exists(pid):
        try:
            p = psutil.Process(pid)
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                is_alive = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            is_alive = False

    data["process_alive"] = is_alive
    if not is_alive and data.get("status") == "RUNNING":
        data["status"] = "STALE (Process Died)"

    return data


def print_status():
    """Prints formatted daemon status in terminal."""
    st = check_status()
    print("\n" + "=" * 60)
    print("           SHIELDNET BACKGROUND DAEMON STATUS")
    print("=" * 60)
    print(f" Status:               {st.get('status')}")
    print(f" Process Alive:        {st.get('process_alive')}")
    print(f" PID:                  {st.get('pid')}")
    print(f" Mode:                 {st.get('mode', 'N/A')}")
    print(f" Uptime:               {st.get('uptime_formatted', 'N/A')} ({st.get('uptime_seconds', 0)}s)")
    print(f" Total Packets:        {st.get('total_packets_captured', 0)}")
    print(f" Active Flows:         {st.get('active_flows', 0)}")
    print(f" Total Alerts:         {st.get('total_alerts', 0)}")
    print(f" Memory RSS:           {st.get('memory_rss_mb', 0)} MB")
    print(f" CPU Percent:          {st.get('cpu_percent', 0)}%")
    print(f" Last Heartbeat:       {st.get('last_heartbeat', 'N/A')}")

    last_alert = st.get("last_alert")
    if last_alert:
        print("\n [Latest Security Alert]")
        print(f"   Record ID:          {last_alert.get('record_id')}")
        print(f"   Timestamp:          {last_alert.get('timestamp')}")
        print(f"   Classification:     {last_alert.get('prediction')}")
        print(f"   Threat Probability: {last_alert.get('threat_probability') * 100:.1f}%")
        print(f"   MITRE Tactic:       {last_alert.get('mitre_tactic')} (Stage {last_alert.get('mitre_stage')})")
        print(f"   Primary Driver:     {last_alert.get('top_driver')}")
        print(f"   Record Hash:        {last_alert.get('record_hash')}")
    print("=" * 60 + "\n")


def stop_daemon() -> bool:
    """Terminates the running daemon by sending termination signal to its PID."""
    st = check_status()
    pid = st.get("pid")
    if not pid or not st.get("process_alive"):
        logger.info("Daemon is not currently running.")
        return True

    logger.info("Stopping ShieldNet daemon [PID: %d]...", pid)
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=5.0)
        logger.info("Daemon cleanly terminated.")
        return True
    except psutil.TimeoutExpired:
        logger.warning("Process did not exit cleanly within timeout. Killing...")
        proc.kill()
        return True
    except Exception as exc:
        logger.error("Failed to stop daemon: %s", exc)
        return False


def run_daemon(interface: Optional[str] = None, interval: float = 1.0, mock: bool = False):
    """Starts the daemon service in the current foreground process."""
    logger.info("Starting ShieldNet background detection daemon...")
    config = DaemonConfig(
        interface=interface,
        evaluation_interval=interval,
        mock_mode=mock,
    )
    daemon = ShieldNetDaemon(config)
    daemon.start(block=True)


def generate_nssm_commands() -> str:
    """Generates the exact commands to register ShieldNet with NSSM."""
    service_name = "ShieldNetDaemon"
    script_path = DAEMON_DIR / "windows_service.py"
    data_dir = PROJECT_DIR / "data"
    stdout_log = data_dir / "service_stdout.log"
    stderr_log = data_dir / "service_stderr.log"

    cmds = [
        f'REM --- ShieldNet NSSM Windows Service Registration ---',
        f'nssm install {service_name} "{PYTHON_EXE}" "{script_path} run"',
        f'nssm set {service_name} AppDirectory "{PROJECT_DIR}"',
        f'nssm set {service_name} DisplayName "ShieldNet Network Detection Daemon"',
        f'nssm set {service_name} Description "Continuous offline network threat detection and cryptographic ledger"',
        f'nssm set {service_name} Start SERVICE_AUTO_START',
        f'nssm set {service_name} AppStdout "{stdout_log}"',
        f'nssm set {service_name} AppStderr "{stderr_log}"',
        f'nssm set {service_name} AppRotateFiles 1',
        f'nssm set {service_name} AppRotateOnline 1',
        f'nssm set {service_name} AppRotateBytes 5242880',
        f'nssm start {service_name}',
    ]
    return "\n".join(cmds)


def generate_service_scripts():
    """Generates ready-to-run .bat and .ps1 installer scripts."""
    # 1. Batch installer
    bat_path = DAEMON_DIR / "install_windows_service.bat"
    bat_content = f"""@echo off
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
{generate_nssm_commands()}

echo [SUCCESS] ShieldNet Windows Service installed and started!
pause
"""
    with open(bat_path, "w", encoding="utf-8") as f:
        f.write(bat_content)
    logger.info("Generated batch installer at %s", bat_path)

    # 2. PowerShell installer
    ps1_path = DAEMON_DIR / "install_windows_service.ps1"
    ps1_content = f"""# ShieldNet Windows Service Installer (PowerShell)
# Requires Administrator privileges

$ServiceName = "ShieldNetDaemon"
$PythonExe = "{PYTHON_EXE}"
$ScriptPath = "{DAEMON_DIR / 'windows_service.py'}"
$ProjectDir = "{PROJECT_DIR}"
$StdoutLog = "{PROJECT_DIR / 'data' / 'service_stdout.log'}"
$StderrLog = "{PROJECT_DIR / 'data' / 'service_stderr.log'}"

Write-Host "[1/2] Verifying NSSM..." -ForegroundColor Cyan
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {{
    Write-Warning "NSSM is not installed in PATH. Please install nssm via Chocolatey (choco install nssm) or Scoop (scoop install nssm)."
    exit 1
}}

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
"""
    with open(ps1_path, "w", encoding="utf-8") as f:
        f.write(ps1_content)
    logger.info("Generated PowerShell installer at %s", ps1_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShieldNet Windows Service Manager")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Run command
    run_parser = subparsers.add_parser("run", help="Run daemon in foreground")
    run_parser.add_argument("--interface", type=str, default=None, help="Network interface")
    run_parser.add_argument("--interval", type=float, default=1.0, help="Evaluation interval")
    run_parser.add_argument("--mock", action="store_true", help="Run in mock/injection mode")

    # Status command
    subparsers.add_parser("status", help="Show current daemon status")

    # Stop command
    subparsers.add_parser("stop", help="Stop running daemon")

    # Install NSSM command
    subparsers.add_parser("install-nssm", help="Display NSSM commands")

    # Generate scripts command
    subparsers.add_parser("generate-scripts", help="Generate .bat and .ps1 installer files")

    args = parser.parse_args()

    if args.command == "run":
        run_daemon(interface=args.interface, interval=args.interval, mock=args.mock)
    elif args.command == "status":
        print_status()
    elif args.command == "stop":
        stop_daemon()
    elif args.command == "install-nssm":
        print(generate_nssm_commands())
    elif args.command == "generate-scripts":
        generate_service_scripts()
    else:
        parser.print_help()
