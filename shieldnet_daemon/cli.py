"""
ShieldNet Unified Command-Line Interface.

Entrypoint for standalone PyInstaller binary and package execution:
    shieldnet daemon run [--mock] [--interface IFACE]
    shieldnet daemon status
    shieldnet daemon stop
    shieldnet dashboard [--port 8080] [--host 127.0.0.1] [--open-browser]
    shieldnet simulate [--scenario ddos] [--count 50]
    shieldnet audit [--db-path PATH]
    shieldnet version
"""

from pathlib import Path
import argparse
import json
import sys
import time

# Ensure project root is on sys.path
PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from shared.paths import get_resource_path, get_data_dir
from daemon.service import ShieldNetDaemon, DaemonConfig
from daemon.windows_service import print_status, stop_daemon
from dashboard.app import DashboardServer
from scripts.simulate_traffic import run_simulation
from engine.ledger import ActionLedger

__version__ = "1.0.0"


def cmd_daemon_run(args):
    """Starts the background daemon in blocking or mock mode."""
    data_dir = get_data_dir()
    enable_ipc = getattr(args, "enable_ipc", False)
    ipc_port = getattr(args, "ipc_port", 49152)

    config = DaemonConfig(
        db_path=data_dir / "ledger.db",
        status_path=data_dir / "daemon_status.json",
        model_path=get_resource_path("models/onnx/world_model.onnx"),
        scaler_path=get_resource_path("models/checkpoints/scaler_reference.npz"),
        logreg_path=get_resource_path("models/checkpoints/logreg_params.npz"),
        interface=args.interface,
        mock_mode=args.mock,
        enable_ipc=enable_ipc,
        ipc_port=ipc_port,
    )

    print(f"\n============================================================")
    print(f"      SHIELDNET AUTONOMOUS BACKGROUND THREAT DAEMON")
    print(f"============================================================")
    print(f" Mode:            {'MOCK_INJECTION' if args.mock else 'LIVE_SNIFFING'}")
    print(f" IPC Bridge:      {'ENABLED (127.0.0.1:' + str(ipc_port) + ') [DEMO MODE]' if enable_ipc else 'DISABLED (Production Hardened)'}")
    print(f" Interface:       {args.interface or 'DEFAULT'}")
    print(f" Ledger DB:       {config.db_path}")
    print(f" Status Path:     {config.status_path}")
    print(f" Model ONNX:      {config.model_path}")
    print(f" Press Ctrl+C to initiate graceful shutdown.")
    print(f"============================================================\n")

    daemon = ShieldNetDaemon(config=config)
    daemon.start(block=True)


def cmd_daemon_status(args):
    """Prints live daemon telemetry."""
    print_status()


def cmd_daemon_stop(args):
    """Stops the running daemon process."""
    if stop_daemon():
        print("[ShieldNet] Daemon stopped successfully.")
    else:
        print("[ShieldNet] Could not stop daemon.")


def cmd_dashboard(args):
    """Launches the decoupled monitoring dashboard."""
    data_dir = get_data_dir()
    db_path = Path(args.db_path) if args.db_path else data_dir / "ledger.db"
    status_path = Path(args.status_path) if args.status_path else data_dir / "daemon_status.json"

    server = DashboardServer(
        host=args.host,
        port=args.port,
        db_path=db_path,
        status_path=status_path,
    )

    if args.open_browser:
        import threading
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{args.host}:{args.port}")).start()

    print(f"\n============================================================")
    print(f"      SHIELDNET DECOUPLED CYBERSECURITY DASHBOARD")
    print(f"============================================================")
    print(f" URL:             http://{args.host}:{args.port}")
    print(f" Ledger Path:     {db_path}")
    print(f" Status Path:     {status_path}")
    print(f" Mode:            READ-ONLY WAL (Zero Lock Contention)")
    print(f" Press Ctrl+C to stop the dashboard server.")
    print(f"============================================================\n")

    server.start(block=True)


def cmd_simulate(args):
    """Executes attack traffic simulation."""
    run_simulation(scenario=args.scenario, target_daemon=args.target_daemon, count=args.count)


def cmd_audit(args):
    """Executes on-demand cryptographic verification of the Action Ledger."""
    data_dir = get_data_dir()
    db_path = Path(args.db_path) if args.db_path else data_dir / "ledger.db"

    if not db_path.exists():
        print(f"\n[Audit] Ledger database not found at {db_path}.\n")
        return

    ledger = ActionLedger(db_path)
    is_valid, verified_cnt, error = ledger.verify_integrity()
    latest = ledger.get_latest_record()

    print(f"\n============================================================")
    print(f"      SHIELDNET CRYPTOGRAPHIC ACTION LEDGER AUDIT")
    print(f"============================================================")
    print(f" Database:             {db_path}")
    print(f" Total Blocks:         {ledger.count_records():,}")
    print(f" Verified Blocks:      {verified_cnt:,}")
    print(f" Genesis Anchor:       {'0' * 64}")
    print(f" Latest Tip Hash:      {latest.record_hash if latest else 'None'}")
    print(f" Chain Status:         {'[VERIFIED INTACT]' if is_valid else '[TAMPERED / CORRUPTED]'}")
    if error:
        print(f" Error Details:        {error}")
    print(f"============================================================\n")


def cmd_version(args):
    """Prints version and offline compliance status."""
    print(f"ShieldNet Offline Detection Engine v{__version__} [Air-Gap Compliant]")


def build_parser() -> argparse.ArgumentParser:
    """Builds the unified CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="shieldnet",
        description="ShieldNet: Autonomous Offline Network Threat Detection & Cryptographic Action Ledger",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # daemon subcommand
    p_daemon = subparsers.add_parser("daemon", help="Manage background detection daemon")
    daemon_subs = p_daemon.add_subparsers(dest="daemon_action", help="Daemon action")
    
    p_d_run = daemon_subs.add_parser("run", help="Run background daemon")
    p_d_run.add_argument("--mock", action="store_true", help="Bypass live network sniffing")
    p_d_run.add_argument("--interface", type=str, default=None, help="Capture interface name")
    p_d_run.add_argument("--enable-ipc", action="store_true", help="Enable localhost IPC bridge for simulation (demo mode only)")
    p_d_run.add_argument("--ipc-port", type=int, default=49152, help="Port for localhost IPC bridge (default: 49152)")
    
    daemon_subs.add_parser("status", help="Query live daemon telemetry")
    daemon_subs.add_parser("stop", help="Gracefully terminate daemon")

    # dashboard subcommand
    p_dash = subparsers.add_parser("dashboard", help="Launch decoupled monitoring dashboard")
    p_dash.add_argument("--host", default="127.0.0.1", help="Binding host IP (default: 127.0.0.1)")
    p_dash.add_argument("--port", type=int, default=8080, help="Binding TCP port (default: 8080)")
    p_dash.add_argument("--db-path", type=str, default=None, help="Custom path to ledger.db")
    p_dash.add_argument("--status-path", type=str, default=None, help="Custom path to daemon_status.json")
    p_dash.add_argument("--open-browser", action="store_true", help="Open dashboard in browser on start")

    # simulate subcommand
    p_sim = subparsers.add_parser("simulate", help="Generate synthetic attack traffic")
    p_sim.add_argument("--scenario", choices=["benign", "portscan", "ddos", "bot", "all"], default="portscan")
    p_sim.add_argument("--count", type=int, default=40, help="Number of packets to simulate")
    p_sim.add_argument("--target-daemon", action="store_true", help="Target running daemon")

    # audit subcommand
    p_audit = subparsers.add_parser("audit", help="Verify cryptographic hash-chain integrity")
    p_audit.add_argument("--db-path", type=str, default=None, help="Custom path to ledger.db")

    # version subcommand
    subparsers.add_parser("version", help="Display version and build info")

    return parser


def main():
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "daemon":
        if args.daemon_action == "run":
            cmd_daemon_run(args)
        elif args.daemon_action == "status":
            cmd_daemon_status(args)
        elif args.daemon_action == "stop":
            cmd_daemon_stop(args)
        else:
            parser.parse_args(["daemon", "--help"])
    elif args.command == "dashboard":
        cmd_dashboard(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "version":
        cmd_version(args)


if __name__ == "__main__":
    main()
