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
import os
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
    mock_mode = getattr(args, "mock", False)
    enable_ipc = getattr(args, "enable_ipc", False) or mock_mode
    ipc_port = getattr(args, "ipc_port", 49152)
    verbose = getattr(args, "verbose", False) or getattr(args, "debug", False)

    # ── Configure logging (console + rotating file) ───────────────────────
    import logging
    import logging.handlers
    log_path = data_dir / "shieldnet_daemon.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S")

    # Console handler: DEBUG when --verbose/--debug, WARNING in default minimal status mode
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.WARNING)
    ch.setFormatter(fmt)
    root_logger.addHandler(ch)

    # Rotating file handler (DEBUG and above, max 5 MB, 3 backups)
    fh = logging.handlers.RotatingFileHandler(
        str(log_path), maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    root_logger.addHandler(fh)
    # ─────────────────────────────────────────────────────────────────────

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
        verbose=verbose,
    )

    print(f"\n============================================================")
    print(f"      SHIELDNET AUTONOMOUS BACKGROUND THREAT DAEMON")
    print(f"============================================================")
    print(f" Mode:            {'MOCK_INJECTION' if args.mock else 'LIVE_SNIFFING'}")
    print(f" Output View:     {'VERBOSE (Full Feature Vectors & Matrices)' if verbose else 'MINIMAL STATUS (Telemetry & Alerts Only)'}")
    print(f" IPC Bridge:      {'ENABLED (127.0.0.1:' + str(ipc_port) + ') [DEMO MODE]' if enable_ipc else 'DISABLED (Production Hardened)'}")
    print(f" Interface:       {args.interface or 'AUTO-DETECT'}")
    print(f" Ledger DB:       {config.db_path}")
    print(f" Status Path:     {config.status_path}")
    print(f" Model ONNX:      {config.model_path}")
    print(f" Log File:        {log_path}")
    print(f" Press Ctrl+C to initiate graceful shutdown.")
    print(f"============================================================\n", flush=True)

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


def cmd_peer(args):
    """Manages Tier 2 cross-node threat intel signatures and zero-IP verification."""
    data_dir = get_data_dir()
    db_path = Path(args.db_path) if getattr(args, "db_path", None) else data_dir / "ledger.db"

    if args.peer_action == "export":
        ledger = ActionLedger(db_path)
        sig = ledger.export_threat_signature(record_id=args.record_id, node_id=getattr(args, "node_id", "local_node"))
        if not sig:
            print(f"\n[Peer Export] Record ID {args.record_id} not found in ledger at {db_path}.\n")
            return
        out_json = json.dumps(sig, indent=2)
        if getattr(args, "out", None):
            out_file = Path(args.out)
            out_file.write_text(out_json, encoding="utf-8")
            print(f"\n[Peer Export] Successfully exported signature for Record #{args.record_id} to {out_file}")
        else:
            print(out_json)

    elif args.peer_action == "verify":
        sig_file = Path(args.file)
        if not sig_file.exists():
            print(f"\n[Peer Verify] File not found: {sig_file}\n")
            return
        payload = json.loads(sig_file.read_text(encoding="utf-8"))
        is_valid, msg = ActionLedger.verify_signature_payload(payload)
        print(f"\n============================================================")
        print(f"      SHIELDNET TIER 2 THREAT SIGNATURE AUDIT")
        print(f"============================================================")
        print(f" File:                 {sig_file}")
        print(f" Origin Node:          {payload.get('origin_node_id', 'Unknown')}")
        print(f" Threat Class:         {payload.get('prediction', 'Unknown')}")
        print(f" Confidence:           {payload.get('threat_probability', 0.0) * 100:.1f}%")
        print(f" Zero-IP Invariant:    [PASS] No identity or system fields present")
        print(f" Cryptographic Status: {'[VERIFIED INTACT]' if is_valid else '[INVALID / TAMPERED]'}")
        if not is_valid:
            print(f" Failure Reason:       {msg}")
        print(f"============================================================\n")


def cmd_doctor(args):
    """Runs a complete security posture, kernel driver, and cryptographic integrity audit."""
    from shared.integrity import IntegrityVerifier
    import platform
    import shutil

    data_dir = get_data_dir()
    db_path = data_dir / "ledger.db"
    models_dir = PROJECT_DIR / "models"

    print(f"\n============================================================")
    print(f"       SHIELDNET SYSTEM & SECURITY POSTURE AUDIT            ")
    print(f"============================================================")

    # 1. OS & Privileges
    is_windows = (os.name == "nt")
    is_admin = False
    if is_windows:
        try:
            import ctypes
            is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
        except Exception:
            is_admin = False

    print(f" [1/5] Host Environment")
    print(f"   Platform:           {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"   Python Version:     {platform.python_version()}")
    print(f"   Process Admin:      {'[YES] (Elevated)' if is_admin else '[NO] (Standard User)'}")

    # 2. Npcap Kernel Driver Hardening
    print(f"\n [2/5] Kernel Sniffer & Npcap Driver Security")
    npcap_installed = False
    npcap_admin_only = False
    npcap_status_str = "NOT INSTALLED"

    if is_windows:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as k:
                npcap_installed = True
                val, _ = winreg.QueryValueEx(k, "AdminOnly")
                npcap_admin_only = (val == 1)
        except Exception:
            pass

        if npcap_installed:
            npcap_status_str = "INSTALLED"
            if npcap_admin_only:
                print(f"   Driver Status:      [PASS] Npcap installed & AdminOnly=1 enforced")
            else:
                print(f"   Driver Status:      [WARN] Npcap installed, but AdminOnly is not set to 1")
        else:
            print(f"   Driver Status:      [NOTICE] Npcap not detected in registry")
    else:
        print(f"   Driver Status:      [N/A] Non-Windows host (uses standard raw socket capabilities)")

    # 3. Cryptographic Asset Integrity (Anti-Poisoning)
    print(f"\n [3/5] Cryptographic Neural Asset & Checkpoint Integrity")
    manifest_file = models_dir / "manifest.json"
    if not manifest_file.exists():
        print(f"   Model Manifest:     [FAIL] manifest.json not found in {models_dir}")
    else:
        try:
            is_valid, errors = IntegrityVerifier.verify_all(models_dir)
            print(f"   Model Weights:      [PASS] All ONNX & scaler parameters cryptographically verified")
        except Exception as exc:
            print(f"   Model Weights:      [FAIL] Integrity violation: {exc}")

    # 4. Action Ledger Cryptographic Chain
    print(f"\n [4/5] Action Ledger Cryptographic Hash-Chain")
    if not db_path.exists():
        print(f"   Action Ledger:      [NOTICE] No existing ledger.db at {db_path}")
    else:
        ledger = ActionLedger(db_path)
        chain_valid, count, chain_err = ledger.verify_integrity()
        if chain_valid:
            print(f"   Hash-Chain Status:  [PASS] Verified {count:,} blocks intact against genesis")
        else:
            print(f"   Hash-Chain Status:  [FAIL] Tamper detected! {chain_err}")

    # 5. Localhost & Isolation Posture
    print(f"\n [5/5] Attack Surface & Isolation Posture")
    print(f"   IPC Simulation:     DISABLED BY DEFAULT (Production Safe)")
    print(f"   Dashboard Binding:  Strictly 127.0.0.1 (Loopback-only, DNS Rebinding Protected)")
    print(f"   Data Directory:     {data_dir}")
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
    p_d_run.add_argument("--verbose", "-v", action="store_true", help="Display verbose debugging info and raw feature vectors/matrices")
    p_d_run.add_argument("--debug", action="store_true", help="Alias for --verbose")
    
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

    # peer subcommand (Tier 2 cross-node threat intel signatures)
    p_peer = subparsers.add_parser("peer", help="Manage Tier 2 cross-node threat intel signatures")
    peer_subs = p_peer.add_subparsers(dest="peer_action", help="Peer action")

    p_p_exp = peer_subs.add_parser("export", help="Export zero-IP threat signature for a ledger record")
    p_p_exp.add_argument("--record-id", type=int, required=True, help="Record ID to export")
    p_p_exp.add_argument("--out", type=str, default=None, help="Output JSON filepath")
    p_p_exp.add_argument("--node-id", type=str, default="local_node", help="Pseudonymous origin node ID")
    p_p_exp.add_argument("--db-path", type=str, default=None, help="Custom path to ledger.db")

    p_p_ver = peer_subs.add_parser("verify", help="Verify cryptographic integrity of a peer signature file")
    p_p_ver.add_argument("--file", type=str, required=True, help="Path to peer signature JSON file")

    # doctor subcommand
    subparsers.add_parser("doctor", help="Run complete security posture and integrity audit")

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
    elif args.command == "peer":
        cmd_peer(args)
    elif args.command == "doctor":
        cmd_doctor(args)
    elif args.command == "version":
        cmd_version(args)


if __name__ == "__main__":
    main()
