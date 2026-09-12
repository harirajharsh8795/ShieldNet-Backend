"""
ShieldNet Decoupled Dashboard Application Server.

Module 7 of ShieldNet Tech Stack:
- Standalone multi-threaded HTTP server monitoring the ShieldNet daemon.
- Zero-dependency, 100% offline air-gap safe (uses Python standard library http.server).
- Concurrency-safe: reads SQLite Action Ledger via read-only WAL mode with zero write contention.
- Independent process: runs completely decoupled without holding in-memory references to daemon.
- Interactive endpoints:
    - GET /                      : High-aesthetic dark-mode SPA dashboard UI
    - GET /api/status            : Daemon liveness, PID, memory, packet count, alert metrics
    - GET /api/ledger            : Paginated threat records from tamper-evident ledger
    - GET /api/ledger/record/<id>: Full event inspection with top SHAP feature drivers
    - GET /api/ledger/verify     : On-demand cryptographic hash-chain audit
    - GET /api/stats             : Aggregated attack classifications and MITRE statistics
"""

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs
import argparse
import json
import logging
import os
import sqlite3
import sys
import threading
import time
import webbrowser
import psutil

# Ensure project root is on sys.path
DASHBOARD_DIR = Path(__file__).resolve().parent
PROJECT_DIR = DASHBOARD_DIR.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from shared.schema import CANONICAL_84_FEATURES
from engine.ledger import ActionLedger, LedgerRecord

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("ShieldNetDashboard")


class ShieldNetDashboardHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler serving the decoupled ShieldNet monitoring dashboard
    and RESTful telemetry APIs.
    """

    # Class-level configuration injected by DashboardServer
    db_path: Path = PROJECT_DIR / "data" / "ledger.db"
    status_path: Path = PROJECT_DIR / "data" / "daemon_status.json"
    template_path: Path = DASHBOARD_DIR / "templates" / "index.html"

    def log_message(self, format: str, *args: Any) -> None:
        """Override to suppress excessive access logs; errors still logged."""
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)

    def _send_json(self, data: Any, status_code: int = 200):
        """Sends a JSON response with proper headers."""
        try:
            body = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_html(self, html_content: str, status_code: int = 200):
        """Sends an HTML response."""
        body = html_content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message: str, status_code: int = 400):
        """Sends a standardized JSON error message."""
        self._send_json({"error": message, "status": status_code}, status_code=status_code)

    def do_GET(self):
        """Dispatches incoming GET requests to appropriate handlers."""
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self.handle_index()
        elif path == "/api/status":
            self.handle_api_status()
        elif path == "/api/ledger":
            self.handle_api_ledger(query)
        elif path.startswith("/api/ledger/record/"):
            record_id_str = path[len("/api/ledger/record/"):]
            self.handle_api_record_detail(record_id_str)
        elif path == "/api/ledger/verify":
            self.handle_api_verify()
        elif path == "/api/stats":
            self.handle_api_stats()
        elif path == "/api/ping":
            self._send_json({"pong": True, "server_time": time.time()})
        else:
            self._send_error("Endpoint not found", 404)

    def handle_index(self):
        """Serves the single-page application HTML interface."""
        if not self.template_path.exists():
            self._send_error(f"Template not found at {self.template_path}", 500)
            return

        with open(self.template_path, "r", encoding="utf-8") as f:
            content = f.read()
        self._send_html(content)

    def handle_api_status(self):
        """
        Reads daemon status heartbeat from disk and checks process liveness.
        Completely non-blocking; handles missing file or terminated daemon cleanly.
        """
        if not self.status_path.exists():
            self._send_json({
                "status": "OFFLINE",
                "process_alive": False,
                "message": "Daemon status heartbeat not found. Daemon may not be running.",
                "total_packets_captured": 0,
                "total_alerts": 0,
            })
            return

        try:
            with open(self.status_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            pid = data.get("pid")
            is_alive = False
            if pid and isinstance(pid, int):
                try:
                    is_alive = psutil.pid_exists(pid)
                    if is_alive:
                        proc = psutil.Process(pid)
                        if proc.status() == psutil.STATUS_ZOMBIE:
                            is_alive = False
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    is_alive = False

            data["process_alive"] = is_alive
            if not is_alive and data.get("status") == "RUNNING":
                data["status"] = "DEAD_PROCESS"

            self._send_json(data)
        except Exception as exc:
            logger.warning("Error reading daemon status: %s", exc)
            self._send_json({
                "status": "ERROR",
                "process_alive": False,
                "error": str(exc),
            })

    def handle_api_ledger(self, query: Dict[str, List[str]]):
        """
        Fetches recent alerts from the SQLite Action Ledger via read-only WAL connection.
        Omit raw 84-dim SHAP vector from summary list for lightweight network payload.
        """
        limit = 50
        offset = 0
        try:
            if "limit" in query:
                limit = max(1, min(500, int(query["limit"][0])))
            if "offset" in query:
                offset = max(0, int(query["offset"][0]))
        except ValueError:
            self._send_error("Invalid limit or offset query parameter", 400)
            return

        if not self.db_path.exists():
            self._send_json([])
            return

        try:
            ledger = ActionLedger(self.db_path)
            records = ledger.get_recent_records(limit=limit)

            results = []
            for r in records:
                d = r.to_dict()
                # Omit full 84-vector in list view to keep payload sub-millisecond
                d["shap_vector"] = None
                d["has_shap"] = r.shap_vector is not None
                results.append(d)

            self._send_json(results)
        except Exception as exc:
            logger.error("Error querying ledger: %s", exc)
            self._send_error(f"Failed to query action ledger: {exc}", 500)

    def handle_api_record_detail(self, record_id_str: str):
        """
        Retrieves a single record with its full 84-dimensional SHAP vector
        and computes the top positive and negative feature attribution drivers.
        """
        try:
            record_id = int(record_id_str)
        except ValueError:
            self._send_error("Record ID must be an integer", 400)
            return

        if not self.db_path.exists():
            self._send_error("Ledger database not found", 404)
            return

        try:
            ledger = ActionLedger(self.db_path)
            record = ledger.get_record_by_id(record_id)
            if record is None:
                self._send_error(f"Record with ID {record_id} not found", 404)
                return

            res = record.to_dict()

            # Compute top SHAP feature drivers
            top_drivers = []
            if record.shap_vector is not None and len(record.shap_vector) == len(CANONICAL_84_FEATURES):
                vec = record.shap_vector
                # Rank features by absolute contribution magnitude
                indices = sorted(range(len(vec)), key=lambda i: abs(vec[i]), reverse=True)
                for idx in indices[:12]:  # Top 12 drivers
                    top_drivers.append({
                        "index": idx,
                        "feature": CANONICAL_84_FEATURES[idx],
                        "value": float(vec[idx]),
                    })

            res["top_drivers"] = top_drivers
            self._send_json(res)
        except Exception as exc:
            logger.error("Error querying record detail %d: %s", record_id, exc)
            self._send_error(f"Failed to fetch record detail: {exc}", 500)

    def handle_api_verify(self):
        """
        Executes on-demand cryptographic verification of the SHA-256 hash-chain.
        """
        if not self.db_path.exists():
            self._send_json({
                "is_valid": True,
                "verified_count": 0,
                "error_details": None,
                "total_records": 0,
                "genesis_anchor": "0" * 64,
                "timestamp": time.time(),
            })
            return

        try:
            ledger = ActionLedger(self.db_path)
            is_valid, verified_cnt, error = ledger.verify_integrity()
            total = ledger.count_records()
            latest = ledger.get_latest_record()

            self._send_json({
                "is_valid": is_valid,
                "verified_count": verified_cnt,
                "total_records": total,
                "error_details": error,
                "latest_record_hash": latest.record_hash if latest else None,
                "genesis_anchor": "0" * 64,
                "timestamp": time.time(),
            })
        except Exception as exc:
            logger.error("Error executing chain verification: %s", exc)
            self._send_error(f"Integrity audit failed: {exc}", 500)

    def handle_api_stats(self):
        """
        Aggregates summary statistics for the dashboard charts:
        - Attack class distribution counts
        - MITRE ATT&CK tactic distribution
        - Severity breakdown
        - Chain verification status
        """
        if not self.db_path.exists():
            self._send_json({
                "total_records": 0,
                "chain_valid": True,
                "attack_distribution": {},
                "mitre_distribution": {},
                "severity_distribution": {},
            })
            return

        try:
            ledger = ActionLedger(self.db_path)
            stats = ledger.get_ledger_stats()

            # Query category aggregations
            with ledger._get_connection() as conn:
                # Attack distribution
                cur = conn.execute("SELECT prediction, COUNT(*) as cnt FROM action_ledger GROUP BY prediction;")
                attack_dist = {row["prediction"]: row["cnt"] for row in cur.fetchall()}

                # MITRE distribution
                cur = conn.execute("""
                    SELECT 'Stage ' || mitre_stage || ': ' || mitre_tactic as tactic, COUNT(*) as cnt 
                    FROM action_ledger GROUP BY mitre_stage, mitre_tactic ORDER BY mitre_stage ASC;
                """)
                mitre_dist = {row["tactic"]: row["cnt"] for row in cur.fetchall()}

                # Severity distribution
                cur = conn.execute("SELECT severity, COUNT(*) as cnt FROM action_ledger GROUP BY severity;")
                sev_dist = {row["severity"]: row["cnt"] for row in cur.fetchall()}

            stats["attack_distribution"] = attack_dist
            stats["mitre_distribution"] = mitre_dist
            stats["severity_distribution"] = sev_dist
            self._send_json(stats)
        except Exception as exc:
            logger.error("Error aggregating stats: %s", exc)
            self._send_error(f"Failed to generate dashboard statistics: {exc}", 500)


class DashboardServer:
    """
    Manages the lifecycle of the decoupled ThreadingHTTPServer dashboard instance.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        db_path: Optional[Path] = None,
        status_path: Optional[Path] = None,
    ):
        self.host = host
        self.port = port
        self.db_path = Path(db_path) if db_path else PROJECT_DIR / "data" / "ledger.db"
        self.status_path = Path(status_path) if status_path else PROJECT_DIR / "data" / "daemon_status.json"

        # Inject runtime configuration into handler class
        ShieldNetDashboardHandler.db_path = self.db_path
        ShieldNetDashboardHandler.status_path = self.status_path

        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self, block: bool = False):
        """Starts the dashboard HTTP server."""
        if self._running:
            logger.warning("DashboardServer is already running.")
            return

        self._server = ThreadingHTTPServer((self.host, self.port), ShieldNetDashboardHandler)
        self._running = True

        logger.info("ShieldNet Decoupled Dashboard running at http://%s:%d", self.host, self.port)
        logger.info("Reading Action Ledger from: %s", self.db_path)
        logger.info("Monitoring Daemon Status at: %s", self.status_path)

        if block:
            try:
                self._server.serve_forever()
            except KeyboardInterrupt:
                logger.info("Dashboard server shutdown requested.")
                self.stop()
        else:
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name="ShieldNet-DashboardServer",
                daemon=True,
            )
            self._thread.start()

    def stop(self):
        """Stops the dashboard server and cleans up resources."""
        if not self._running or self._server is None:
            return

        logger.info("Shutting down ShieldNet Dashboard server...")
        self._running = False
        self._server.shutdown()
        self._server.server_close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("Dashboard server cleanly stopped.")


def main():
    """Command-line launcher for the ShieldNet Decoupled Dashboard."""
    parser = argparse.ArgumentParser(description="ShieldNet Decoupled Cybersecurity Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Binding host IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Binding TCP port (default: 8080)")
    parser.add_argument("--db-path", type=str, default=None, help="Custom path to ledger.db")
    parser.add_argument("--status-path", type=str, default=None, help="Custom path to daemon_status.json")
    parser.add_argument("--open-browser", action="store_true", help="Automatically open dashboard in web browser")
    args = parser.parse_args()

    server = DashboardServer(
        host=args.host,
        port=args.port,
        db_path=Path(args.db_path) if args.db_path else None,
        status_path=Path(args.status_path) if args.status_path else None,
    )

    if args.open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{args.host}:{args.port}")).start()

    print(f"\n============================================================")
    print(f"      SHIELDNET DECOUPLED CYBERSECURITY DASHBOARD")
    print(f"============================================================")
    print(f" URL:             http://{args.host}:{args.port}")
    print(f" Ledger Path:     {server.db_path}")
    print(f" Status Path:     {server.status_path}")
    print(f" Mode:            READ-ONLY WAL (Zero Lock Contention)")
    print(f" Press Ctrl+C to stop the dashboard server.")
    print(f"============================================================\n")

    server.start(block=True)


if __name__ == "__main__":
    main()
