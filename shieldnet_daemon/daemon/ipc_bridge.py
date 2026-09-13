"""
ShieldNet Local IPC Bridge for Simulation & Demo Showcase.

Enables external tools (such as simulate_traffic.py and the CLI simulator)
to securely inject synthetic packet batches directly into the running daemon
without requiring promiscuous Npcap sniffing on physical interfaces.

Security & Hardening Guardrails:
1. Loopback-only binding: Strictly binds to 127.0.0.1; rejects external connections.
2. Ephemeral session token: Generated fresh on startup with 256-bit entropy.
3. Hardened token storage: Filesystem ACLs restrict read permissions to current user.
4. Constant-time token verification: Uses hmac.compare_digest to prevent timing attacks.
5. Brute-force lockout: Locks out requests for 60 seconds after 5 consecutive failed auth attempts.
6. Strict schema validation: Rejects malformed types, invalid IPs, and out-of-range packet fields.
7. Secure cleanup: Token file unlinked immediately on shutdown.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import struct
import subprocess
import threading
import time

from shared.feature_extractor import PacketMetadata

logger = logging.getLogger("ShieldNetIPC")

DEFAULT_IPC_HOST = "127.0.0.1"
DEFAULT_IPC_PORT = 49152
MAX_PAYLOAD_BYTES = 5 * 1024 * 1024  # 5 MB safety limit
MAX_BATCH_PACKETS = 10000
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 60.0


def validate_packet_dict(pkt: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Strictly validates packet fields, types, and protocol ranges before instantiation.
    Protects the feature extraction pipeline against malformed or malicious inputs.
    """
    if not isinstance(pkt, dict):
        return False, "Packet item must be a dictionary."

    # Required numeric & string fields
    required_fields = {
        "src_ip": str,
        "dst_ip": str,
        "src_port": int,
        "dst_port": int,
        "protocol": int,
        "total_length": int,
        "payload_length": int,
        "header_length": int,
        "direction": int,
        "tcp_flags": int,
        "tcp_window": int,
        "ttl": int,
    }

    for f_name, f_type in required_fields.items():
        if f_name not in pkt:
            return False, f"Missing required field: '{f_name}'"
        val = pkt[f_name]
        if not isinstance(val, f_type) or isinstance(val, bool):  # bool is subclass of int in Python
            return False, f"Field '{f_name}' must be of type {f_type.__name__}, got {type(val).__name__}"

    # IP address syntax validation
    try:
        ipaddress.ip_address(pkt["src_ip"])
        ipaddress.ip_address(pkt["dst_ip"])
    except ValueError as exc:
        return False, f"Invalid IP address format: {exc}"

    # Port ranges (0 - 65535)
    if not (0 <= pkt["src_port"] <= 65535):
        return False, f"Invalid src_port: {pkt['src_port']} (must be 0-65535)"
    if not (0 <= pkt["dst_port"] <= 65535):
        return False, f"Invalid dst_port: {pkt['dst_port']} (must be 0-65535)"

    # Protocol values (ICMP=1, TCP=6, UDP=17)
    if pkt["protocol"] not in (1, 6, 17):
        return False, f"Unsupported protocol: {pkt['protocol']} (must be 1, 6, or 17)"

    # Packet length bounds
    if not (20 <= pkt["total_length"] <= 65535):
        return False, f"Invalid total_length: {pkt['total_length']} (must be 20-65535)"
    if not (0 <= pkt["payload_length"] <= 65515):
        return False, f"Invalid payload_length: {pkt['payload_length']}"
    if not (20 <= pkt["header_length"] <= 120):
        return False, f"Invalid header_length: {pkt['header_length']}"

    # Direction (0=Forward, 1=Backward)
    if pkt["direction"] not in (0, 1):
        return False, f"Invalid direction: {pkt['direction']} (must be 0 or 1)"

    # TCP flags and window
    if not (0 <= pkt["tcp_flags"] <= 0xFF):
        return False, f"Invalid tcp_flags: {pkt['tcp_flags']}"
    if not (0 <= pkt["tcp_window"] <= 65535):
        return False, f"Invalid tcp_window: {pkt['tcp_window']}"

    # TTL bounds
    if not (1 <= pkt["ttl"] <= 255):
        return False, f"Invalid ttl: {pkt['ttl']} (must be 1-255)"

    return True, None


def packet_dict_to_metadata(d: Dict[str, Any]) -> PacketMetadata:
    """Converts a pre-validated dictionary into a canonical PacketMetadata object."""
    return PacketMetadata(
        timestamp=float(d.get("timestamp", time.time())),
        src_ip=d["src_ip"],
        dst_ip=d["dst_ip"],
        src_port=d["src_port"],
        dst_port=d["dst_port"],
        protocol=d["protocol"],
        total_length=d["total_length"],
        payload_length=d["payload_length"],
        header_length=d["header_length"],
        direction=d["direction"],
        tcp_flags=d["tcp_flags"],
        tcp_window=d["tcp_window"],
        seq_num=int(d.get("seq_num", 0)),
        ack_num=int(d.get("ack_num", 0)),
        ttl=d["ttl"],
    )


class IPCServer:
    """
    Localhost-only authenticated IPC server for injecting simulated traffic
    into the running ShieldNet daemon.
    """

    def __init__(
        self,
        daemon_ref: Any,
        data_dir: Path,
        host: str = DEFAULT_IPC_HOST,
        port: int = DEFAULT_IPC_PORT,
    ):
        self.daemon = daemon_ref
        self.data_dir = Path(data_dir)
        self.host = host
        self.port = port
        self.token_path = self.data_dir / ".ipc_token"

        # Ephemeral session token with 256-bit cryptographic entropy
        self.token = secrets.token_hex(32)

        # Thread synchronization and state
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

        # Brute-force lockout state
        self._failed_attempts = 0
        self._lockout_until = 0.0
        self._lock = threading.Lock()

    def _write_token_file(self):
        """Writes ephemeral token and locks down file permissions."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.token_path.write_text(self.token, encoding="utf-8")

        # Restrict permissions: current user read/write only
        try:
            if os.name == "nt":
                username = os.getenv("USERNAME", "Users")
                subprocess.run(
                    ["icacls", str(self.token_path), "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
                    capture_output=True,
                    check=False,
                )
            else:
                os.chmod(self.token_path, 0o600)
        except Exception as exc:
            logger.debug("Could not harden .ipc_token ACL: %s", exc)

    def _remove_token_file(self):
        """Securely deletes token file on shutdown."""
        try:
            if self.token_path.exists():
                self.token_path.unlink()
        except Exception as exc:
            logger.debug("Failed to remove .ipc_token: %s", exc)

    def start(self):
        """Binds to loopback interface and launches listener thread."""
        if self._running:
            return

        self._write_token_file()
        self._running = True

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(0.5)

        self._thread = threading.Thread(
            target=self._listen_loop,
            name="ShieldNet-IPCServer",
            daemon=True,
        )
        self._thread.start()
        logger.info("[IPC] Server listening on %s:%d [Ephemeral Token Generated]", self.host, self.port)

    def stop(self):
        """Stops listener and cleans up socket and token."""
        if not self._running:
            return
        self._running = False
        self._remove_token_file()

        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

        logger.info("[IPC] Server stopped cleanly.")

    def _listen_loop(self):
        """Accepts incoming loopback connections."""
        while self._running:
            try:
                client_sock, client_addr = self._server_socket.accept()
            except (socket.timeout, OSError):
                continue

            # Strict loopback defense: reject non-loopback connections
            if client_addr[0] != "127.0.0.1":
                logger.warning("[IPC] Rejected non-loopback connection attempt from %s", client_addr[0])
                try:
                    client_sock.close()
                except Exception:
                    pass
                continue

            # Handle connection in client thread
            handler_thread = threading.Thread(
                target=self._handle_client,
                args=(client_sock,),
                name="ShieldNet-IPCClientHandler",
                daemon=True,
            )
            handler_thread.start()

    def _handle_client(self, client_sock: socket.socket):
        """Processes request framed with 4-byte length prefix."""
        client_sock.settimeout(3.0)
        try:
            # 1. Read 4-byte length prefix
            prefix = self._recv_exact(client_sock, 4)
            if not prefix:
                return
            (payload_len,) = struct.unpack("!I", prefix)

            # Enforce max payload limit
            if payload_len > MAX_PAYLOAD_BYTES:
                err_resp = {"status": "error", "error": f"Payload exceeds {MAX_PAYLOAD_BYTES} bytes."}
                self._send_frame(client_sock, err_resp)
                return

            # 2. Read full JSON payload
            payload_data = self._recv_exact(client_sock, payload_len)
            if not payload_data:
                return

            msg = json.loads(payload_data.decode("utf-8"))

            # 3. Check brute-force lockout
            now = time.time()
            with self._lock:
                if now < self._lockout_until:
                    remaining = int(self._lockout_until - now)
                    err_resp = {
                        "status": "error",
                        "error": f"Authentication lockout active. Try again in {remaining}s.",
                    }
                    self._send_frame(client_sock, err_resp)
                    return

            # 4. Validate auth token using constant-time comparison
            req_token = msg.get("token", "")
            if not hmac.compare_digest(req_token, self.token):
                with self._lock:
                    self._failed_attempts += 1
                    if self._failed_attempts >= MAX_FAILED_ATTEMPTS:
                        self._lockout_until = now + LOCKOUT_DURATION_SECONDS
                        self._failed_attempts = 0
                        logger.warning(
                            "[IPC] Auth lockout triggered for %d seconds after failed attempts.",
                            int(LOCKOUT_DURATION_SECONDS),
                        )
                err_resp = {"status": "error", "error": "Invalid authentication token."}
                self._send_frame(client_sock, err_resp)
                return

            # Reset failed attempts on valid auth
            with self._lock:
                self._failed_attempts = 0

            # 5. Dispatch command
            cmd = msg.get("cmd")
            if cmd == "ping":
                resp = {
                    "status": "ok",
                    "message": "pong",
                    "mode": getattr(self.daemon, "active_mode", "UNKNOWN"),
                    "queue_size": self.daemon.packet_queue.qsize() if hasattr(self.daemon, "packet_queue") else 0,
                }
            elif cmd == "inject":
                raw_packets = msg.get("packets", [])
                if not isinstance(raw_packets, list):
                    resp = {"status": "error", "error": "'packets' must be a list."}
                elif len(raw_packets) > MAX_BATCH_PACKETS:
                    resp = {"status": "error", "error": f"Batch exceeds max {MAX_BATCH_PACKETS} packets."}
                else:
                    # Strict validation on each packet
                    valid_metadata_list = []
                    val_err = None
                    for idx, p_dict in enumerate(raw_packets):
                        is_valid, reason = validate_packet_dict(p_dict)
                        if not is_valid:
                            val_err = f"Packet #{idx} invalid: {reason}"
                            break
                        valid_metadata_list.append(packet_dict_to_metadata(p_dict))

                    if val_err:
                        resp = {"status": "error", "error": val_err}
                    else:
                        # Inject into daemon pipeline with provenance 'simulated'
                        accepted = self.daemon.inject_packets(valid_metadata_list, source="simulated")
                        resp = {
                            "status": "ok",
                            "accepted": accepted,
                            "source": "simulated",
                            "queue_size": self.daemon.packet_queue.qsize(),
                        }
            elif cmd == "stats":
                resp = {
                    "status": "ok",
                    "packets_captured": getattr(self.daemon, "total_packets_captured", 0),
                    "evaluations": getattr(self.daemon, "total_evaluations", 0),
                    "alerts": getattr(self.daemon, "total_alerts_logged", 0),
                }
            else:
                resp = {"status": "error", "error": f"Unknown command: '{cmd}'"}

            self._send_frame(client_sock, resp)

        except Exception as exc:
            logger.error("[IPC] Client handler error: %s", exc)
            try:
                self._send_frame(client_sock, {"status": "error", "error": str(exc)})
            except Exception:
                pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _recv_exact(self, sock: socket.socket, num_bytes: int) -> Optional[bytes]:
        """Receives exactly num_bytes from socket."""
        buf = bytearray()
        while len(buf) < num_bytes:
            chunk = sock.recv(num_bytes - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _send_frame(self, sock: socket.socket, payload: Dict[str, Any]):
        """Sends length-prefixed JSON frame."""
        data = json.dumps(payload).encode("utf-8")
        header = struct.pack("!I", len(data))
        sock.sendall(header + data)


class IPCClient:
    """
    Client for transmitting simulated traffic batches to the running daemon over IPC.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        token_path: Optional[Path] = None,
        host: str = DEFAULT_IPC_HOST,
        port: int = DEFAULT_IPC_PORT,
    ):
        self.host = host
        self.port = port
        self.token = token

        if self.token is None:
            # Auto-discover from token file if not explicitly supplied
            t_path = token_path or (Path(__file__).resolve().parent.parent / "data" / ".ipc_token")
            if t_path.exists():
                self.token = t_path.read_text(encoding="utf-8").strip()

    def _send_request(self, req: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
        """Connects, sends request frame, and parses response."""
        if not self.token:
            raise ConnectionError(
                "No IPC auth token found. Ensure the ShieldNet daemon is running with --enable-ipc."
            )

        req["token"] = self.token
        data = json.dumps(req).encode("utf-8")
        header = struct.pack("!I", len(data))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((self.host, self.port))
            sock.sendall(header + data)

            # Read response prefix
            prefix = sock.recv(4)
            if len(prefix) < 4:
                raise ConnectionError("Incomplete response from ShieldNet IPC server.")
            (resp_len,) = struct.unpack("!I", prefix)

            # Read response body
            resp_buf = bytearray()
            while len(resp_buf) < resp_len:
                chunk = sock.recv(resp_len - len(resp_buf))
                if not chunk:
                    break
                resp_buf.extend(chunk)

            return json.loads(resp_buf.decode("utf-8"))
        finally:
            sock.close()

    def ping(self) -> Dict[str, Any]:
        """Pings running daemon."""
        return self._send_request({"cmd": "ping"})

    def inject_packets(self, packets: List[Any]) -> Dict[str, Any]:
        """
        Sends list of PacketMetadata or packet dicts to running daemon over IPC.
        """
        serialized = []
        for p in packets:
            if hasattr(p, "to_dict"):
                serialized.append(p.to_dict())
            elif isinstance(p, dict):
                serialized.append(p)
            elif isinstance(p, PacketMetadata):
                serialized.append({
                    "timestamp": p.timestamp,
                    "src_ip": p.src_ip,
                    "dst_ip": p.dst_ip,
                    "src_port": p.src_port,
                    "dst_port": p.dst_port,
                    "protocol": p.protocol,
                    "total_length": p.total_length,
                    "payload_length": p.payload_length,
                    "header_length": p.header_length,
                    "direction": p.direction,
                    "tcp_flags": p.tcp_flags,
                    "tcp_window": p.tcp_window,
                    "seq_num": p.seq_num,
                    "ack_num": p.ack_num,
                    "ttl": p.ttl,
                })
            else:
                raise ValueError(f"Unsupported packet item type: {type(p)}")

        return self._send_request({"cmd": "inject", "packets": serialized})

    def get_stats(self) -> Dict[str, Any]:
        """Fetches live telemetry over IPC."""
        return self._send_request({"cmd": "stats"})
