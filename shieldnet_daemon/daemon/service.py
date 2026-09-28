"""
ShieldNet Autonomous Background Detection Daemon.

Implements Module 6 of ShieldNet Tech Stack:
- Continuous headless background process running the full 7-stage offline pipeline:
    1. Packet capture / injection queue
    2. RollingFlowBuffer temporal feature extraction (84 canonical features, L=3)
    3. ONNX Runtime inference engine (GRU+Attention, K=5 rollout)
    4. Confidence Gate (World Model + Logistic Regression baseline ensemble)
    5. Gated SHAP explainability (strictly invoked on flagged windows)
    6. SQLite Action Ledger with SHA-256 hash chaining
    7. Atomic daemon status heartbeat for decoupled dashboard monitoring
- Multi-threaded architecture: capture worker, processing loop, and status heartbeat.
- Graceful shutdown signal handling (SIGINT, SIGTERM, Windows SIGBREAK).
- Air-gap / offline compliance: zero cloud or external network dependencies.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
import json
import logging
import os
import queue
import signal
import sys
import threading
import time
import numpy as np
import psutil

# Base path resolution
DAEMON_DIR = Path(__file__).resolve().parent
PROJECT_DIR = DAEMON_DIR.parent

if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

# Ensure Npcap DLL directory is discoverable on Windows
if os.name == "nt":
    _npcap_dir = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "Npcap"
    if _npcap_dir.exists():
        try:
            os.add_dll_directory(str(_npcap_dir))
        except Exception:
            pass
        if str(_npcap_dir) not in os.environ.get("PATH", ""):
            os.environ["PATH"] = str(_npcap_dir) + os.pathsep + os.environ.get("PATH", "")

from shared.schema import (
    CANONICAL_84_FEATURES,
    NUM_CANONICAL_FEATURES,
    CONTEXT_LENGTH,
    ATTACK_CLASSES,
    MITRE_STAGES,
)
from shared.feature_extractor import PacketMetadata, parse_scapy_packet
from shared.rolling_buffer import RollingFlowBuffer
from shared.scaler_guard import FrozenReferenceScalerGuard
from shared.integrity import IntegrityVerifier, SecurityIntegrityViolation
from engine.inference import ONNXInferenceEngine
from engine.confidence_gate import ConfidenceGate
from engine.explainer import GatedSHAPExplainer, SHAPOutput
from engine.ledger import ActionLedger, LedgerRecord

logger = logging.getLogger("ShieldNetDaemon")


@dataclass
class DaemonConfig:
    """Configuration parameters for the ShieldNet background daemon."""
    db_path: Path = field(default_factory=lambda: PROJECT_DIR / "data" / "ledger.db")
    status_path: Path = field(default_factory=lambda: PROJECT_DIR / "data" / "daemon_status.json")
    model_path: Path = field(default_factory=lambda: PROJECT_DIR / "models" / "onnx" / "world_model.onnx")
    scaler_path: Path = field(default_factory=lambda: PROJECT_DIR / "models" / "checkpoints" / "scaler_reference.npz")
    logreg_path: Path = field(default_factory=lambda: PROJECT_DIR / "models" / "checkpoints" / "logreg_params.npz")
    interface: Optional[str] = None
    evaluation_interval: float = 1.0       # Window evaluation frequency in seconds
    heartbeat_interval: float = 2.0        # Status heartbeat write frequency in seconds
    flow_timeout: float = 15.0             # Inactive flow eviction timeout in seconds
    confidence_tau: float = 0.80           # World model confidence gating threshold
    threat_threshold: float = 0.80         # Binary flag threshold (high-precision: reduces false positives)
    max_queue_size: int = 10000            # Packet ingest queue capacity
    mock_mode: bool = False                # If True, bypass live NIC sniffing
    enable_ipc: bool = False               # If True, launch localhost IPC bridge (demo mode only)
    ipc_host: str = "127.0.0.1"            # Strictly loopback only
    ipc_port: int = 49152                  # Default IPC simulation port
    verify_integrity: bool = True          # Cryptographic SHA-256 asset verification at startup
    enforce_production_security: bool = True # Disallow IPC bridge if in live capture mode
    verbose: bool = False                  # If True, emits raw feature matrices and detailed debugging
    console_status: bool = True            # If True and not verbose, periodically prints minimal status line
    status_interval: float = 3.0           # Frequency in seconds for minimal console status updates
    ledger_max_records: Optional[int] = 10000  # Action ledger row-cap limit (auto-pruned with checkpoint anchoring)


class ShieldNetDaemon:
    """
    Core headless background daemon orchestrating real-time detection,
    gated explainability, tamper-evident ledger logging, and status reporting.
    """

    def __init__(self, config: Optional[DaemonConfig] = None):
        self.config = config or DaemonConfig()
        self.data_dir = self.config.db_path.parent
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Thread synchronization
        self._running = False
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._process = psutil.Process(os.getpid())

        # Packet ingestion buffer
        self.packet_queue: queue.Queue = queue.Queue(maxsize=self.config.max_queue_size)

        # Metrics and runtime stats
        self.start_time: float = 0.0
        self.total_packets_captured: int = 0
        self.total_packets_dropped: int = 0
        self.total_evaluations: int = 0
        self.total_alerts_logged: int = 0
        self.last_eval_time: float = 0.0
        self.last_heartbeat_time: float = 0.0
        self.last_alert: Optional[Dict[str, Any]] = None
        self.last_threat_prob: float = 0.0
        self.last_pred_class: str = "Benign"
        self.latest_forecast: List[Dict[str, Any]] = []
        self.active_mode: str = "INITIALIZING"

        self.ipc_server: Optional[Any] = None

        # Initialize core engine components
        self._init_components()

    def _init_components(self):
        """Initializes all sub-modules from Modules 1 through 5 with cryptographic integrity checks."""
        if self.config.verify_integrity:
            models_root = PROJECT_DIR / "models"
            logger.info("[Init] Cryptographic Asset Verification: validating %s against manifest.json", models_root)
            IntegrityVerifier.verify_all(models_dir=models_root)

        logger.info("[Init] Loading Scaler Guard from %s", self.config.scaler_path)
        self.scaler_guard = FrozenReferenceScalerGuard(self.config.scaler_path)

        logger.info("[Init] Initializing RollingFlowBuffer (window=%.1fs, timeout=%.1fs)",
                    self.config.evaluation_interval, self.config.flow_timeout)
        self.buffer = RollingFlowBuffer(
            window_seconds=self.config.evaluation_interval,
            flow_timeout=self.config.flow_timeout,
            context_length=CONTEXT_LENGTH,
        )

        logger.info("[Init] Initializing ONNX Inference Engine from %s", self.config.model_path)
        self.inference_engine = ONNXInferenceEngine(
            model_path=self.config.model_path,
            scaler_guard=self.scaler_guard,
            num_threads=2,
        )

        logger.info("[Init] Initializing Confidence Gate from %s (tau=%.2f)",
                    self.config.logreg_path, self.config.confidence_tau)
        self.confidence_gate = ConfidenceGate(
            logreg_path=self.config.logreg_path,
            confidence_tau=self.config.confidence_tau,
            threat_threshold=self.config.threat_threshold,
        )

        logger.info("[Init] Initializing Gated SHAP Explainer (nsamples=30)")
        self.explainer = GatedSHAPExplainer(
            inference_engine=self.inference_engine,
            nsamples=30,
        )

        logger.info("[Init] Initializing SQLite Action Ledger at %s (max_records=%s)",
                    self.config.db_path, self.config.ledger_max_records)
        self.ledger = ActionLedger(
            db_path=self.config.db_path,
            max_records=self.config.ledger_max_records,
        )

        from engine.corroboration import CrossNodeCorroborator
        self.corroborator = CrossNodeCorroborator(
            node_id=f"node_{os.getpid()}",
            similarity_threshold=0.75,
            max_boost=0.15,
        )

    def inject_packet(self, pkt: PacketMetadata, source: Optional[str] = None) -> bool:
        """
        Directly injects a PacketMetadata instance into the daemon's ingest queue.
        Thread-safe; used by simulators, tests, and packet capture hooks.
        """
        if source:
            pkt.source = source
        try:
            self.packet_queue.put_nowait(pkt)
            self.total_packets_captured += 1
            return True
        except queue.Full:
            self.total_packets_dropped += 1
            return False

    def inject_packets(self, packets: List[PacketMetadata], source: Optional[str] = None) -> int:
        """Injects a batch of packets into the ingest queue with provenance tracking."""
        accepted = 0
        for pkt in packets:
            if self.inject_packet(pkt, source=source):
                accepted += 1
        return accepted

    def inject_scapy_packet(self, scapy_pkt: Any) -> bool:
        """Parses a Scapy packet and pushes it into the ingest queue."""
        pkt_meta = parse_scapy_packet(scapy_pkt)
        if pkt_meta is not None:
            return self.inject_packet(pkt_meta)
        return False

    def start(self, block: bool = False):
        """Starts background daemon workers (Capture, Processing, Heartbeat)."""
        if self._running:
            logger.warning("ShieldNetDaemon is already running.")
            return

        self._running = True
        self._stop_event.clear()
        self.start_time = time.time()
        self.last_eval_time = self.start_time
        self.last_heartbeat_time = self.start_time

        # Register OS signal handlers for graceful shutdown
        self._setup_signals()

        # Start processing worker thread
        proc_thread = threading.Thread(
            target=self._processing_loop,
            name="ShieldNet-Processor",
            daemon=True,
        )
        proc_thread.start()
        self._threads.append(proc_thread)

        # Start heartbeat worker thread
        hb_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="ShieldNet-Heartbeat",
            daemon=True,
        )
        hb_thread.start()
        self._threads.append(hb_thread)

        # Start sniffer worker thread
        sniffer_thread = threading.Thread(
            target=self._sniffer_loop,
            name="ShieldNet-Sniffer",
            daemon=True,
        )
        sniffer_thread.start()
        self._threads.append(sniffer_thread)

        # Start IPC Server worker thread (Demo Mode only)
        if self.config.enable_ipc:
            if not self.config.mock_mode and self.config.enforce_production_security:
                logger.critical("[Security Violation] Refusing to start IPC bridge in live capture mode!")
                raise SecurityIntegrityViolation(
                    "Security Policy Violation: The IPC bridge is strictly restricted to mock/demo mode. "
                    "Running an injection bridge in live production capture opens an unauthorized sensor manipulation vector."
                )
            from daemon.ipc_bridge import IPCServer
            self.ipc_server = IPCServer(
                daemon_ref=self,
                data_dir=self.data_dir,
                host=self.config.ipc_host,
                port=self.config.ipc_port,
            )
            self.ipc_server.start()
            logger.info("[IPC] Local simulation IPC bridge active on %s:%d [DEMO MODE]",
                        self.config.ipc_host, self.config.ipc_port)

        self._write_status(status_override="RUNNING")
        logger.info("ShieldNet daemon started successfully [PID: %d]", os.getpid())

        if block:
            last_status_time = 0.0
            try:
                while self._running:
                    now = time.time()
                    if not self.config.verbose and self.config.console_status:
                        if now - last_status_time >= self.config.status_interval:
                            summary = self.get_telemetry_summary()
                            t_str = time.strftime("%H:%M:%S")
                            print(
                                f"[{t_str}] [STATUS] State: {summary['state']} | "
                                f"Pkts: {summary['packets']} | Flows: {summary['flows']} | "
                                f"Alerts: {summary['alerts']} | Threat Confidence: {summary['threat_prob']:.2f} ({summary['threat_level']})",
                                flush=True,
                            )
                            last_status_time = now
                    time.sleep(0.5)
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt received in main thread.")
                self.stop()

    def stop(self, timeout: float = 5.0):
        """Triggers graceful shutdown across all worker threads and flushes ledger."""
        if not self._running:
            return

        logger.info("Initiating graceful shutdown for ShieldNet daemon...")
        self._running = False
        self._stop_event.set()

        # Stop IPC server if active
        if self.ipc_server:
            try:
                self.ipc_server.stop()
            except Exception as exc:
                logger.debug("Error stopping IPC server: %s", exc)
            self.ipc_server = None

        # Wait for threads to terminate
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=timeout)

        # Final queue flush
        self._drain_queue()

        # Update final status file
        self._write_status(status_override="STOPPED")
        logger.info("ShieldNet daemon cleanly stopped.")

    def _setup_signals(self):
        """Registers termination signals across POSIX and Windows."""
        try:
            if threading.current_thread() is threading.main_thread():
                signal.signal(signal.SIGINT, self._signal_handler)
                signal.signal(signal.SIGTERM, self._signal_handler)
                if hasattr(signal, "SIGBREAK"):
                    signal.signal(signal.SIGBREAK, self._signal_handler)
        except (ValueError, AttributeError) as exc:
            logger.debug("Signal registration skipped: %s", exc)

    def _signal_handler(self, signum, frame):
        """Handles incoming termination signals."""
        logger.info("Received signal %s, initiating shutdown.", signum)
        self.stop()

    def _detect_active_interface(self) -> Optional[str]:
        """Detects the primary active network adapter with an active IPv4 gateway."""
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            candidates = []
            for iface_name, iface_addrs in addrs.items():
                if iface_name.lower().startswith("loopback") or "pseudo" in iface_name.lower():
                    continue
                is_up = stats.get(iface_name).isup if iface_name in stats else False
                if not is_up:
                    continue
                ipv4s = [a.address for a in iface_addrs if a.family.name == "AF_INET" and not a.address.startswith("127.")]
                if ipv4s:
                    is_physical = ("wifi" in iface_name.lower() or "ethernet" in iface_name.lower()) and "vethernet" not in iface_name.lower()
                    candidates.append((1 if is_physical else 0, iface_name, ipv4s[0]))

            if candidates:
                candidates.sort(key=lambda x: x[0], reverse=True)
                selected = candidates[0][1]
                logger.info("[Sniffer] Auto-detected primary active interface: '%s' (IP: %s)", selected, candidates[0][2])
                return selected
        except Exception as exc:
            logger.debug("Failed to auto-detect active network interface: %s", exc)
        return None

    def _sniffer_loop(self):
        """Packet capture thread. Uses Scapy if available; falls back to injection."""
        if self.config.mock_mode:
            self.active_mode = "MOCK_INJECTION"
            logger.info("Mock mode enabled: live network interface sniffer disabled.")
            return

        try:
            import scapy.config
            import scapy.layers.inet   # noqa: F401 — ensure IP/TCP/UDP dissectors are registered
            import scapy.layers.inet6  # noqa: F401 — ensure IPv6/ICMPv6 dissectors are registered
            import scapy.layers.l2     # noqa: F401 — ensure Ether dissector is registered
            from scapy.sendrecv import AsyncSniffer

            # Force Scapy to use Npcap/WinPcap backend on Windows (not libdnet fallback)
            scapy.config.conf.use_pcap = True

            target_iface = self.config.interface or self._detect_active_interface()
            logger.info("[Sniffer] Attempting Scapy packet capture on interface: %s", target_iface or "DEFAULT")

            # Diagnostic counters
            _raw_frames_seen = [0]       # Total frames arriving in callback
            _inet_frames_accepted = [0]  # Frames with a valid IPv4 or IPv6 layer
            _last_diag_time = [time.time()]

            def _safe_packet_callback(scapy_pkt):
                _raw_frames_seen[0] += 1
                try:
                    from scapy.layers.inet import IP
                    from scapy.layers.inet6 import IPv6
                    from scapy.layers.l2 import Ether

                    def _has_inet(pkt):
                        return pkt.haslayer(IP) or pkt.haslayer(IPv6)

                    # If Scapy couldn't guess datalink type, the packet arrives as
                    # a raw Packet with a bytes payload — try to re-parse as Ether.
                    if not _has_inet(scapy_pkt):
                        raw = bytes(scapy_pkt)
                        # Try Ethernet frame first (most common for WiFi in managed mode)
                        try:
                            reparsed = Ether(raw)
                            if _has_inet(reparsed):
                                scapy_pkt = reparsed
                        except Exception:
                            pass

                    # Second chance: maybe it's a raw IP/IPv6 datagram (no Ether header)
                    if not _has_inet(scapy_pkt):
                        raw = bytes(scapy_pkt)
                        try:
                            reparsed = IP(raw)
                            if reparsed.haslayer(IP):
                                scapy_pkt = reparsed
                        except Exception:
                            pass

                    if not _has_inet(scapy_pkt):
                        raw = bytes(scapy_pkt)
                        try:
                            reparsed = IPv6(raw)
                            if reparsed.haslayer(IPv6):
                                scapy_pkt = reparsed
                        except Exception:
                            pass

                    if _has_inet(scapy_pkt):
                        _inet_frames_accepted[0] += 1
                    self.inject_scapy_packet(scapy_pkt)

                except Exception as pkt_err:
                    logger.debug("[Sniffer] Packet callback dropped malformed packet: %s", pkt_err)

                # Emit a periodic diagnostic log every 10 seconds
                now = time.time()
                if now - _last_diag_time[0] >= 10.0:
                    logger.info(
                        "[Sniffer] Diagnostics: raw_frames=%d, inet_accepted=%d (IPv4+IPv6), queue_size=%d",
                        _raw_frames_seen[0], _inet_frames_accepted[0], self.packet_queue.qsize(),
                    )
                    _last_diag_time[0] = now

            # BPF filter: capture both IPv4 and IPv6 traffic — Npcap evaluates this in
            # kernel space before packets reach Python (zero overhead for other L3 types).
            sniffer = AsyncSniffer(
                prn=_safe_packet_callback,
                store=False,
                iface=target_iface,
                filter="ip or ip6",   # Kernel BPF: IPv4 + IPv6 frames reach callback
            )
            sniffer.start()
            self.active_mode = "LIVE_SNIFFING"
            logger.info("[Sniffer] Live packet sniffer active on '%s' (BPF: ip or ip6).", target_iface)

            while self._running and not self._stop_event.is_set():
                time.sleep(0.2)

            if sniffer.running:
                sniffer.stop()
            logger.info(
                "[Sniffer] Session ended. raw_frames=%d, inet_accepted=%d",
                _raw_frames_seen[0], _inet_frames_accepted[0],
            )
        except Exception as exc:
            self.active_mode = "INJECTION_ONLY"
            logger.warning(
                "[Sniffer] Live packet capture unavailable (%s). "
                "Operating in injection mode (simulator/API feeds).", exc
            )
            # Print loudly so the user can never miss this failure
            print(
                f"\n[!!! SNIFFER FAILURE !!!] Live packet capture could not start.\n"
                f"    Error: {exc}\n"
                f"    Cause: Npcap may not be installed, or you are not running as Administrator.\n"
                f"    The daemon will accept injected packets only (no live traffic).\n",
                flush=True,
            )

    def _processing_loop(self):
        """Core detection loop: ingests packets, steps window, runs ONNX+Gate+SHAP."""
        while self._running and not self._stop_event.is_set():
            # 1. Drain pending packets from ingest queue
            packets_drained = 0
            while not self.packet_queue.empty() and packets_drained < 500:
                try:
                    pkt = self.packet_queue.get_nowait()
                    self.buffer.ingest_packet(pkt)
                    self.packet_queue.task_done()
                    packets_drained += 1
                except queue.Empty:
                    break

            # 2. Check if evaluation interval has elapsed
            now = time.time()
            if now - self.last_eval_time >= self.config.evaluation_interval:
                self._evaluate_active_windows(now)
                self.last_eval_time = now

            # Sleep briefly to avoid 100% CPU spinning when idle
            time.sleep(0.01)

    def _drain_queue(self):
        """Drains remaining packets on shutdown."""
        while not self.packet_queue.empty():
            try:
                pkt = self.packet_queue.get_nowait()
                self.buffer.ingest_packet(pkt)
                self.packet_queue.task_done()
            except queue.Empty:
                break
        self._evaluate_active_windows(time.time())

    def _evaluate_active_windows(self, current_time: float):
        """
        Steps the rolling buffer, runs ONNX inference + Confidence Gate,
        and logs alerts with gated SHAP explainability.
        """
        evaluations = self.buffer.step_window(current_time, self.scaler_guard)
        if not evaluations:
            return

        logger.debug(
            "[Eval] %d flows passed readiness guards (active=%d, skipped_immature=%d)",
            len(evaluations), len(self.buffer.active_flows),
            self.buffer.total_flows_skipped_immature,
        )

        self.total_evaluations += len(evaluations)

        for item in evaluations:
            seq = item["sequence"]  # (L, 84)
            seq_batch = np.expand_dims(seq, axis=0).astype(np.float32)  # (1, L, 84)
            raw_vec = item["raw_vector"]

            # Step 3: ONNX Runtime Model Inference (single step + K=5 rollout)
            step_out = self.inference_engine.predict_step(seq_batch)
            rollout = self.inference_engine.rollout(seq_batch, k_steps=5)

            # Step 4: Confidence Gate Ensemble Evaluation
            gate_res = self.confidence_gate.evaluate_window(
                wm_step_output=step_out,
                current_state=item["normalized_vector"],
                k_step_rollout=rollout,
            )

            # Update live telemetry metrics
            self.last_threat_prob = float(gate_res["threat_probability"])
            self.last_pred_class = str(gate_res["predicted_class"])

            # Format K=5 forecast trajectory
            k_step_forecast = []
            rollout_probs = rollout.get("k_step_rollout", [])
            rollout_mitre = rollout.get("mitre_trajectory", [])
            rollout_classes = rollout.get("predicted_classes", [])
            trigger_step = gate_res.get("triggering_step", 1)

            for i in range(len(rollout_probs)):
                step_num = i + 1
                prob = float(rollout_probs[i])
                p_class = rollout_classes[i] if i < len(rollout_classes) else "Unknown"
                m_stage = int(rollout_mitre[i]) if i < len(rollout_mitre) else 0
                k_step_forecast.append({
                    "step": step_num,
                    "step_ahead": f"t+{step_num}",
                    "threat_probability": round(prob, 4),
                    "predicted_class": p_class,
                    "mitre_stage": m_stage,
                    "mitre_tactic": MITRE_STAGES.get(m_stage, f"Stage {m_stage}"),
                    "is_trigger": bool(gate_res["is_flagged"] and step_num == trigger_step),
                })

            self.latest_forecast = k_step_forecast

            # Verbose debugging: gate raw feature matrices and vectors behind verbose flag
            if self.config.verbose:
                logger.debug(
                    "[Verbose] Active Flow Window: shape=%s, raw_vector[:5]=%s",
                    seq.shape,
                    np.round(raw_vec[:5], 3).tolist(),
                )
                logger.debug("[Verbose] Sequence Feature Matrix (L=%d, D=%d):\n%s", seq.shape[0], seq.shape[1], seq)
                logger.debug("[Verbose] Full Raw Feature Vector (84-dim):\n%s", raw_vec)
                logger.debug("[Verbose] Threat Rollout (K=5): %s", rollout.get("threat_probabilities", []))

            # Step 5: Gated SHAP Explanation (only if flagged)
            if gate_res["is_flagged"]:
                shap_out: Optional[SHAPOutput] = self.explainer.explain_window(
                    gate_result=gate_res,
                    sequence=seq_batch,
                )

                shap_summary_json = shap_out.shap_summary if shap_out else "{}"
                shap_vec = shap_out.shap_vector if shap_out else None

                if shap_vec is not None and self.config.verbose:
                    logger.debug("[Verbose] Full SHAP Attribution Vector (84-dim):\n%s", shap_vec)

                # Step 6: Tier 2 Cross-Node Threat Intel Corroboration
                final_threat_prob = gate_res["threat_probability"]
                corrob_metadata = None
                if shap_vec is not None:
                    corrob_res = self.corroborator.corroborate_local_threat(
                        local_shap=shap_vec,
                        local_threat_prob=gate_res["threat_probability"],
                        local_pred_class=gate_res["predicted_class"],
                    )
                    if corrob_res.is_corroborated:
                        final_threat_prob = corrob_res.boosted_probability
                        corrob_metadata = corrob_res.to_dict()
                        logger.info(
                            "[Tier 2 Corroboration] %s threat corroborated by peer %s (Cosine Sim: %.3f, Boost: %.2f%% -> %.2f%%)",
                            gate_res["predicted_class"],
                            corrob_res.corroborating_node_id,
                            corrob_res.max_similarity,
                            gate_res["threat_probability"] * 100,
                            final_threat_prob * 100,
                        )

                # Inject forecast and corroboration metadata into shap_summary_json
                if shap_summary_json != "{}":
                    try:
                        s_data = json.loads(shap_summary_json)
                        s_data["k_step_forecast"] = k_step_forecast
                        s_data["triggering_step"] = gate_res.get("triggering_step", 1)
                        s_data["triggering_step_ahead"] = gate_res.get("triggering_step_ahead", "t+1")
                        if corrob_metadata:
                            s_data["tier2_corroboration"] = corrob_metadata
                        shap_summary_json = json.dumps(s_data)
                    except Exception:
                        pass

                # Step 7: SQLite Action Ledger with Hash-Chaining
                record = self.ledger.append_record(
                    prediction=gate_res["predicted_class"],
                    threat_probability=final_threat_prob,
                    mitre_stage=gate_res["mitre_stage"],
                    mitre_tactic=gate_res["mitre_tactic"],
                    severity=gate_res["severity"],
                    shap_summary=shap_summary_json,
                    shap_vector=shap_vec,
                    source=item.get("source", "live_sniffer"),
                )

                self.total_alerts_logged += 1
                top_feature_str = (
                    shap_out.top_features[0]["feature_name"]
                    if shap_out and shap_out.top_features
                    else "N/A"
                )

                self.last_alert = {
                    "record_id": record.id,
                    "timestamp": record.iso_time,
                    "prediction": record.prediction,
                    "threat_probability": round(record.threat_probability, 4),
                    "mitre_stage": record.mitre_stage,
                    "mitre_tactic": record.mitre_tactic,
                    "severity": record.severity,
                    "top_driver": top_feature_str,
                    "record_hash": record.record_hash[:16] + "...",
                    "triggering_step": gate_res.get("triggering_step", 1),
                    "triggering_step_ahead": gate_res.get("triggering_step_ahead", "t+1"),
                    "k_step_forecast": k_step_forecast,
                }

                trigger_str = gate_res.get("triggering_step_ahead", "t+1")
                logger.warning(
                    "[ALERT #%d] Threat Detected (Trigger: %s): %s (Prob: %.2f%%, MITRE: %s - %s) Hash: %s",
                    record.id,
                    trigger_str,
                    record.prediction,
                    record.threat_probability * 100,
                    record.mitre_stage,
                    record.mitre_tactic,
                    record.record_hash[:12],
                )

    def _heartbeat_loop(self):
        """Periodically emits atomic health and telemetry status JSON."""
        while self._running and not self._stop_event.is_set():
            now = time.time()
            if now - self.last_heartbeat_time >= self.config.heartbeat_interval:
                self._write_status(status_override="RUNNING")
                self.last_heartbeat_time = now
            time.sleep(0.5)

    def _write_status(self, status_override: Optional[str] = None):
        """Writes daemon status to JSON atomically."""
        try:
            uptime = max(0.0, time.time() - self.start_time) if self.start_time > 0 else 0.0
            uptime_str = time.strftime("%H:%M:%S", time.gmtime(uptime))

            try:
                mem_rss_mb = round(self._process.memory_info().rss / (1024 * 1024), 2)
                cpu_pct = round(self._process.cpu_percent(interval=None), 1)
            except Exception:
                mem_rss_mb = 0.0
                cpu_pct = 0.0

            status_payload = {
                "pid": os.getpid(),
                "status": status_override or ("RUNNING" if self._running else "STOPPED"),
                "mode": self.active_mode,
                "start_time": self.start_time,
                "uptime_seconds": round(uptime, 2),
                "uptime_formatted": uptime_str,
                "total_packets_captured": self.total_packets_captured,
                "total_packets_dropped": self.total_packets_dropped,
                "active_flows": len(self.buffer.active_flows),
                "total_evaluations": self.total_evaluations,
                "total_alerts": self.total_alerts_logged,
                "last_heartbeat": datetime.now().isoformat(),
                "memory_rss_mb": mem_rss_mb,
                "cpu_percent": cpu_pct,
                "ledger_db_path": str(self.config.db_path),
                "last_alert": self.last_alert,
                "latest_forecast": self.latest_forecast,
                "last_threat_probability": round(self.last_threat_prob, 4),
                "last_predicted_class": self.last_pred_class,
                "ledger_stats": self.ledger.get_ledger_stats(),
            }

            # Atomic write: write to temporary file, then atomic rename
            tmp_path = self.config.status_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(status_payload, f, indent=2)
            tmp_path.replace(self.config.status_path)
        except Exception as exc:
            logger.debug("Failed to write status heartbeat: %s", exc)

    def get_status(self) -> Dict[str, Any]:
        """Returns the current status dictionary directly from memory or disk."""
        if self.config.status_path.exists():
            try:
                with open(self.config.status_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "pid": os.getpid(),
            "status": "RUNNING" if self._running else "STOPPED",
            "uptime_seconds": max(0.0, time.time() - self.start_time),
            "total_packets": self.total_packets_captured,
            "total_alerts": self.total_alerts_logged,
        }

    def get_telemetry_summary(self) -> Dict[str, Any]:
        """Returns concise status summary for terminal display."""
        threat_level = "Nominal"
        if self.last_threat_prob >= self.config.threat_threshold:
            threat_level = f"FLAGGED ({self.last_pred_class})"
        elif self.last_threat_prob >= 0.5:
            threat_level = f"ELEVATED ({self.last_threat_prob:.2f})"

        return {
            "state": f"RUNNING ({self.active_mode})" if self._running else "STOPPED",
            "packets": self.total_packets_captured,
            "flows": len(self.buffer.active_flows),
            "alerts": self.total_alerts_logged,
            "threat_prob": self.last_threat_prob,
            "threat_level": threat_level,
            "last_alert": self.last_alert,
            "latest_forecast": self.latest_forecast,
        }

    def import_peer_signature(self, payload: Union[str, Dict[str, Any]]) -> Tuple[bool, str]:
        """Imports a verified, zero-IP peer threat signature into the corroboration pool."""
        is_valid, msg, _ = self.corroborator.import_signature_payload(payload)
        return is_valid, msg

    def export_threat_signature(self, record_id: int) -> Optional[Dict[str, Any]]:
        """Exports a zero-IP verifiable threat signature for a given ledger record."""
        return self.ledger.export_threat_signature(record_id=record_id, node_id=self.corroborator.node_id)


