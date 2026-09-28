"""
ShieldNet Rolling Flow Buffer & Temporal Sequence Engine.

Implements sliding time-window buffers per active network flow key (5-tuple),
computes 84-dimensional feature representations upon window evaluation or timeout,
and maintains temporal context windows (L=3) for GRU World Model inference.
"""

import time
from collections import deque
from typing import Dict, List, Tuple, Optional, Any
import numpy as np

from .schema import NUM_CANONICAL_FEATURES, CONTEXT_LENGTH
from .feature_extractor import PacketMetadata, compute_flow_features
from .scaler_guard import FrozenReferenceScalerGuard


class FlowRecord:
    """Maintains state and packet deque for a bidirectional network flow."""
    def __init__(self, first_packet: PacketMetadata):
        self.initiator_ip = first_packet.src_ip
        self.responder_ip = first_packet.dst_ip
        self.initiator_port = first_packet.src_port
        self.responder_port = first_packet.dst_port
        self.protocol = first_packet.protocol
        self.created_at = first_packet.timestamp
        self.last_seen_at = first_packet.timestamp
        self.packets: deque = deque(maxlen=2000)
        self.source: str = getattr(first_packet, "source", "live_sniffer")
        
        # Set direction of first packet as Forward (0)
        first_packet.direction = 0
        self.packets.append(first_packet)

    def add_packet(self, pkt: PacketMetadata):
        """Appends an incoming packet, automatically resolving forward/backward direction."""
        self.last_seen_at = pkt.timestamp
        if getattr(pkt, "source", "live_sniffer") == "simulated":
            self.source = "simulated"
        if pkt.src_ip == self.initiator_ip and pkt.src_port == self.initiator_port:
            pkt.direction = 0  # Forward
        else:
            pkt.direction = 1  # Backward
        self.packets.append(pkt)

    def compute_features(self) -> np.ndarray:
        """Computes the 84-feature continuous vector for all buffered packets."""
        return compute_flow_features(list(self.packets))


class RollingFlowBuffer:
    """
    Manages concurrent active flows, window aggregations, and L-step temporal history.
    """

    # ── Flow readiness thresholds (prevents degenerate feature vectors) ──────
    MIN_PACKETS_FOR_EVAL = 4     # Need ≥4 packets for meaningful IAT/bidirectional stats
    MIN_FLOW_AGE_SEC = 0.3       # Flow must exist ≥0.3s to avoid zero-duration vectors
    MIN_NEW_PACKETS_FOR_REEVAL = 2  # Need ≥2 NEW packets since last eval to re-evaluate
    MAX_ZERO_FEATURE_RATIO = 0.85   # Skip if >85% of raw features are exactly zero

    def __init__(self, 
                 window_seconds: float = 1.0, 
                 flow_timeout: float = 15.0,
                 context_length: int = CONTEXT_LENGTH,
                 max_flows: int = 50000):
        self.window_seconds = window_seconds
        self.flow_timeout = flow_timeout
        self.context_length = context_length
        self.max_flows = max_flows
        
        # 5-tuple canonical key -> FlowRecord
        self.active_flows: Dict[Tuple, FlowRecord] = {}
        
        # 5-tuple canonical key -> deque of standardized feature vectors (L=3)
        self.flow_history: Dict[Tuple, deque] = {}
        
        # 5-tuple canonical key -> packet count at last evaluation (prevents re-eval of stale data)
        self._last_eval_pkt_count: Dict[Tuple, int] = {}
        
        # Global state history for host-level continuous trajectory (L=3)
        self.global_history: deque = deque(maxlen=self.context_length)
        
        # Metrics
        self.total_packets_processed = 0
        self.total_flows_created = 0
        self.total_flows_evicted_overflow = 0
        self.total_flows_skipped_immature = 0

    def _evict_oldest_flows(self, count: int = 1000):
        """Evicts oldest idle flows to maintain memory bounds under high-volume flood attacks."""
        if not self.active_flows:
            return
        # Find oldest flows by last_seen_at
        sorted_keys = sorted(self.active_flows.keys(), key=lambda k: self.active_flows[k].last_seen_at)
        for old_key in sorted_keys[:count]:
            self.active_flows.pop(old_key, None)
            self.flow_history.pop(old_key, None)
            self.total_flows_evicted_overflow += 1

    @staticmethod
    def _make_canonical_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> Tuple:
        """
        Creates a direction-invariant 5-tuple key so bidirectional traffic
        for the same socket pair maps to the identical flow record.
        """
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, proto)
        else:
            return (dst_ip, src_ip, dst_port, src_port, proto)

    def ingest_packet(self, pkt: PacketMetadata) -> Tuple:
        """
        Ingests a captured packet into the appropriate flow buffer.
        
        Returns:
            canonical_key: 5-tuple identifying the flow.
        """
        self.total_packets_processed += 1
        key = self._make_canonical_key(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        
        if key not in self.active_flows:
            # Memory safety: bound maximum concurrent flows under attack
            if len(self.active_flows) >= self.max_flows:
                evict_count = max(1, int(self.max_flows * 0.05))
                self._evict_oldest_flows(count=evict_count)
            self.active_flows[key] = FlowRecord(pkt)
            self.total_flows_created += 1
        else:
            self.active_flows[key].add_packet(pkt)
            
        return key

    def get_flow_features(self, key: Tuple) -> Optional[np.ndarray]:
        """Returns the current 84-dimensional feature vector for a specific flow key."""
        flow = self.active_flows.get(key)
        if flow is None:
            return None
        return flow.compute_features()

    def step_window(self, current_time: Optional[float] = None, 
                    scaler_guard: Optional[FrozenReferenceScalerGuard] = None) -> List[Dict[str, Any]]:
        """
        Evaluates active flows, produces 84-dimensional feature vectors,
        updates L=3 temporal sequence buffers, and evicts timed-out flows.

        Flow readiness guards (prevents degenerate false positives):
          1. Minimum packet count (≥4) for meaningful bidirectional statistics
          2. Minimum flow age (≥0.3s) to avoid zero-duration degenerate vectors
          3. Minimum new packets since last eval (≥2) to prevent stale re-evaluation
          4. Raw feature degeneracy check (skip if >85% features are exactly zero)
        
        Returns:
            List of window evaluations: [{
                'flow_key': Tuple,
                'raw_vector': np.ndarray (84,),
                'normalized_vector': np.ndarray (84,),
                'sequence': np.ndarray (L, 84),
                'packet_count': int,
                'duration_sec': float
            }, ...]
        """
        if current_time is None:
            current_time = time.time()

        evaluations = []
        keys_to_remove = []

        for key, flow in list(self.active_flows.items()):
            idle_time = current_time - flow.last_seen_at
            
            # Check if flow has expired
            is_expired = idle_time > self.flow_timeout

            n_pkts = len(flow.packets)
            flow_age = current_time - flow.created_at

            # ── Guard 1: Minimum packet count ────────────────────────────────
            if n_pkts < self.MIN_PACKETS_FOR_EVAL:
                if is_expired:
                    keys_to_remove.append(key)
                continue

            # ── Guard 2: Minimum flow age ────────────────────────────────────
            if flow_age < self.MIN_FLOW_AGE_SEC and not is_expired:
                self.total_flows_skipped_immature += 1
                continue

            # ── Guard 3: Require new packets since last evaluation ───────────
            prev_count = self._last_eval_pkt_count.get(key, 0)
            new_pkts = n_pkts - prev_count
            if new_pkts < self.MIN_NEW_PACKETS_FOR_REEVAL and not is_expired:
                continue

            # Compute features from all buffered packets in this flow
            raw_vec = flow.compute_features()

            # ── Guard 4: Feature degeneracy check ────────────────────────────
            zero_ratio = float(np.count_nonzero(raw_vec == 0.0)) / len(raw_vec)
            if zero_ratio > self.MAX_ZERO_FEATURE_RATIO and not is_expired:
                self.total_flows_skipped_immature += 1
                continue

            # Record that we evaluated at this packet count
            self._last_eval_pkt_count[key] = n_pkts
            
            # Normalize via Frozen Scaler Guard if provided
            if scaler_guard:
                norm_vec = scaler_guard.transform(raw_vec)
            else:
                norm_vec = raw_vec.copy()

            # Update per-flow temporal history (L=3)
            if key not in self.flow_history:
                self.flow_history[key] = deque(maxlen=self.context_length)
            
            self.flow_history[key].append(norm_vec)

            # Construct temporal tensor (L, 84), padding if history < L
            hist = list(self.flow_history[key])
            if len(hist) < self.context_length:
                pad_count = self.context_length - len(hist)
                seq = np.vstack([np.tile(hist[0], (pad_count, 1)), np.array(hist)])
            else:
                seq = np.array(hist)

            evaluations.append({
                "flow_key": key,
                "raw_vector": raw_vec,
                "normalized_vector": norm_vec,
                "sequence": seq,
                "packet_count": n_pkts,
                "duration_sec": max(0.0, flow.last_seen_at - flow.created_at),
                "source": getattr(flow, "source", "live_sniffer"),
            })

            if is_expired:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            self.active_flows.pop(key, None)
            self.flow_history.pop(key, None)
            self._last_eval_pkt_count.pop(key, None)

        return evaluations

    def get_aggregate_host_sequence(self, scaler_guard: Optional[FrozenReferenceScalerGuard] = None) -> np.ndarray:
        """
        Produces a consolidated (1, L, 84) sequence representing aggregate host telemetry.
        If no flows are active, produces a neutral benign baseline sequence.
        """
        if not self.active_flows:
            benign_base = np.zeros(NUM_CANONICAL_FEATURES, dtype=np.float32)
            # Default benign TTL and window
            benign_base[77] = 64.0     # ttl_mean
            benign_base[79] = 65535.0  # tcp_window_mean
            benign_base[80] = 65535.0  # tcp_window_min
            benign_base[81] = 65535.0  # tcp_window_max
            
            norm_vec = scaler_guard.transform(benign_base) if scaler_guard else benign_base
            self.global_history.append(norm_vec)
        else:
            # Average features across active flows
            all_vecs = [f.compute_features() for f in self.active_flows.values() if len(f.packets) > 0]
            if all_vecs:
                agg_raw = np.mean(all_vecs, axis=0)
                norm_vec = scaler_guard.transform(agg_raw) if scaler_guard else agg_raw
                self.global_history.append(norm_vec)

        hist = list(self.global_history)
        while len(hist) < self.context_length:
            hist.insert(0, hist[0] if hist else np.zeros(NUM_CANONICAL_FEATURES, dtype=np.float32))

        # (1, L, 84)
        return np.expand_dims(np.array(hist[-self.context_length:], dtype=np.float32), axis=0)
