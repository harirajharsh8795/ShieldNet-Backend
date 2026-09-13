"""
ShieldNet Traffic & Cyberattack Simulator.

Generates realistic network traffic patterns for offline daemon demonstration:
1. Benign Web & DNS Browsing (HTTPS/HTTP handshakes, normal IAT & TTL)
2. PortScan Reconnaissance (Rapid SYN+RST bursts from ONE src_port, many dst_ports)
3. DDoS SYN Flood (High-rate packet saturation from fixed attacker IP)
4. Botnet C2 Beaconing (Periodic heartbeat + C2 server responses)
5. SSH Brute-Force (Repeated auth attempts on single dst_port, with challenge responses)

IMPORTANT — Flow Aggregation Design:
  The model was trained on CIC-IDS-2017 bidirectional FLOW features.
  A "flow" in this context is identified by a canonical 5-tuple
  (src_ip, dst_ip, src_port, dst_port, proto). All packets in one
  scenario MUST use the same canonical 5-tuple to aggregate into a
  single flow with statistically rich features (IAT distributions,
  flag counts, byte ratios, etc.).

  Using different dst_ports per probe (naive port scan) creates N
  separate 2-packet micro-flows, each producing a degenerate feature
  vector that the model cannot distinguish from benign traffic.

  Solution: every generator produces packets on a single canonical
  5-tuple. The statistical SHAPE of the IAT/flag/byte distributions
  still encodes the attack character without fragmenting into micro-flows.
"""

from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
import argparse
import logging
import random
import sys
import time

# Ensure project root is on sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from shared.schema import ATTACK_CLASSES, MITRE_STAGES
from shared.feature_extractor import PacketMetadata

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("TrafficSimulator")


def _pkt(
    t: float,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    direction: int,
    flags: int,
    total_len: int,
    payload: int,
    header: int,
    window: int = 65535,
    ttl: int = 64,
    seq: int = 0,
    ack: int = 0,
    proto: int = 6,
    source: str = "simulated",
) -> PacketMetadata:
    """Helper: build a PacketMetadata with provenance tag."""
    return PacketMetadata(
        timestamp=t,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        total_length=total_len,
        payload_length=payload,
        header_length=header,
        direction=direction,
        tcp_flags=flags,
        tcp_window=window,
        seq_num=seq,
        ack_num=ack,
        ttl=ttl,
        source=source,
    )


def generate_benign_traffic(
    num_packets: int = 50,
    src_ip: str = "192.168.1.105",
    dst_ip: str = "142.250.190.46",
    dst_port: int = 443,
    start_time: Optional[float] = None,
) -> List[PacketMetadata]:
    """
    Generates realistic benign HTTPS session traffic.

    Single flow: src_ip:src_port <-> dst_ip:443 (TCP)
    Characteristics:
    - Normal IAT (20–80 ms)
    - Standard TCP handshake (SYN -> SYN-ACK -> ACK)
    - Large bidirectional data exchange (TLS application data)
    - Symmetric forward/backward ratio
    - TTL 128 (forward), TTL 64 (backward)
    """
    t = start_time if start_time is not None else time.time()
    src_port = random.randint(49152, 65535)
    packets: List[PacketMetadata] = []

    # 1. TCP SYN
    packets.append(_pkt(t, src_ip, dst_ip, src_port, dst_port, 0, 0x02, 60, 0, 60,
                        window=65535, ttl=128, seq=1000, ack=0))
    t += 0.015
    # 2. SYN-ACK
    packets.append(_pkt(t, dst_ip, src_ip, dst_port, src_port, 1, 0x12, 60, 0, 60,
                        window=65535, ttl=64, seq=5000, ack=1001))
    t += 0.005
    # 3. ACK
    packets.append(_pkt(t, src_ip, dst_ip, src_port, dst_port, 0, 0x10, 52, 0, 52,
                        window=65535, ttl=128, seq=1001, ack=5001))

    # 4. TLS bidirectional data exchange
    seq_fwd, seq_bwd = 1001, 5001
    for i in range(max(1, num_packets - 3)):
        t += random.uniform(0.020, 0.080)
        direction = 0 if random.random() < 0.55 else 1
        payload = random.randint(200, 1400)
        tot_len = payload + 52

        if direction == 0:
            packets.append(_pkt(t, src_ip, dst_ip, src_port, dst_port, 0, 0x18, tot_len, payload, 52,
                                window=65535, ttl=128, seq=seq_fwd, ack=seq_bwd))
            seq_fwd += payload
        else:
            packets.append(_pkt(t, dst_ip, src_ip, dst_port, src_port, 1, 0x18, tot_len, payload, 52,
                                window=65535, ttl=64, seq=seq_bwd, ack=seq_fwd))
            seq_bwd += payload

    logger.debug("Benign: %d packets, 1 flow (src_port=%d -> dst_port=%d)", len(packets), src_port, dst_port)
    return packets


def generate_portscan_attack(
    num_packets: int = 80,
    src_ip: str = "10.0.0.99",
    dst_ip: str = "192.168.1.10",
    start_time: Optional[float] = None,
) -> List[PacketMetadata]:
    """
    Generates rapid TCP reconnaissance (SYN scan) in a SINGLE aggregated flow.

    Single flow: src_ip:SRC_PORT <-> dst_ip:80 (TCP)
    Packets alternate between:
    - Forward SYN probes (attacker -> target, rapid bursts, tiny IAT)
    - Backward RST-ACK (target -> attacker, closed port, ~100µs later)

    CIC-IDS-2017 PortScan signature features this produces:
    - Very high Flow Packets/s (> 2000)
    - Tiny Flow IAT Mean (< 1000 µs)
    - High SYN Flag Count
    - High RST Flag Count (closed port responses)
    - Near-zero payload (reconnaissance probes)
    - TTL=48 on forward probes (distinct scanner TTL)
    - Down/Up Ratio ~1.0 (attacker sends probe, target replies RST)
    """
    t = start_time if start_time is not None else time.time()
    packets: List[PacketMetadata] = []
    src_port = 54321   # Fixed src_port — all probes share the same 5-tuple
    dst_port = 80      # Fixed dst_port for single-flow aggregation
    seq = 100000

    for i in range(num_packets // 2):
        t += random.uniform(0.00008, 0.00030)  # 80–300 µs between probes

        # Forward: SYN probe from attacker
        packets.append(_pkt(t, src_ip, dst_ip, src_port, dst_port, 0, 0x02, 60, 0, 60,
                            window=1024, ttl=48, seq=seq + i, ack=0))
        # Backward: RST-ACK from victim (closed port, +50–120 µs)
        t += random.uniform(0.00005, 0.00012)
        packets.append(_pkt(t, dst_ip, src_ip, dst_port, src_port, 1, 0x14, 40, 0, 40,
                            window=0, ttl=64, seq=0, ack=seq + i + 1))

    logger.debug("PortScan: %d packets, 1 flow (%s:%d -> %s:%d)", len(packets), src_ip, src_port, dst_ip, dst_port)
    return packets


def generate_ddos_synflood(
    num_packets: int = 100,
    target_ip: str = "192.168.1.10",
    target_port: int = 80,
    attacker_ip: str = "10.0.0.88",
    start_time: Optional[float] = None,
) -> List[PacketMetadata]:
    """
    Generates high-velocity DDoS SYN flood — single fixed-IP flow.

    Single flow: attacker_ip:SRC_PORT -> target_ip:target_port (TCP)
    DDoS is fundamentally UNIDIRECTIONAL (spoofed IPs never get responses).
    All packets are forward-direction.

    CIC-IDS-2017 DDoS signature features:
    - Extreme Flow Packets/s (> 5000)
    - Tiny Flow IAT (50–200 µs)
    - All SYN or PSH-ACK flags
    - Down/Up Ratio = 0 (zero backward packets)
    - Total Backward Packets = 0
    - Tiny TCP window (512) — common in flood tools
    """
    t = start_time if start_time is not None else time.time()
    packets: List[PacketMetadata] = []
    src_port = 45678  # Fixed src_port — single flow

    for i in range(num_packets):
        t += random.uniform(0.00004, 0.00018)  # 40–180 µs
        flag = 0x02 if i % 3 != 0 else 0x18   # 2/3 SYN, 1/3 PSH-ACK

        packets.append(_pkt(t, attacker_ip, target_ip, src_port, target_port, 0, flag,
                            64, 0, 64, window=512, ttl=48, seq=i * 500, ack=0))

    logger.debug("DDoS: %d packets, 1 flow (%s:%d -> %s:%d)",
                 len(packets), attacker_ip, src_port, target_ip, target_port)
    return packets


def generate_botnet_c2(
    num_beacons: int = 25,
    bot_ip: str = "192.168.1.105",
    c2_ip: str = "185.220.101.5",
    c2_port: int = 4444,
    beacon_interval: float = 0.5,
    start_time: Optional[float] = None,
) -> List[PacketMetadata]:
    """
    Generates periodic C2 beacon pulses WITH server responses.

    Single flow: bot_ip:52140 <-> c2_ip:c2_port (TCP)

    CIC-IDS-2017 Bot/C2 signature features:
    - Periodic IAT equal to beacon_interval (rigid timing = machine-like)
    - Constant-size forward payload (32-byte encrypted heartbeat)
    - C2 server replies with small variable-size commands
    - Low Flow Packets/s (< 5 pps)
    - TTL=38 on outbound (abnormal static TTL — Tor exit / VPN)
    - Down/Up Ratio ~1.0
    """
    t = start_time if start_time is not None else time.time()
    bot_port = 52140
    packets: List[PacketMetadata] = []
    seq_bot, seq_c2 = 10000, 80000

    for i in range(num_beacons):
        t += beacon_interval  # Perfectly periodic heartbeat

        # Forward: Bot -> C2 beacon
        packets.append(_pkt(t, bot_ip, c2_ip, bot_port, c2_port, 0, 0x18, 84, 32, 52,
                            window=8192, ttl=38, seq=seq_bot, ack=seq_c2))
        seq_bot += 32

        # Backward: C2 -> Bot command (+20–60 ms RTT)
        t += random.uniform(0.020, 0.060)
        cmd_payload = random.randint(8, 24)
        packets.append(_pkt(t, c2_ip, bot_ip, c2_port, bot_port, 1, 0x18, cmd_payload + 52, cmd_payload, 52,
                            window=65535, ttl=64, seq=seq_c2, ack=seq_bot))
        seq_c2 += cmd_payload

    logger.debug("BotC2: %d packets, 1 flow (%s -> %s:%d)", len(packets), bot_ip, c2_ip, c2_port)
    return packets


def generate_bruteforce_ssh(
    num_attempts: int = 30,
    attacker_ip: str = "10.0.0.50",
    target_ip: str = "192.168.1.20",
    target_port: int = 22,
    start_time: Optional[float] = None,
) -> List[PacketMetadata]:
    """
    Generates SSH brute-force authentication attempts — single aggregated flow.

    Single flow: attacker_ip:SRC_PORT <-> target_ip:22 (TCP)
    Uses a fixed source port so all attempts are aggregated into one flow.
    Within each attempt: SYN -> SYN-ACK -> ACK -> SSH banner -> RST.

    CIC-IDS-2017 SSH-Patator signature features:
    - Medium packet rate (200–500 ms IAT between attempts)
    - High RST Flag Count (auth rejected, attacker resets)
    - High SYN Flag Count (reconnect per attempt)
    - Short bidirectional payload (53-byte SSH banner exchange)
    - Down/Up Ratio ~0.5
    """
    t = start_time if start_time is not None else time.time()
    packets: List[PacketMetadata] = []
    src_port = 41000   # Fixed src_port — all attempts in one flow
    seq_atk = 200000

    for i in range(num_attempts):
        t += random.uniform(0.180, 0.450)  # 180–450 ms between attempts

        # SYN
        packets.append(_pkt(t, attacker_ip, target_ip, src_port, target_port, 0, 0x02, 60, 0, 60,
                            window=29200, ttl=64, seq=seq_atk, ack=0))
        t += 0.006
        # SYN-ACK
        seq_srv = 9000000 + i * 1000
        packets.append(_pkt(t, target_ip, attacker_ip, target_port, src_port, 1, 0x12, 60, 0, 60,
                            window=65535, ttl=64, seq=seq_srv, ack=seq_atk + 1))
        t += 0.006
        # ACK
        packets.append(_pkt(t, attacker_ip, target_ip, src_port, target_port, 0, 0x10, 52, 0, 52,
                            window=29200, ttl=64, seq=seq_atk + 1, ack=seq_srv + 1))
        t += 0.012
        # SSH Banner from server (53 bytes)
        packets.append(_pkt(t, target_ip, attacker_ip, target_port, src_port, 1, 0x18, 105, 53, 52,
                            window=65535, ttl=64, seq=seq_srv + 1, ack=seq_atk + 1))
        t += random.uniform(0.005, 0.025)
        # RST from attacker (failed auth, reset)
        packets.append(_pkt(t, attacker_ip, target_ip, src_port, target_port, 0, 0x04, 40, 0, 40,
                            window=0, ttl=64, seq=seq_atk + 1, ack=0))
        seq_atk += 1000

    logger.debug("BruteForce: %d packets, 1 flow (%s -> %s:%d)", len(packets), attacker_ip, target_ip, target_port)
    return packets


def run_simulation(scenario: str, target_daemon: bool = False, count: int = 50):
    """Executes traffic simulation and optionally injects into running daemon."""
    logger.info("Initializing traffic simulation: scenario='%s', count=%d", scenario, count)

    generators = {
        "benign":   lambda: generate_benign_traffic(num_packets=count),
        "portscan": lambda: generate_portscan_attack(num_packets=count),
        "ddos":     lambda: generate_ddos_synflood(num_packets=count),
        "bot":      lambda: generate_botnet_c2(num_beacons=max(10, count // 2)),
        "brute":    lambda: generate_bruteforce_ssh(num_attempts=max(10, count // 4)),
    }

    if scenario == "all":
        packets = []
        for name, gen in generators.items():
            logger.info("Generating scenario: %s", name)
            packets.extend(gen())
    elif scenario in generators:
        packets = generators[scenario]()
    else:
        logger.error("Unknown scenario '%s'. Available: benign, portscan, ddos, bot, brute, all", scenario)
        return

    logger.info("Generated %d synthetic packets successfully.", len(packets))

    if target_daemon:
        from daemon.ipc_bridge import IPCClient
        token_file = PROJECT_DIR / "data" / ".ipc_token"

        try:
            client = IPCClient(token_path=token_file)
            resp = client.inject_packets(packets)
            if resp.get("status") == "ok":
                logger.info(
                    "[IPC] Successfully injected %d packets into running daemon (provenance: simulated, queue: %d).",
                    resp.get("accepted", len(packets)),
                    resp.get("queue_size", 0),
                )
            else:
                logger.error("[IPC] Daemon returned error: %s", resp.get("error", "Unknown error"))
        except (ConnectionRefusedError, ConnectionError, FileNotFoundError, OSError) as exc:
            logger.warning(
                "[IPC] Could not connect to running daemon on 127.0.0.1:49152 (%s). "
                "Ensure the daemon is running in demo mode: "
                "'shieldnet daemon run --mock --enable-ipc' (or python cli.py daemon run --mock --enable-ipc).",
                exc,
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShieldNet Cyberattack & Traffic Simulator")
    parser.add_argument(
        "--scenario",
        choices=["benign", "portscan", "ddos", "bot", "brute", "all"],
        default="portscan",
        help="Traffic scenario to generate (default: portscan)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=80,
        help="Number of packets to simulate (default: 80)",
    )
    parser.add_argument(
        "--target-daemon",
        action="store_true",
        help="Inject packets directly into ShieldNet daemon",
    )
    args = parser.parse_args()

    run_simulation(scenario=args.scenario, target_daemon=args.target_daemon, count=args.count)
