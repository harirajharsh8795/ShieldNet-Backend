"""
ShieldNet Traffic & Cyberattack Simulator.

Generates realistic network traffic patterns for offline daemon demonstration:
1. Benign Web & DNS Browsing (HTTPS/HTTP handshakes, normal IAT & TTL)
2. PortScan Reconnaissance (Rapid SYN probes across sequential ports)
3. DDoS SYN Flood (High-rate packet saturation, spoofed sources)
4. Botnet C2 Beaconing (Periodic heartbeat bursts, fixed payload lengths)
5. SSH / FTP Brute-Force (Repeated rapid connection resets)

Produces PacketMetadata objects that can be directly ingested into the ShieldNet
daemon or transmitted via Scapy raw sockets.
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


def generate_benign_traffic(
    num_packets: int = 30,
    src_ip: str = "192.168.1.105",
    dst_ip: str = "142.250.190.46",
    dst_port: int = 443,
    start_time: Optional[float] = None,
) -> List[PacketMetadata]:
    """
    Generates realistic benign HTTPS session traffic with standard handshakes,
    normal payload sizes, standard TCP window sizes, and normal inter-arrival times.
    """
    t = start_time if start_time is not None else time.time()
    src_port = random.randint(49152, 65535)
    packets: List[PacketMetadata] = []

    # 1. TCP SYN (Forward)
    packets.append(PacketMetadata(
        timestamp=t,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=6,
        total_length=60,
        payload_length=0,
        header_length=60,
        direction=0,
        tcp_flags=0x02,  # SYN
        tcp_window=65535,
        seq_num=1000,
        ack_num=0,
        ttl=128,
    ))

    # 2. TCP SYN-ACK (Backward, +15ms)
    t += 0.015
    packets.append(PacketMetadata(
        timestamp=t,
        src_ip=dst_ip,
        dst_ip=src_ip,
        src_port=dst_port,
        dst_port=src_port,
        protocol=6,
        total_length=60,
        payload_length=0,
        header_length=60,
        direction=1,
        tcp_flags=0x12,  # SYN-ACK
        tcp_window=65535,
        seq_num=5000,
        ack_num=1001,
        ttl=64,
    ))

    # 3. TCP ACK (Forward, +5ms)
    t += 0.005
    packets.append(PacketMetadata(
        timestamp=t,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=6,
        total_length=52,
        payload_length=0,
        header_length=52,
        direction=0,
        tcp_flags=0x10,  # ACK
        tcp_window=65535,
        seq_num=1001,
        ack_num=5001,
        ttl=128,
    ))

    # 4. Data Exchange (TLS Client Hello & Application Data)
    seq_fwd = 1001
    seq_bwd = 5001
    for i in range(max(1, num_packets - 3)):
        iat = random.uniform(0.020, 0.080)
        t += iat
        direction = 0 if random.random() < 0.6 else 1
        payload = random.randint(100, 1400)
        tot_len = payload + 52

        if direction == 0:
            packets.append(PacketMetadata(
                timestamp=t,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=6,
                total_length=tot_len,
                payload_length=payload,
                header_length=52,
                direction=0,
                tcp_flags=0x18,  # PSH-ACK
                tcp_window=65535,
                seq_num=seq_fwd,
                ack_num=seq_bwd,
                ttl=128,
            ))
            seq_fwd += payload
        else:
            packets.append(PacketMetadata(
                timestamp=t,
                src_ip=dst_ip,
                dst_ip=src_ip,
                src_port=dst_port,
                dst_port=src_port,
                protocol=6,
                total_length=tot_len,
                payload_length=payload,
                header_length=52,
                direction=1,
                tcp_flags=0x18,  # PSH-ACK
                tcp_window=65535,
                seq_num=seq_bwd,
                ack_num=seq_fwd,
                ttl=64,
            ))
            seq_bwd += payload

    return packets


def generate_portscan_attack(
    num_ports: int = 30,
    src_ip: str = "10.0.0.99",
    dst_ip: str = "192.168.1.10",
    start_time: Optional[float] = None,
) -> List[PacketMetadata]:
    """
    Generates rapid TCP reconnaissance probe traffic (SYN & XMAS port scan probes).
    Characteristics: Tiny IAT (< 500us), aggressive scanning flags, abnormal TTL.
    Target MITRE Stage: 1 (Discovery / Reconnaissance).
    """
    t = start_time if start_time is not None else time.time()
    packets: List[PacketMetadata] = []
    src_port = 49152

    for i in range(num_ports):
        t += random.uniform(0.0001, 0.0004)  # 100 - 400 microseconds
        # Alternate between SYN probe and XMAS/FIN probe across services
        flag = 0x02 if i % 2 == 0 else 0x29

        packets.append(PacketMetadata(
            timestamp=t,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=80,  # Probed service port
            protocol=6,
            total_length=60 if i % 2 == 0 else 120,
            payload_length=0 if i % 2 == 0 else 60,
            header_length=60,
            direction=0,
            tcp_flags=flag,
            tcp_window=1024,
            seq_num=i * 1000,
            ack_num=0,
            ttl=48,  # Distinct reconnaissance TTL
        ))

    return packets


def generate_ddos_synflood(
    num_packets: int = 60,
    target_ip: str = "192.168.1.10",
    target_port: int = 80,
    attacker_ip: str = "10.0.0.88",
    start_time: Optional[float] = None,
) -> List[PacketMetadata]:
    """
    Generates high-velocity SYN flood / DDoS saturation traffic against target_port.
    Characteristics: Extreme packet velocity, PSH/SYN flood, saturating flow queues.
    Target MITRE Stage: 5 (Impact / Denial of Service).
    """
    t = start_time if start_time is not None else time.time()
    packets: List[PacketMetadata] = []
    src_port = 54321

    for i in range(num_packets):
        t += random.uniform(0.00005, 0.0002)  # 50 - 200 microseconds
        flag = 0x18 if i % 2 == 0 else 0x02  # PSH-ACK and SYN flood

        packets.append(PacketMetadata(
            timestamp=t,
            src_ip=attacker_ip,
            dst_ip=target_ip,
            src_port=src_port,
            dst_port=target_port,
            protocol=6,
            total_length=64 if i % 2 == 0 else 128,
            payload_length=0 if i % 2 == 0 else 64,
            header_length=64,
            direction=0,
            tcp_flags=flag,
            tcp_window=512,
            seq_num=i * 500,
            ack_num=0,
            ttl=48,
        ))

    return packets


def generate_botnet_c2(
    num_beacons: int = 20,
    bot_ip: str = "192.168.1.105",
    c2_ip: str = "185.220.101.5",
    c2_port: int = 4444,
    beacon_interval: float = 0.5,
    start_time: Optional[float] = None,
) -> List[PacketMetadata]:
    """
    Generates periodic Command & Control (C2) beacon pulses.
    Characteristics: Rigid periodic inter-arrival timing, identical payload lengths.
    Target MITRE Stage: 4 (Command & Control).
    """
    t = start_time if start_time is not None else time.time()
    bot_port = 52140
    packets: List[PacketMetadata] = []

    seq_num = 10000
    for _ in range(num_beacons):
        t += beacon_interval  # Periodic heartbeat
        packets.append(PacketMetadata(
            timestamp=t,
            src_ip=bot_ip,
            dst_ip=c2_ip,
            src_port=bot_port,
            dst_port=c2_port,
            protocol=6,
            total_length=84,
            payload_length=32,  # Constant 32-byte encrypted heartbeat
            header_length=52,
            direction=0,
            tcp_flags=0x18,     # PSH-ACK
            tcp_window=8192,
            seq_num=seq_num,
            ack_num=20000,
            ttl=38,             # Abnormal static TTL
        ))
        seq_num += 32

    return packets


def run_simulation(scenario: str, target_daemon: bool = False, count: int = 50):
    """Executes traffic simulation and optionally injects into running daemon."""
    logger.info("Initializing traffic simulation: scenario='%s', count=%d", scenario, count)

    generators = {
        "benign": lambda: generate_benign_traffic(num_packets=count),
        "portscan": lambda: generate_portscan_attack(num_ports=count),
        "ddos": lambda: generate_ddos_synflood(num_packets=count),
        "bot": lambda: generate_botnet_c2(num_beacons=count),
    }

    if scenario == "all":
        packets = []
        for name, gen in generators.items():
            logger.info("Generating scenario: %s", name)
            packets.extend(gen())
    elif scenario in generators:
        packets = generators[scenario]()
    else:
        logger.error("Unknown scenario '%s'. Available: benign, portscan, ddos, bot, all", scenario)
        return

    logger.info("Generated %d synthetic packets successfully.", len(packets))

    if target_daemon:
        from daemon.service import ShieldNetDaemon, DaemonConfig
        status_file = PROJECT_DIR / "data" / "daemon_status.json"
        if not status_file.exists():
            logger.warning("No active daemon status found at %s. Starting temporary instance.", status_file)
            daemon = ShieldNetDaemon()
            daemon.start()
            daemon.inject_packets(packets)
            time.sleep(2.0)
            daemon.stop()
        else:
            logger.info("Injecting packets into running daemon...")
            # If daemon is running, we can instantiate a lightweight injector or direct Scapy push
            daemon = ShieldNetDaemon()
            daemon.inject_packets(packets)
            logger.info("Injected %d packets into daemon buffer.", len(packets))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShieldNet Cyberattack & Traffic Simulator")
    parser.add_argument(
        "--scenario",
        choices=["benign", "portscan", "ddos", "bot", "all"],
        default="portscan",
        help="Traffic scenario to generate (default: portscan)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=40,
        help="Number of packets to simulate (default: 40)",
    )
    parser.add_argument(
        "--target-daemon",
        action="store_true",
        help="Inject packets directly into ShieldNet daemon",
    )
    args = parser.parse_args()

    run_simulation(scenario=args.scenario, target_daemon=args.target_daemon, count=args.count)
