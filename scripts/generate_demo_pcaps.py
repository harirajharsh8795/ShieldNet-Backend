"""
ShieldNet — Demo PCAP Generator
================================
Generates 5 realistic .pcap files for offline demonstration.

Usage: python scripts/generate_demo_pcaps.py

Generates:
  demo_test_pcaps/1_normal_https.pcap     — Benign HTTPS traffic
  demo_test_pcaps/2_portscan_nmap.pcap    — Nmap SYN port scan (Reconnaissance)
  demo_test_pcaps/3_slowloris_dos.pcap    — Slowloris HTTP DoS (Impact)
  demo_test_pcaps/4_ssh_patator.pcap      — SSH brute-force (Credential Access)
  demo_test_pcaps/5_bot_c2_beacon.pcap    — Bot C2 heartbeat pattern (C2)

PS Requirement: "parsed using Scapy or PyShark"
"""

import sys
import random
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "demo_test_pcaps"
OUTPUT_DIR.mkdir(exist_ok=True)

try:
    from scapy.all import (
        IP, TCP, UDP, Raw, Ether, wrpcap,
        RandShort, RandIP, Packet
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy not installed. Install with: pip install scapy")
    print("          Generating placeholder PCAP files (binary stubs).")


def _stub_pcap(path: Path, label: str):
    """Write a minimal valid PCAP file stub when Scapy is unavailable."""
    # PCAP global header: magic, major, minor, GMT offset, accuracy, snaplen, link type
    import struct
    header = struct.pack("<IHHiIII",
        0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # Ethernet link type
    path.write_bytes(header)
    print(f"  [STUB] {path.name} ({label})")


def generate_normal_https(out_path: Path, n_packets: int = 80):
    """Simulate benign HTTPS (TLS) traffic: ClientHello → ServerHello → Data."""
    if not SCAPY_AVAILABLE:
        return _stub_pcap(out_path, "Benign HTTPS")

    pkts = []
    client_ip = "192.168.1.105"
    server_ip = "172.217.14.196"  # Simulated Google IP

    for i in range(n_packets):
        sport = random.randint(49152, 65535)
        # Simulate TLS-like TCP stream
        syn = Ether() / IP(src=client_ip, dst=server_ip, ttl=64) / \
              TCP(sport=sport, dport=443, flags="S", seq=1000+i, window=65535)
        pkts.append(syn)

        syn_ack = Ether() / IP(src=server_ip, dst=client_ip, ttl=52) / \
                  TCP(sport=443, dport=sport, flags="SA", seq=2000+i, ack=1001+i, window=8192)
        pkts.append(syn_ack)

        # Data (payload simulates TLS application data)
        payload = bytes(random.randint(0, 255) for _ in range(random.randint(100, 1400)))
        data = Ether() / IP(src=client_ip, dst=server_ip, ttl=64) / \
               TCP(sport=sport, dport=443, flags="PA", seq=1001+i, ack=2001+i) / Raw(load=payload)
        pkts.append(data)

    wrpcap(str(out_path), pkts)
    print(f"  [OK] {out_path.name} — {len(pkts)} packets (Benign HTTPS)")


def generate_portscan(out_path: Path, n_ports: int = 150):
    """Simulate Nmap-style TCP SYN port scan (Reconnaissance stage)."""
    if not SCAPY_AVAILABLE:
        return _stub_pcap(out_path, "PortScan - Nmap SYN")

    pkts = []
    attacker_ip = "10.0.0.99"
    target_ip   = "192.168.10.50"

    # Sequential SYN sweep across common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                    465, 587, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
    ports = common_ports + list(range(1024, 1024 + n_ports - len(common_ports)))

    for port in ports[:n_ports]:
        sport = random.randint(49152, 65535)
        # SYN probe
        syn = Ether() / IP(src=attacker_ip, dst=target_ip, ttl=random.randint(60, 128)) / \
              TCP(sport=sport, dport=port, flags="S", seq=random.randint(1000, 99999), window=1024)
        pkts.append(syn)

        # RST/ACK response (closed port) or SYN-ACK (open port, ~10% chance)
        if random.random() < 0.1:
            sa = Ether() / IP(src=target_ip, dst=attacker_ip, ttl=64) / \
                 TCP(sport=port, dport=sport, flags="SA", seq=random.randint(1000, 99999), ack=syn[TCP].seq+1)
            pkts.append(sa)
        else:
            rst = Ether() / IP(src=target_ip, dst=attacker_ip, ttl=64) / \
                  TCP(sport=port, dport=sport, flags="RA", seq=0, ack=syn[TCP].seq+1)
            pkts.append(rst)

    wrpcap(str(out_path), pkts)
    print(f"  [OK] {out_path.name} — {len(pkts)} packets (PortScan / Nmap SYN sweep)")


def generate_slowloris(out_path: Path, n_connections: int = 30):
    """Simulate Slowloris DoS: partial HTTP headers to stall server sockets."""
    if not SCAPY_AVAILABLE:
        return _stub_pcap(out_path, "Slowloris DoS")

    pkts = []
    target_ip = "192.168.10.50"
    # Many source IPs (distributed variant)
    attacker_ips = [f"10.0.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(n_connections)]

    for i, src_ip in enumerate(attacker_ips):
        sport = random.randint(49152, 65535)
        seq = random.randint(10000, 999999)

        # TCP 3-way handshake
        syn = Ether() / IP(src=src_ip, dst=target_ip, ttl=64) / \
              TCP(sport=sport, dport=80, flags="S", seq=seq, window=65535)
        pkts.append(syn)
        sa  = Ether() / IP(src=target_ip, dst=src_ip, ttl=64) / \
              TCP(sport=80, dport=sport, flags="SA", seq=seq+10000, ack=seq+1)
        pkts.append(sa)
        ack = Ether() / IP(src=src_ip, dst=target_ip, ttl=64) / \
              TCP(sport=sport, dport=80, flags="A", seq=seq+1, ack=seq+10001)
        pkts.append(ack)

        # Partial HTTP request (Slowloris pattern: incomplete headers with Keep-Alive)
        partial_header = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nX-Keep-Alive: {i*13}\r\n"
        data = Ether() / IP(src=src_ip, dst=target_ip, ttl=64) / \
               TCP(sport=sport, dport=80, flags="PA", seq=seq+1, ack=seq+10001) / \
               Raw(load=partial_header.encode())
        pkts.append(data)

        # Dribble more partial headers every ~10 packets to keep socket alive
        for _ in range(random.randint(5, 15)):
            drip = Ether() / IP(src=src_ip, dst=target_ip, ttl=64) / \
                   TCP(sport=sport, dport=80, flags="PA", seq=seq+1+len(partial_header), ack=seq+10001) / \
                   Raw(load=b"X-Padding: " + bytes(random.randint(32,90) for _ in range(8)) + b"\r\n")
            pkts.append(drip)

    wrpcap(str(out_path), pkts)
    print(f"  [OK] {out_path.name} — {len(pkts)} packets (Slowloris DoS — partial HTTP headers)")


def generate_ssh_bruteforce(out_path: Path, n_attempts: int = 50):
    """Simulate SSH brute-force (FTP/SSH Patator pattern): rapid auth failures."""
    if not SCAPY_AVAILABLE:
        return _stub_pcap(out_path, "SSH Brute Force")

    pkts = []
    attacker_ip = "172.16.0.77"
    target_ip   = "192.168.10.50"

    for i in range(n_attempts):
        sport = random.randint(49152, 65535)
        seq   = random.randint(10000, 999999)

        # TCP connect to SSH port 22
        syn = Ether() / IP(src=attacker_ip, dst=target_ip, ttl=64) / \
              TCP(sport=sport, dport=22, flags="S", seq=seq, window=65535)
        pkts.append(syn)

        sa = Ether() / IP(src=target_ip, dst=attacker_ip, ttl=64) / \
             TCP(sport=22, dport=sport, flags="SA", seq=seq+1000, ack=seq+1, window=8192)
        pkts.append(sa)

        ack = Ether() / IP(src=attacker_ip, dst=target_ip, ttl=64) / \
              TCP(sport=sport, dport=22, flags="A", seq=seq+1, ack=seq+1001)
        pkts.append(ack)

        # SSH banner exchange (SSH-2.0-OpenSSH_8.4)
        banner = b"SSH-2.0-OpenSSH_8.4p1 Ubuntu\r\n"
        srv_banner = Ether() / IP(src=target_ip, dst=attacker_ip, ttl=64) / \
                     TCP(sport=22, dport=sport, flags="PA") / Raw(load=banner)
        pkts.append(srv_banner)

        # Client sends auth attempt (simulated key exchange blob)
        auth_payload = bytes([0x00]*4 + [random.randint(0,255) for _ in range(random.randint(40,120))])
        auth = Ether() / IP(src=attacker_ip, dst=target_ip, ttl=64) / \
               TCP(sport=sport, dport=22, flags="PA") / Raw(load=auth_payload)
        pkts.append(auth)

        # Server rejects (RST or short auth fail response)
        rst = Ether() / IP(src=target_ip, dst=attacker_ip, ttl=64) / \
              TCP(sport=22, dport=sport, flags="RA")
        pkts.append(rst)

    wrpcap(str(out_path), pkts)
    print(f"  [OK] {out_path.name} — {len(pkts)} packets (SSH Brute Force — {n_attempts} auth attempts)")


def generate_bot_c2_beacon(out_path: Path, n_beacons: int = 40):
    """Simulate Ares/Mirai Bot C2 heartbeat pattern: regular HTTP POSTs to C2 server."""
    if not SCAPY_AVAILABLE:
        return _stub_pcap(out_path, "Bot C2 Beacon")

    pkts = []
    bot_ip = "192.168.10.8"
    c2_ip  = "185.220.101.45"  # Simulated dark-web C2 IP

    for i in range(n_beacons):
        sport = random.randint(49152, 65535)
        seq   = random.randint(10000, 999999)

        # TCP connect
        syn = Ether() / IP(src=bot_ip, dst=c2_ip, ttl=64) / \
              TCP(sport=sport, dport=8080, flags="S", seq=seq, window=65535)
        pkts.append(syn)

        sa = Ether() / IP(src=c2_ip, dst=bot_ip, ttl=48) / \
             TCP(sport=8080, dport=sport, flags="SA", seq=seq+5000, ack=seq+1)
        pkts.append(sa)

        ack = Ether() / IP(src=bot_ip, dst=c2_ip, ttl=64) / \
              TCP(sport=sport, dport=8080, flags="A", seq=seq+1, ack=seq+5001)
        pkts.append(ack)

        # HTTP POST heartbeat (mimics Ares C2 protocol)
        c2_payload = (
            f"POST /gate.php HTTP/1.1\r\n"
            f"Host: {c2_ip}:8080\r\n"
            f"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 32\r\n\r\n"
            f"uid={i:08x}&status=alive&key={random.randint(0,0xffff):04x}"
        ).encode()

        post = Ether() / IP(src=bot_ip, dst=c2_ip, ttl=64) / \
               TCP(sport=sport, dport=8080, flags="PA", seq=seq+1, ack=seq+5001) / \
               Raw(load=c2_payload)
        pkts.append(post)

        # C2 response (short command or empty ack)
        cmd_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nNOOP"
        resp = Ether() / IP(src=c2_ip, dst=bot_ip, ttl=48) / \
               TCP(sport=8080, dport=sport, flags="PA", seq=seq+5001, ack=seq+1+len(c2_payload)) / \
               Raw(load=cmd_payload)
        pkts.append(resp)

        # Connection teardown
        fin = Ether() / IP(src=bot_ip, dst=c2_ip, ttl=64) / \
              TCP(sport=sport, dport=8080, flags="FA")
        pkts.append(fin)

    wrpcap(str(out_path), pkts)
    print(f"  [OK] {out_path.name} — {len(pkts)} packets (Bot C2 Heartbeat — {n_beacons} beacons)")


def main():
    print("=" * 60)
    print("  ShieldNet Demo PCAP Generator")
    print("  PS-26153 | Scapy-based (Offline)")
    print("=" * 60)
    print(f"  Output directory: {OUTPUT_DIR}\n")

    if not SCAPY_AVAILABLE:
        print("  [!] Scapy not found. Writing minimal placeholder stubs.")
        print("      Install Scapy: pip install scapy")
        print()

    generate_normal_https(OUTPUT_DIR / "1_normal_https.pcap")
    generate_portscan(OUTPUT_DIR / "2_portscan_nmap.pcap")
    generate_slowloris(OUTPUT_DIR / "3_slowloris_dos.pcap")
    generate_ssh_bruteforce(OUTPUT_DIR / "4_ssh_patator.pcap")
    generate_bot_c2_beacon(OUTPUT_DIR / "5_bot_c2_beacon.pcap")

    print(f"\n  Done! Generated 5 demo PCAPs in: {OUTPUT_DIR}")
    print("  Upload any of these to the ShieldNet dashboard to demo the system.")
    print()
    print("  Expected detections:")
    print("    1_normal_https.pcap   -> BENIGN (low threat probability)")
    print("    2_portscan_nmap.pcap  -> PortScan / Reconnaissance")
    print("    3_slowloris_dos.pcap  -> DoS slowloris / Impact")
    print("    4_ssh_patator.pcap    -> SSH-Patator / Credential Access")
    print("    5_bot_c2_beacon.pcap  -> Bot / Command & Control")


if __name__ == "__main__":
    main()
