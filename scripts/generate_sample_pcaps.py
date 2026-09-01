"""
Generates valid libpcap binary files (.pcap) using pure Python struct.
Creates:
1. sample_enterprise_capture.pcap (Enterprise Web & SSH telemetry)
2. sample_scada_modbus.pcap (SCADA / CII Modbus Port 502 telemetry)
"""

import struct
import time
from pathlib import Path
import shutil

def create_pcap(filepath: Path, packets: list):
    """
    Writes a standard libpcap 2.4 file.
    Global Header (24 bytes):
    magic_number (4B) = 0xa1b2c3d4
    version_major (2B) = 2
    version_minor (2B) = 4
    thiszone (4B) = 0
    sigfigs (4B) = 0
    snaplen (4B) = 65535
    network (4B) = 1 (Ethernet)
    """
    global_hdr = struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    
    with open(filepath, "wb") as f:
        f.write(global_hdr)
        for ts_sec, ts_usec, pkt_bytes in packets:
            caplen = len(pkt_bytes)
            origlen = caplen
            # Packet Header (16 bytes): ts_sec, ts_usec, caplen, origlen
            pkt_hdr = struct.pack("!IIII", ts_sec, ts_usec, caplen, origlen)
            f.write(pkt_hdr)
            f.write(pkt_bytes)

def make_ipv4_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int = 0x02, seq: int = 1000, ack: int = 0, payload: bytes = b"", ttl: int = 64, win: int = 8192):
    # Ethernet Header (14 bytes): Dst MAC (6B), Src MAC (6B), EtherType (2B = 0x0800 for IPv4)
    eth = b"\x00\x0c\x29\x4f\x8e\x35" + b"\x00\x50\x56\xc0\x00\x08" + struct.pack("!H", 0x0800)
    
    # IPv4 Header (20 bytes)
    version_ihl = 0x45 # Version 4, IHL 5
    tos = 0
    tot_len = 20 + 20 + len(payload)
    pkt_id = 54321
    flags_frag = 0x4000 # Don't Fragment
    proto = 6 # TCP
    chksum = 0 # zero for dummy capture
    src_bytes = bytes([int(x) for x in src_ip.split(".")])
    dst_bytes = bytes([int(x) for x in dst_ip.split(".")])
    
    ip_hdr = struct.pack("!BBHHHBBH4s4s", version_ihl, tos, tot_len, pkt_id, flags_frag, ttl, proto, chksum, src_bytes, dst_bytes)
    
    # TCP Header (20 bytes)
    offset_reserved = (5 << 4) # 5 32-bit words
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset_reserved, flags, win, 0, 0)
    
    return eth + ip_hdr + tcp_hdr + payload

def generate_pcaps():
    root = Path(__file__).parent.parent
    pcap_dir = root / "demo_test_pcaps"
    public_dir = root / "frontend" / "public" / "sample_telemetry"
    csv_dir = root / "demo_test_csvs"
    
    pcap_dir.mkdir(parents=True, exist_ok=True)
    public_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy existing demo CSVs to frontend public
    if csv_dir.exists():
        for csv_file in csv_dir.glob("*.csv"):
            shutil.copy(csv_file, public_dir / csv_file.name)
            print(f"Copied {csv_file.name} to {public_dir}")

    now = int(time.time())
    
    # 1. Enterprise PCAP: Normal SYN/ACK handshake + SSH negotiation
    ent_pkts = []
    # SYN from client to server (port 22)
    ent_pkts.append((now, 100000, make_ipv4_tcp_packet("192.168.10.50", "172.16.0.1", 52140, 22, flags=0x02, seq=100)))
    # SYN-ACK from server
    ent_pkts.append((now, 102000, make_ipv4_tcp_packet("172.16.0.1", "192.168.10.50", 22, 52140, flags=0x12, seq=200, ack=101)))
    # ACK from client
    ent_pkts.append((now, 103000, make_ipv4_tcp_packet("192.168.10.50", "172.16.0.1", 52140, 22, flags=0x10, seq=101, ack=201)))
    # SSH protocol string payload
    ssh_data = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    ent_pkts.append((now, 120000, make_ipv4_tcp_packet("172.16.0.1", "192.168.10.50", 22, 52140, flags=0x18, seq=201, ack=101, payload=ssh_data)))
    
    ent_path = pcap_dir / "sample_enterprise_capture.pcap"
    create_pcap(ent_path, ent_pkts)
    shutil.copy(ent_path, public_dir / "sample_enterprise_capture.pcap")
    print(f"Generated {ent_path} ({len(ent_pkts)} packets)")
    
    # 2. SCADA Modbus PCAP: Modbus TCP Port 502 Command Injection
    scada_pkts = []
    # Rapid SYN probing across port 502
    for i in range(10):
        t_us = 100000 + i * 2000
        # Modbus Read Coils Query
        modbus_payload = struct.pack("!HHHBBHH", i+1, 0, 6, 1, 1, 0, 10)
        scada_pkts.append((now, t_us, make_ipv4_tcp_packet("10.0.100.42", "10.0.100.1", 40000+i, 502, flags=0x18, seq=500+i*50, ack=100, payload=modbus_payload)))
        
    scada_path = pcap_dir / "sample_scada_modbus.pcap"
    create_pcap(scada_path, scada_pkts)
    shutil.copy(scada_path, public_dir / "sample_scada_modbus.pcap")
    print(f"Generated {scada_path} ({len(scada_pkts)} packets)")

if __name__ == "__main__":
    generate_pcaps()
