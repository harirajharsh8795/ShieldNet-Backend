"""
ShieldNet Sniffer Diagnostic — identifies why 0 packets are captured.
Run this in Administrator PowerShell:
    .\.venv\Scripts\python.exe diagnostic_sniffer.py
"""
import os
import sys
import time

# Ensure Npcap DLL is discoverable
if os.name == "nt":
    from pathlib import Path
    _npcap_dir = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "Npcap"
    if _npcap_dir.exists():
        try:
            os.add_dll_directory(str(_npcap_dir))
        except Exception:
            pass
        if str(_npcap_dir) not in os.environ.get("PATH", ""):
            os.environ["PATH"] = str(_npcap_dir) + os.pathsep + os.environ.get("PATH", "")
        print(f"[OK] Npcap directory found: {_npcap_dir}")
    else:
        print(f"[FAIL] Npcap directory NOT found at {_npcap_dir}")
        print("       Install Npcap from https://npcap.com/dist/npcap-1.80.exe")
        sys.exit(1)

print()

# ── Step 1: psutil interface listing ──
print("=" * 60)
print("  STEP 1: Network interfaces (psutil)")
print("=" * 60)
import psutil

addrs = psutil.net_if_addrs()
stats = psutil.net_if_stats()

for name, iface_addrs in addrs.items():
    is_up = stats.get(name).isup if name in stats else False
    ipv4s = [a.address for a in iface_addrs if a.family.name == "AF_INET" and not a.address.startswith("127.")]
    ipv6s = [a.address for a in iface_addrs if a.family.name == "AF_INET6"]
    status = "UP" if is_up else "DOWN"
    print(f"  [{status:>4}] {name}")
    if ipv4s:
        print(f"         IPv4: {', '.join(ipv4s)}")
    if ipv6s:
        print(f"         IPv6: {', '.join(ipv6s[:2])}{'...' if len(ipv6s) > 2 else ''}")
print()

# ── Step 2: Scapy interface listing ──
print("=" * 60)
print("  STEP 2: Network interfaces (Scapy / Npcap)")
print("=" * 60)
try:
    import scapy.config
    scapy.config.conf.use_pcap = True

    from scapy.arch.windows import get_windows_if_list
    scapy_ifaces = get_windows_if_list()
    for iface in scapy_ifaces:
        name = iface.get("name", "?")
        desc = iface.get("description", "?")
        ips = iface.get("ips", [])
        print(f"  Name: {name}")
        print(f"  Desc: {desc}")
        print(f"  IPs:  {ips[:3]}")
        print()
except Exception as e:
    print(f"  [FAIL] Could not list Scapy interfaces: {e}")
    print()

# ── Step 3: Auto-detect ──
print("=" * 60)
print("  STEP 3: Auto-detect (same logic as daemon)")
print("=" * 60)
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
    print(f"  Selected: '{candidates[0][1]}' (IP: {candidates[0][2]})")
    print(f"  All candidates: {[(c[1], c[2]) for c in candidates]}")
else:
    print("  [FAIL] No active interface found! Check that WiFi/Ethernet is connected.")
print()

# ── Step 4: Try AsyncSniffer for 5 seconds ──
print("=" * 60)
print("  STEP 4: Live capture test (5 seconds)")
print("=" * 60)
try:
    from scapy.sendrecv import AsyncSniffer
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    import scapy.layers.l2  # noqa

    target = candidates[0][1] if candidates else None
    counter = [0, 0, 0]  # raw, ipv4, ipv6

    def _cb(pkt):
        counter[0] += 1
        if pkt.haslayer(IP):
            counter[1] += 1
        if pkt.haslayer(IPv6):
            counter[2] += 1

    print(f"  Starting AsyncSniffer on '{target}' with BPF 'ip or ip6'...")
    sniffer = AsyncSniffer(
        prn=_cb,
        store=False,
        iface=target,
        filter="ip or ip6",
    )
    sniffer.start()
    print("  Sniffer started. Waiting 5 seconds...")
    time.sleep(5)
    sniffer.stop()

    print(f"\n  Results after 5s:")
    print(f"    Raw frames:  {counter[0]}")
    print(f"    IPv4 frames: {counter[1]}")
    print(f"    IPv6 frames: {counter[2]}")

    if counter[0] == 0:
        print("\n  [WARN] Zero packets with BPF filter. Retrying WITHOUT filter and interface...")

        counter2 = [0]
        def _cb2(pkt):
            counter2[0] += 1

        sniffer2 = AsyncSniffer(prn=_cb2, store=False)
        sniffer2.start()
        time.sleep(3)
        sniffer2.stop()
        print(f"    No-filter results: raw={counter2[0]}")

        if counter2[0] == 0:
            print("\n  [FAIL] Still zero. Possible causes:")
            print("    1. Not running as Administrator")
            print("    2. Npcap not installed or broken")
        else:
            print("\n  [INFO] Packets flow without filter — the BPF filter or interface name is the issue.")
            print(f"         Try: --interface \"<correct_name>\" from the Scapy list above.")
    else:
        print("\n  [OK] Packets captured successfully!")
except Exception as e:
    print(f"  [FAIL] AsyncSniffer failed: {e}")
    import traceback
    traceback.print_exc()

print()
print("=" * 60)
print("  DIAGNOSTIC COMPLETE")
print("=" * 60)
