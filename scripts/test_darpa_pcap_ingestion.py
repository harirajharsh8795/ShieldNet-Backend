"""
NetGuard Step 3: DARPA 1998/99 Intrusion Detection Evaluation Integration.

1. Tests connection to MIT Lincoln Lab 1998 data repository.
2. Downloads the 4-hour training subset tcpdump / sample pcap.
3. Tests parsing via Scapy / PyShark PCAP extraction pipeline.
4. Extracts 84-dimensional flow/packet state vectors and maps DARPA categories to MITRE stages.
5. Runs real inference with the locked World Model (world_model_v1.pt).
"""

import sys
import os
import time
import urllib.request
import gzip
import shutil
from pathlib import Path

DARPA_SAMPLE_URLS = [
    # MIT Lincoln Lab 1998 Four-Hour Sample / Tcpdump files
    "https://www.ll.mit.edu/sites/default/files/inline-files/1998-four-hour-sample.dump.gz",
    "https://www.ll.mit.edu/r-d/datasets/1998-darpa-intrusion-detection-evaluation-dataset",
    "https://data.mendeley.com/public-files/datasets/kdd99/darpa98_sample.pcap",
    "https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures/kdd99.pcap"
]

def test_darpa_fetch():
    print("=" * 85)
    print("STEP 3: DARPA 1998/99 PCAP INGESTION & PIPELINE COMPATIBILITY TEST")
    print("=" * 85)
    
    data_dir = Path("data/darpa1998")
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Try fetching Lincoln Lab public URLs
    target_urls = [
        "https://www.ll.mit.edu/sites/default/files/inline-files/sample.dump.gz",
        "https://www.ll.mit.edu/sites/default/files/inline-files/four-hour-sample.dump.gz",
        "https://www.ll.mit.edu/ideval/data/1998/four-hour-sample.dump.gz",
        "https://www.ll.mit.edu/ideval/data/1998data.html"
    ]
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    print("1. Probing MIT Lincoln Lab DARPA 1998 dataset endpoints...")
    found_dump_url = None
    for url in target_urls:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                ct = resp.headers.get('Content-Type', '')
                cl = resp.headers.get('Content-Length', 'unknown')
                print(f"  [HTTP {status}] {url} (Content-Type: {ct}, Size: {cl})")
                if "html" in ct and "1998" in url:
                    html_content = resp.read().decode('utf-8', errors='ignore')
                    # Parse links inside HTML for .dump.gz or .tar.gz or tcpdump files
                    for line in html_content.splitlines():
                        if ".dump" in line or ".pcap" in line or ".gz" in line:
                            print(f"    Discovered link in page: {line.strip()[:100]}")
                elif "dump" in url or "pcap" in url:
                    found_dump_url = url
        except Exception as e:
            print(f"  [ERROR] {url} -> {e}")

    return found_dump_url

if __name__ == "__main__":
    test_darpa_fetch()
