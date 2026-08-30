"""
Standalone PCAP Feature Extraction Utility.

Extracts flow-level and packet-level features directly from raw .pcap or .pcapng files
using Scapy, generating a schema-compliant CSV ready for ShieldNet inference or training.

Usage:
    python scripts/extract_pcap_features.py input.pcap --output data/processed/extracted_pcap.csv
"""

import sys
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.features.packet_level import extract_packet_features_from_pcap
from src.features.schema import validate_dataframe


def main():
    parser = argparse.ArgumentParser(description="Extract ShieldNet features from raw PCAP file")
    parser.add_argument("pcap_path", help="Path to input .pcap or .pcapng file")
    parser.add_argument("--output", "-o", default="data/processed/pcap_features.csv", help="Output CSV path")
    args = parser.parse_args()

    pcap_file = Path(args.pcap_path)
    if not pcap_file.exists():
        print(f"Error: PCAP file '{pcap_file}' not found.")
        sys.exit(1)

    print(f"Extracting packet & flow features from {pcap_file}...")
    df = extract_packet_features_from_pcap(str(pcap_file))

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

    print(f"✓ Extraction complete. Saved {len(df):,} flows to {out_path}")
    validation = validate_dataframe(df)
    print(f"  Flow features present: {validation['flow_present']}/{validation['flow_total']}")
    print(f"  Packet features present: {validation['packet_present']}/{validation['packet_total']}")


if __name__ == "__main__":
    main()
