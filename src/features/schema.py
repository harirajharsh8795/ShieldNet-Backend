"""
Unified feature schema for NetGuard.
Defines the canonical 100-feature set for Config A (Fused Flow+Packet)
and the 90-feature set for Config B (Flow-Only Baseline).
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Set
import pandas as pd
from pathlib import Path

# ─── Feature Level Constants ──────────────────────────────────────────────────
FLOW_LEVEL = "flow"
PACKET_LEVEL = "packet"
META_LEVEL = "meta"

# ─── Canonical Column Definitions for Config A (100 Columns) ──────────────────
# Format: (column_name, level, description, dtype)

CONFIG_A_COLUMNS: List[Tuple[str, str, str, str]] = [
    # ── Metadata & Identifier Columns (16) ──
    ("Flow ID",                     META_LEVEL,   "Unique flow identifier string",                               "object"),
    ("Source IP",                   META_LEVEL,   "Source IPv4 address",                                         "object"),
    ("Source Port",                 META_LEVEL,   "Source port number (float/int)",                              "float64"),
    ("Destination IP",              META_LEVEL,   "Destination IPv4 address",                                    "object"),
    ("Destination Port",            META_LEVEL,   "Destination port number (float/int)",                         "float64"),
    ("Protocol",                    META_LEVEL,   "IP protocol number (6=TCP, 17=UDP, 0=HOPOPT)",                "float64"),
    ("Timestamp",                   META_LEVEL,   "Flow timestamp string",                                       "object"),
    ("Label",                       META_LEVEL,   "Attack label (with Rare-Attack merged for training)",          "object"),
    ("Label_Original",              META_LEVEL,   "Fine-grained original attack label",                          "object"),
    ("proto_int",                   META_LEVEL,   "Integer-encoded IP protocol",                                 "int64"),
    ("src_port_int",                META_LEVEL,   "Clean integer source port",                                   "int64"),
    ("dst_port_int",                META_LEVEL,   "Clean integer destination port",                              "int64"),
    ("src_ip_str",                  META_LEVEL,   "Normalized source IP string",                                 "object"),
    ("dst_ip_str",                  META_LEVEL,   "Normalized destination IP string",                            "object"),
    ("session_group",               META_LEVEL,   "Day/Session capture group name",                              "object"),
    ("five_tuple_key",              META_LEVEL,   "Session-prefixed 5-tuple key for flow-packet join",           "object"),
    ("is_packet_matched",           META_LEVEL,   "Binary flag indicating verified packet stream match",         "bool"),

    # ── Flow-Level Numeric Features (76) ──
    ("Flow Duration",               FLOW_LEVEL,   "Duration of the flow in microseconds",                        "float64"),
    ("Total Fwd Packets",           FLOW_LEVEL,   "Total packets in the forward direction",                      "float64"),
    ("Total Backward Packets",      FLOW_LEVEL,   "Total packets in the backward direction",                     "float64"),
    ("Total Length of Fwd Packets", FLOW_LEVEL,   "Total payload bytes in forward direction",                    "float64"),
    ("Total Length of Bwd Packets", FLOW_LEVEL,   "Total payload bytes in backward direction",                   "float64"),
    ("Fwd Packet Length Max",       FLOW_LEVEL,   "Maximum forward packet length in bytes",                      "float64"),
    ("Fwd Packet Length Min",       FLOW_LEVEL,   "Minimum forward packet length in bytes",                      "float64"),
    ("Fwd Packet Length Mean",      FLOW_LEVEL,   "Mean forward packet length in bytes",                         "float64"),
    ("Fwd Packet Length Std",       FLOW_LEVEL,   "Standard deviation of forward packet length",                 "float64"),
    ("Bwd Packet Length Max",       FLOW_LEVEL,   "Maximum backward packet length in bytes",                     "float64"),
    ("Bwd Packet Length Min",       FLOW_LEVEL,   "Minimum backward packet length in bytes",                     "float64"),
    ("Bwd Packet Length Mean",      FLOW_LEVEL,   "Mean backward packet length in bytes",                        "float64"),
    ("Bwd Packet Length Std",       FLOW_LEVEL,   "Standard deviation of backward packet length",                "float64"),
    ("Flow Bytes/s",                FLOW_LEVEL,   "Flow throughput in bytes per second",                         "float64"),
    ("Flow Packets/s",              FLOW_LEVEL,   "Flow rate in packets per second",                             "float64"),
    ("Flow IAT Mean",               FLOW_LEVEL,   "Mean inter-arrival time across all flow packets (us)",        "float64"),
    ("Flow IAT Std",                FLOW_LEVEL,   "Standard deviation of flow inter-arrival time (us)",          "float64"),
    ("Flow IAT Max",                FLOW_LEVEL,   "Maximum flow inter-arrival time (us)",                        "float64"),
    ("Flow IAT Min",                FLOW_LEVEL,   "Minimum flow inter-arrival time (us)",                        "float64"),
    ("Fwd IAT Total",               FLOW_LEVEL,   "Total forward inter-arrival time (us)",                       "float64"),
    ("Fwd IAT Mean",                FLOW_LEVEL,   "Mean forward inter-arrival time (us)",                        "float64"),
    ("Fwd IAT Std",                 FLOW_LEVEL,   "Standard deviation of forward inter-arrival time (us)",       "float64"),
    ("Fwd IAT Max",                 FLOW_LEVEL,   "Maximum forward inter-arrival time (us)",                     "float64"),
    ("Fwd IAT Min",                 FLOW_LEVEL,   "Minimum forward inter-arrival time (us)",                     "float64"),
    ("Bwd IAT Total",               FLOW_LEVEL,   "Total backward inter-arrival time (us)",                      "float64"),
    ("Bwd IAT Mean",                FLOW_LEVEL,   "Mean backward inter-arrival time (us)",                       "float64"),
    ("Bwd IAT Std",                 FLOW_LEVEL,   "Standard deviation of backward inter-arrival time (us)",      "float64"),
    ("Bwd IAT Max",                 FLOW_LEVEL,   "Maximum backward inter-arrival time (us)",                    "float64"),
    ("Bwd IAT Min",                 FLOW_LEVEL,   "Minimum backward inter-arrival time (us)",                    "float64"),
    ("Fwd PSH Flags",               FLOW_LEVEL,   "Forward PSH flag count",                                      "float64"),
    ("Bwd PSH Flags",               FLOW_LEVEL,   "Backward PSH flag count",                                     "float64"),
    ("Fwd URG Flags",               FLOW_LEVEL,   "Forward URG flag count",                                      "float64"),
    ("Bwd URG Flags",               FLOW_LEVEL,   "Backward URG flag count",                                     "float64"),
    ("Fwd Header Length",           FLOW_LEVEL,   "Total forward header length in bytes",                        "float64"),
    ("Bwd Header Length",           FLOW_LEVEL,   "Total backward header length in bytes",                       "float64"),
    ("Fwd Packets/s",               FLOW_LEVEL,   "Forward packet transmission rate (pkts/sec)",                 "float64"),
    ("Bwd Packets/s",               FLOW_LEVEL,   "Backward packet transmission rate (pkts/sec)",                "float64"),
    ("Min Packet Length",           FLOW_LEVEL,   "Minimum packet length across flow in bytes",                  "float64"),
    ("Max Packet Length",           FLOW_LEVEL,   "Maximum packet length across flow in bytes",                  "float64"),
    ("Packet Length Mean",          FLOW_LEVEL,   "Mean packet length across flow in bytes",                     "float64"),
    ("Packet Length Std",           FLOW_LEVEL,   "Standard deviation of packet length",                         "float64"),
    ("Packet Length Variance",      FLOW_LEVEL,   "Variance of packet length",                                   "float64"),
    ("FIN Flag Count",              FLOW_LEVEL,   "Number of packets with FIN flag set",                         "float64"),
    ("SYN Flag Count",              FLOW_LEVEL,   "Number of packets with SYN flag set",                         "float64"),
    ("RST Flag Count",              FLOW_LEVEL,   "Number of packets with RST flag set",                         "float64"),
    ("PSH Flag Count",              FLOW_LEVEL,   "Number of packets with PSH flag set",                         "float64"),
    ("ACK Flag Count",              FLOW_LEVEL,   "Number of packets with ACK flag set",                         "float64"),
    ("URG Flag Count",              FLOW_LEVEL,   "Number of packets with URG flag set",                         "float64"),
    ("CWE Flag Count",              FLOW_LEVEL,   "Number of packets with CWE flag set",                         "float64"),
    ("ECE Flag Count",              FLOW_LEVEL,   "Number of packets with ECE flag set",                         "float64"),
    ("Down/Up Ratio",               FLOW_LEVEL,   "Ratio of download packets to upload packets",                 "float64"),
    ("Average Packet Size",         FLOW_LEVEL,   "Average overall packet size in bytes",                        "float64"),
    ("Avg Fwd Segment Size",        FLOW_LEVEL,   "Average forward segment size in bytes",                       "float64"),
    ("Avg Bwd Segment Size",        FLOW_LEVEL,   "Average backward segment size in bytes",                      "float64"),
    ("Fwd Header Length.1",         FLOW_LEVEL,   "Duplicate forward header length column (TrafficLabelling)",   "float64"),
    ("Fwd Avg Bytes/Bulk",          FLOW_LEVEL,   "Average bytes per bulk in forward direction",                 "float64"),
    ("Fwd Avg Packets/Bulk",        FLOW_LEVEL,   "Average packets per bulk in forward direction",               "float64"),
    ("Fwd Avg Bulk Rate",           FLOW_LEVEL,   "Average bulk rate in forward direction",                      "float64"),
    ("Bwd Avg Bytes/Bulk",          FLOW_LEVEL,   "Average bytes per bulk in backward direction",                "float64"),
    ("Bwd Avg Packets/Bulk",        FLOW_LEVEL,   "Average packets per bulk in backward direction",              "float64"),
    ("Bwd Avg Bulk Rate",           FLOW_LEVEL,   "Average bulk rate in backward direction",                     "float64"),
    ("Subflow Fwd Packets",         FLOW_LEVEL,   "Average subflow forward packets",                             "float64"),
    ("Subflow Fwd Bytes",           FLOW_LEVEL,   "Average subflow forward payload bytes",                       "float64"),
    ("Subflow Bwd Packets",         FLOW_LEVEL,   "Average subflow backward packets",                            "float64"),
    ("Subflow Bwd Bytes",           FLOW_LEVEL,   "Average subflow backward payload bytes",                      "float64"),
    ("Init_Win_bytes_forward",      FLOW_LEVEL,   "Initial TCP window size in forward direction (bytes)",        "float64"),
    ("Init_Win_bytes_backward",     FLOW_LEVEL,   "Initial TCP window size in backward direction (bytes)",       "float64"),
    ("act_data_pkt_fwd",            FLOW_LEVEL,   "Count of forward packets with at least 1 byte of TCP data",   "float64"),
    ("min_seg_size_forward",        FLOW_LEVEL,   "Minimum observed forward segment size in bytes",              "float64"),
    ("Active Mean",                 FLOW_LEVEL,   "Mean time flow was active before becoming idle (us)",         "float64"),
    ("Active Std",                  FLOW_LEVEL,   "Standard deviation of active time (us)",                      "float64"),
    ("Active Max",                  FLOW_LEVEL,   "Maximum active time (us)",                                    "float64"),
    ("Active Min",                  FLOW_LEVEL,   "Minimum active time (us)",                                    "float64"),
    ("Idle Mean",                   FLOW_LEVEL,   "Mean time flow was idle before becoming active (us)",         "float64"),
    ("Idle Std",                    FLOW_LEVEL,   "Standard deviation of idle time (us)",                        "float64"),
    ("Idle Max",                    FLOW_LEVEL,   "Maximum idle time (us)",                                      "float64"),
    ("Idle Min",                    FLOW_LEVEL,   "Minimum idle time (us)",                                      "float64"),

    # ── Packet-Level Verified Features (7) ──
    ("ttl_mean",                    PACKET_LEVEL, "Mean IP Time-to-Live (TTL) extracted from packet headers",     "float64"),
    ("ttl_variance",                PACKET_LEVEL, "Variance of IP TTL across packets in the flow",                "float64"),
    ("tcp_window_mean",             PACKET_LEVEL, "Mean TCP window advertisement across packet headers",          "float64"),
    ("tcp_window_min",              PACKET_LEVEL, "Minimum observed TCP window size",                            "float64"),
    ("tcp_window_max",              PACKET_LEVEL, "Maximum observed TCP window size",                            "float64"),
    ("ip_fragment_flag_present",    PACKET_LEVEL, "Binary indicator of IP fragmentation flag presence in packets", "float64"),
    ("retransmission_count",        PACKET_LEVEL, "Count of 32-bit TCP sequence backward jump retransmissions",   "float64"),
]

# ─── Helper Functions ─────────────────────────────────────────────────────────

def get_config_a_feature_names(level: Optional[str] = None) -> List[str]:
    """Return list of column names for Config A."""
    if level is None:
        return [c[0] for c in CONFIG_A_COLUMNS]
    return [c[0] for c in CONFIG_A_COLUMNS if c[1] == level]


def get_numeric_feature_names(include_packet_level: bool = True) -> List[str]:
    """Return numeric feature column names for machine learning."""
    if include_packet_level:
        return [c[0] for c in CONFIG_A_COLUMNS if c[1] in (FLOW_LEVEL, PACKET_LEVEL)]
    return [c[0] for c in CONFIG_A_COLUMNS if c[1] == FLOW_LEVEL]


def get_schema_dataframe() -> pd.DataFrame:
    """Return schema as a pandas DataFrame."""
    return pd.DataFrame(CONFIG_A_COLUMNS, columns=["Feature", "Level", "Description", "Dtype"])


def generate_data_dictionary(output_path: str) -> str:
    """Auto-generate comprehensive DATA_DICTIONARY.md markdown documentation."""
    schema_df = get_schema_dataframe()
    
    flow_features = schema_df[schema_df["Level"] == FLOW_LEVEL]
    packet_features = schema_df[schema_df["Level"] == PACKET_LEVEL]
    meta_features = schema_df[schema_df["Level"] == META_LEVEL]
    
    content = [
        "# NetGuard — Unified Feature Data Dictionary\n",
        "*Auto-generated from `src/features/schema.py` for CIC-IDS2017 Fusion Engine.*\n",
        "## 1. Overview & Architecture\n",
        f"- **Total Dataset Columns:** {len(schema_df)}",
        f"- **Flow-Level Numeric Features:** {len(flow_features)}",
        f"- **Packet-Level Verified Features:** {len(packet_features)}",
        f"- **Metadata & Identifiers:** {len(meta_features)}\n",
        "### Dual-Configuration Inputs:",
        "- **Config A (`fused_matched_v1.parquet`):** 2,194,284 rows with all 100 columns (Flow + genuine Packet features, 0% imputation). Primary input for World Model and Hybrid NIDS.",
        "- **Config B (`flow_only_full.parquet`):** 2,830,743 rows with 90 Flow-only columns (0 packet features). Used for Logistic Regression baseline and Phase 6 Packet-vs-Flow ablation.\n",
        "### Sparse-Class Handling (Rare-Attack Meta-Class):",
        "- The 3 ultra-rare attack classes (`Heartbleed`: 11, `Web Attack – SQL Injection`: 21, `Infiltration`: 36) have sample counts below the 200-sample threshold for stratified splitting.",
        "- For training and stratified train/val/test splits, these 3 classes are merged into a single **`Rare-Attack`** meta-class (total 68 samples).",
        "- Their original fine-grained labels are preserved in the **`Label_Original`** column for qualitative evaluation, attack tracing, and Phase 7 K-step rollout visualizations.\n",
        "---\n",
        "## 2. Packet-Level Verified Features (Config A)\n",
        "| Feature | Type | Level | Description |",
        "| :--- | :--- | :--- | :--- |",
    ]
    
    for _, row in packet_features.iterrows():
        content.append(f"| `{row['Feature']}` | `{row['Dtype']}` | **Packet** | {row['Description']} |")
        
    content.extend([
        "\n---\n",
        "## 3. Flow-Level Numeric Features\n",
        "| Feature | Type | Level | Description |",
        "| :--- | :--- | :--- | :--- |",
    ])
    
    for _, row in flow_features.iterrows():
        content.append(f"| `{row['Feature']}` | `{row['Dtype']}` | Flow | {row['Description']} |")
        
    content.extend([
        "\n---\n",
        "## 4. Metadata, Session Keys & Labels\n",
        "| Feature | Type | Level | Description |",
        "| :--- | :--- | :--- | :--- |",
    ])
    
    for _, row in meta_features.iterrows():
        content.append(f"| `{row['Feature']}` | `{row['Dtype']}` | Metadata | {row['Description']} |")
        
    content_str = "\n".join(content)
    
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(content_str, encoding="utf-8")
    print(f"Data dictionary generated at: {out_file.resolve()}")
    return str(out_file)


if __name__ == "__main__":
    generate_data_dictionary("docs/DATA_DICTIONARY.md")
