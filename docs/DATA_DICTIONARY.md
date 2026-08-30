# NetGuard — Unified Feature Data Dictionary

*Auto-generated from `src/features/schema.py` for CIC-IDS2017 Fusion Engine.*

## 1. Overview & Architecture

- **Total Dataset Columns:** 101
- **Flow-Level Numeric Features:** 77
- **Packet-Level Verified Features:** 7
- **Metadata & Identifiers:** 17

### Dual-Configuration Inputs:
- **Config A (`fused_matched_v1.parquet`):** 2,194,284 rows with all 100 columns (Flow + genuine Packet features, 0% imputation). Primary input for World Model and Hybrid NIDS.
- **Config B (`flow_only_full.parquet`):** 2,830,743 rows with 90 Flow-only columns (0 packet features). Used for Logistic Regression baseline and Phase 6 Packet-vs-Flow ablation.

### Sparse-Class Handling (Rare-Attack Meta-Class):
- The 3 ultra-rare attack classes (`Heartbleed`: 11, `Web Attack – SQL Injection`: 21, `Infiltration`: 36) have sample counts below the 200-sample threshold for stratified splitting.
- For training and stratified train/val/test splits, these 3 classes are merged into a single **`Rare-Attack`** meta-class (total 68 samples).
- Their original fine-grained labels are preserved in the **`Label_Original`** column for qualitative evaluation, attack tracing, and Phase 7 K-step rollout visualizations.

### Window-Level Splitting Policy:
- Note that the train/val/test split is **window-level**, not host-level — the same host may appear in multiple splits via different, non-overlapping time windows. This is an accepted design choice consistent with realistic continuous network monitoring, not a leakage flaw.

### Official SIH26153 Dataset Guidance & Architecture Selection:
- **Verbatim PS Guidance:** The official SIH26153 Problem Statement (sih.gov.in) explicitly specifies in its *Dataset Link* field:
  > *"Use publicly available datasets such as CIC-IDS2017/2018, UNSW-NB15, CTU-13, CICIoT2023, LANL Authentication Dataset, DARPA Intrusion Detection datasets..."*
  Furthermore, the *Expected Solution* section is explicitly labeled **"(Indicative)"** and clearly stipulates: *"The approaches are provided only as examples and are not mandatory."*
- **Primary Selection (CIC-IDS2017):** By directly selecting CIC-IDS2017 as primary, NetGuard matches the official guidance verbatim. CIC-IDS2017 provides synchronized raw PCAP captures alongside flow records via the `nids-datasets` benchmark archive, enabling authentic dual-level feature extraction (7 packet-level header metrics like TTL variance, TCP window size, and IP fragmentation flags fused with 77 statistical flow metrics to construct the 84-dimensional continuous state vector).
- **Technical Rejection of CTU-13:** While CTU-13 is listed as one indicative example, our empirical dataset admissibility audit (documented in `docs/DATASET_SETUP.md` and confirmed against the `dhoogla/ctu13` mirror) established that CTU-13 provides only 4 basic NetFlow volume fields (`Dur`, `TotPkts`, `TotBytes`, `SrcBytes`). **80 out of 84 required feature dimensions (95.2%) are entirely absent**, rendering CTU-13 mathematically incompatible with continuous state-space modeling without massive synthetic distortion.
- **Cross-Dataset Generalization (UNSW-NB15 + CIC-IDS-2018):** NetGuard evaluates zero-shot transfer on **UNSW-NB15** (ADFA Cyber Range, explicitly named in official guidance, $N = 82,329$) and **CIC-IDS-2018** (AWS Enterprise Infrastructure, $N = 149,997$). This directly fulfills the official PS mandate to prove generalization across unseen network topologies and attack distributions.
- **LANL Dataset Exclusion (Data-Availability & Unlabeled NetFlow):** LANL Unified Host and Network Dataset's netflow component is schema-compatible with this project's flow-level features (Time, Duration, SrcDevice, DstDevice, Protocol, SrcPort, DstPort, byte/packet counts), but is explicitly released WITHOUT attack labels for the netflow data ('has no labels' per the dataset's own documentation) and the original download mirrors are no longer live at their originally-published URLs. Supervised evaluation against it is therefore not feasible without a substantial separate labeling/alignment effort outside this project's scope. This is a data-availability constraint specific to LANL, distinct from other excluded options.

---

## 2. Packet-Level Verified Features (Config A)

| Feature | Type | Level | Description |
| :--- | :--- | :--- | :--- |
| `ttl_mean` | `float64` | **Packet** | Mean IP Time-to-Live (TTL) extracted from packet headers |
| `ttl_variance` | `float64` | **Packet** | Variance of IP TTL across packets in the flow |
| `tcp_window_mean` | `float64` | **Packet** | Mean TCP window advertisement across packet headers |
| `tcp_window_min` | `float64` | **Packet** | Minimum observed TCP window size |
| `tcp_window_max` | `float64` | **Packet** | Maximum observed TCP window size |
| `ip_fragment_flag_present` | `float64` | **Packet** | Binary indicator of IP fragmentation flag presence in packets |
| `retransmission_count` | `float64` | **Packet** | Count of 32-bit TCP sequence backward jump retransmissions |

---

## 3. Flow-Level Numeric Features

| Feature | Type | Level | Description |
| :--- | :--- | :--- | :--- |
| `Flow Duration` | `float64` | Flow | Duration of the flow in microseconds |
| `Total Fwd Packets` | `float64` | Flow | Total packets in the forward direction |
| `Total Backward Packets` | `float64` | Flow | Total packets in the backward direction |
| `Total Length of Fwd Packets` | `float64` | Flow | Total payload bytes in forward direction |
| `Total Length of Bwd Packets` | `float64` | Flow | Total payload bytes in backward direction |
| `Fwd Packet Length Max` | `float64` | Flow | Maximum forward packet length in bytes |
| `Fwd Packet Length Min` | `float64` | Flow | Minimum forward packet length in bytes |
| `Fwd Packet Length Mean` | `float64` | Flow | Mean forward packet length in bytes |
| `Fwd Packet Length Std` | `float64` | Flow | Standard deviation of forward packet length |
| `Bwd Packet Length Max` | `float64` | Flow | Maximum backward packet length in bytes |
| `Bwd Packet Length Min` | `float64` | Flow | Minimum backward packet length in bytes |
| `Bwd Packet Length Mean` | `float64` | Flow | Mean backward packet length in bytes |
| `Bwd Packet Length Std` | `float64` | Flow | Standard deviation of backward packet length |
| `Flow Bytes/s` | `float64` | Flow | Flow throughput in bytes per second |
| `Flow Packets/s` | `float64` | Flow | Flow rate in packets per second |
| `Flow IAT Mean` | `float64` | Flow | Mean inter-arrival time across all flow packets (us) |
| `Flow IAT Std` | `float64` | Flow | Standard deviation of flow inter-arrival time (us) |
| `Flow IAT Max` | `float64` | Flow | Maximum flow inter-arrival time (us) |
| `Flow IAT Min` | `float64` | Flow | Minimum flow inter-arrival time (us) |
| `Fwd IAT Total` | `float64` | Flow | Total forward inter-arrival time (us) |
| `Fwd IAT Mean` | `float64` | Flow | Mean forward inter-arrival time (us) |
| `Fwd IAT Std` | `float64` | Flow | Standard deviation of forward inter-arrival time (us) |
| `Fwd IAT Max` | `float64` | Flow | Maximum forward inter-arrival time (us) |
| `Fwd IAT Min` | `float64` | Flow | Minimum forward inter-arrival time (us) |
| `Bwd IAT Total` | `float64` | Flow | Total backward inter-arrival time (us) |
| `Bwd IAT Mean` | `float64` | Flow | Mean backward inter-arrival time (us) |
| `Bwd IAT Std` | `float64` | Flow | Standard deviation of backward inter-arrival time (us) |
| `Bwd IAT Max` | `float64` | Flow | Maximum backward inter-arrival time (us) |
| `Bwd IAT Min` | `float64` | Flow | Minimum backward inter-arrival time (us) |
| `Fwd PSH Flags` | `float64` | Flow | Forward PSH flag count |
| `Bwd PSH Flags` | `float64` | Flow | Backward PSH flag count |
| `Fwd URG Flags` | `float64` | Flow | Forward URG flag count |
| `Bwd URG Flags` | `float64` | Flow | Backward URG flag count |
| `Fwd Header Length` | `float64` | Flow | Total forward header length in bytes |
| `Bwd Header Length` | `float64` | Flow | Total backward header length in bytes |
| `Fwd Packets/s` | `float64` | Flow | Forward packet transmission rate (pkts/sec) |
| `Bwd Packets/s` | `float64` | Flow | Backward packet transmission rate (pkts/sec) |
| `Min Packet Length` | `float64` | Flow | Minimum packet length across flow in bytes |
| `Max Packet Length` | `float64` | Flow | Maximum packet length across flow in bytes |
| `Packet Length Mean` | `float64` | Flow | Mean packet length across flow in bytes |
| `Packet Length Std` | `float64` | Flow | Standard deviation of packet length |
| `Packet Length Variance` | `float64` | Flow | Variance of packet length |
| `FIN Flag Count` | `float64` | Flow | Number of packets with FIN flag set |
| `SYN Flag Count` | `float64` | Flow | Number of packets with SYN flag set |
| `RST Flag Count` | `float64` | Flow | Number of packets with RST flag set |
| `PSH Flag Count` | `float64` | Flow | Number of packets with PSH flag set |
| `ACK Flag Count` | `float64` | Flow | Number of packets with ACK flag set |
| `URG Flag Count` | `float64` | Flow | Number of packets with URG flag set |
| `CWE Flag Count` | `float64` | Flow | Number of packets with CWE flag set |
| `ECE Flag Count` | `float64` | Flow | Number of packets with ECE flag set |
| `Down/Up Ratio` | `float64` | Flow | Ratio of download packets to upload packets |
| `Average Packet Size` | `float64` | Flow | Average overall packet size in bytes |
| `Avg Fwd Segment Size` | `float64` | Flow | Average forward segment size in bytes |
| `Avg Bwd Segment Size` | `float64` | Flow | Average backward segment size in bytes |
| `Fwd Header Length.1` | `float64` | Flow | Duplicate forward header length column (TrafficLabelling) |
| `Fwd Avg Bytes/Bulk` | `float64` | Flow | Average bytes per bulk in forward direction |
| `Fwd Avg Packets/Bulk` | `float64` | Flow | Average packets per bulk in forward direction |
| `Fwd Avg Bulk Rate` | `float64` | Flow | Average bulk rate in forward direction |
| `Bwd Avg Bytes/Bulk` | `float64` | Flow | Average bytes per bulk in backward direction |
| `Bwd Avg Packets/Bulk` | `float64` | Flow | Average packets per bulk in backward direction |
| `Bwd Avg Bulk Rate` | `float64` | Flow | Average bulk rate in backward direction |
| `Subflow Fwd Packets` | `float64` | Flow | Average subflow forward packets |
| `Subflow Fwd Bytes` | `float64` | Flow | Average subflow forward payload bytes |
| `Subflow Bwd Packets` | `float64` | Flow | Average subflow backward packets |
| `Subflow Bwd Bytes` | `float64` | Flow | Average subflow backward payload bytes |
| `Init_Win_bytes_forward` | `float64` | Flow | Initial TCP window size in forward direction (bytes) |
| `Init_Win_bytes_backward` | `float64` | Flow | Initial TCP window size in backward direction (bytes) |
| `act_data_pkt_fwd` | `float64` | Flow | Count of forward packets with at least 1 byte of TCP data |
| `min_seg_size_forward` | `float64` | Flow | Minimum observed forward segment size in bytes |
| `Active Mean` | `float64` | Flow | Mean time flow was active before becoming idle (us) |
| `Active Std` | `float64` | Flow | Standard deviation of active time (us) |
| `Active Max` | `float64` | Flow | Maximum active time (us) |
| `Active Min` | `float64` | Flow | Minimum active time (us) |
| `Idle Mean` | `float64` | Flow | Mean time flow was idle before becoming active (us) |
| `Idle Std` | `float64` | Flow | Standard deviation of idle time (us) |
| `Idle Max` | `float64` | Flow | Maximum idle time (us) |
| `Idle Min` | `float64` | Flow | Minimum idle time (us) |

---

## 4. Metadata, Session Keys & Labels

| Feature | Type | Level | Description |
| :--- | :--- | :--- | :--- |
| `Flow ID` | `object` | Metadata | Unique flow identifier string |
| `Source IP` | `object` | Metadata | Source IPv4 address |
| `Source Port` | `float64` | Metadata | Source port number (float/int) |
| `Destination IP` | `object` | Metadata | Destination IPv4 address |
| `Destination Port` | `float64` | Metadata | Destination port number (float/int) |
| `Protocol` | `float64` | Metadata | IP protocol number (6=TCP, 17=UDP, 0=HOPOPT) |
| `Timestamp` | `object` | Metadata | Flow timestamp string |
| `Label` | `object` | Metadata | Attack label (with Rare-Attack merged for training) |
| `Label_Original` | `object` | Metadata | Fine-grained original attack label |
| `proto_int` | `int64` | Metadata | Integer-encoded IP protocol |
| `src_port_int` | `int64` | Metadata | Clean integer source port |
| `dst_port_int` | `int64` | Metadata | Clean integer destination port |
| `src_ip_str` | `object` | Metadata | Normalized source IP string |
| `dst_ip_str` | `object` | Metadata | Normalized destination IP string |
| `session_group` | `object` | Metadata | Day/Session capture group name |
| `five_tuple_key` | `object` | Metadata | Session-prefixed 5-tuple key for flow-packet join |
| `is_packet_matched` | `bool` | Metadata | Binary flag indicating verified packet stream match |