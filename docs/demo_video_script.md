# ShieldNet Demo Video Script (Strictly 2 Minutes / 120 Seconds)
**Smart India Hackathon · Problem Statement SIH26153**  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity | **Category:** Software  

---

### ⏱️ Timestamped Video Walkthrough Schedule

| Timestamp | Visual / Screen Action | Voiceover Audio Script (Word Count: ~245 words) |
| :--- | :--- | :--- |
| **0:00 - 0:12** | **Landing Page (`/`):** Hero with animated cyber particle canvas. Title: *"Forecasting network attacks before compromise completes — not after."* | *"Traditional NIDS alert the SOC only after an enterprise breach has succeeded. We present ShieldNet — a Neural World Model that learns continuous network state dynamics to forecast cyber attacks before compromise is completed."* |
| **0:12 - 0:28** | **Ingestion & Topology (`/dashboard`):** Demonstrating PCAP DPI / NetFlow CSV dropzone and the **Dynamic Network Topology Graph ($G_t = (V, E, X_t)$)** with active packet pulses across enterprise & CII subnets. | *"Operating 100% air-gapped without cloud APIs, ShieldNet ingests dual-level telemetry — fusing 77 NetFlow features with 7 raw packet header dynamics into standardized 84-dimensional state vectors and dynamic network communication graphs for enterprise and Critical Infrastructure."* |
| **0:28 - 0:50** | **Live Simulation (`/dashboard/simulation`):** Showing the live probability timeline and the **K-Step Neural Forward-Simulation panel** ($t+1$ to $t+5$, $+50$s) with ghosted confidence decay and MITRE Stage 2 (*Initial Access*) badge. | *"Unlike memoryless classifiers, ShieldNet's Recurrent World Model forward-simulates future state transitions. Notice how our K-step rollout projects threat convergence 5 steps ahead (+50 seconds), automatically mapping adversary progression to MITRE ATT&CK Initial Access."* |
| **0:50 - 1:10** | **Interactive Mitigation Sandbox (`/dashboard/simulation`):** Clicking *'Rate Limit Host'* and *'Isolate Endpoint'*, showing the real-time curve comparison and $-78.4\%$ projected risk reduction. | *"ShieldNet is the first NIDS to include a Counterfactual Defense Sandbox. Security operators simulate policy interventions in latent state-space — verifying an immediate 78% threat reduction before applying physical firewall rules."* |
| **1:10 - 1:28** | **Axiomatic Explainability (`/explainability`):** Showing Integrated Gradients waterfall chart, temporal attention weights heatmap, and interactive What-If counterfactual slider. | *"Explainability is mathematically grounded via axiomatic Integrated Gradients and Temporal Attention weights. ShieldNet isolates top telemetry drivers like TCP window collapse and SYN burst ratios, coupled with an instant plain-language forensic narrative."* |
| **1:28 - 1:44** | **SIERL Blockchain Ledger (`/dashboard/blockchain`):** Showing SHA-256 Merkle block explorer, multi-artifact hash verification (model weights, packet evidence, XAI attribution), and 1-click Section 65B legal certificate. | *"Fulfilling the Blockchain & Cybersecurity theme, ShieldNet anchors all telemetry to SIERL — our SHA-256 cryptographic ledger. Every prediction, model weight, and forensic attribution is tamper-evidently signed, generating Section 65B Indian Evidence Act digital certificates for court admissibility."* |
| **1:44 - 2:00** | **Verified Benchmark & Closing (`/baseline`):** Showing the 3-Way Model Comparison Table (79.38% Threat Recall at 3.99% FPR, 87.70% Balanced Accuracy, 0.0155ms latency) and Air-Gap verification. | *"Empirically verified against logistic regression and LSTM baselines, ShieldNet achieves 79.38% recall with sub-millisecond line-rate latency. ShieldNet delivers sovereign, proactive foresight for national cyber defense. Thank you."* |

---

### 🎬 Screen Recording & Production Checklist for Presenters

1. **Resolution & Scaling:** Record at 1920x1080 (1080p), browser zoom at 100% (or 90% for high-density overview).
2. **Audio Setup:** Clear voiceover with crisp condenser microphone; eliminate background noise.
3. **Cursor Highlights:** Enable subtle yellow cursor halo to draw evaluator attention to key buttons:
   - Clicking *"Scenario Selector"* on Topology Graph (`/dashboard`)
   - Clicking *"Simulate Intervention"* (`/dashboard/simulation`)
   - Adjusting *"What-If Recourse Slider"* (`/explainability`)
   - Clicking *"Export Section 65B Certificate"* (`/dashboard/blockchain`)
4. **Air-Gap Verification Notice:** Highlight the green `AIR-GAP VERIFIED (C4 LOCKED)` badge in the top navbar during the closing 5 seconds.
