# ShieldNet: Future Work & Architectural Extensions

---

## 1. Explicitly Deferred Exploration Modules

In accordance with SIH Problem Statement #153 guidelines and tournament time-boxing constraints, the following architectural extensions have been documented and deferred for post-hackathon enterprise scaling:

### A. Spatio-Temporal Graph Neural Networks (GraphSAGE / GAT + GRU)
- **PS Clause Reference:** *"Represent network state using feature vectors or graphs."*
- **Status:** **HONESTLY DEFERRED.**
- **Rationale:** The PS explicitly specifies network state representation using *"feature vectors OR graphs"*. ShieldNet fully satisfies this requirement through an 84-dimensional continuous fused feature-vector representation (77 flow-level + 7 packet-level aggregates). Graph-based topological message passing across host IP nodes requires multi-host graph construction overhead, which was deferred to maintain sub-millisecond per-sample inference latency ($0.0155\text{ ms}$).

### B. Latent Generative World Models (VAE + MDN-RNN)
- **PS Clause Reference:** *"Learn state-transition dynamics using LSTM, Transformer, GNN, latent state models, or other AI techniques."*
- **Status:** **HONESTLY DEFERRED.**
- **Rationale:** The tournament evaluated GRU, Transformer, and Tabular Ensemble architectures. Mixture Density Networks (MDN-RNN) and Variational Autoencoder (VAE) latent state sampling introduce non-deterministic stochastic variance during forward trajectory rollouts. ShieldNet's deterministic Recurrent State-Space World Model (RSS-WM) achieved superior state reconstruction stability (MSE $1.1997$) and verified $+2.53\sigma$ to $+3.92\sigma$ temporal significance.

### C. Authentication Log Ingestion (LANL Cyber Dataset Fusion)
- **PS Clause Reference:** *"May utilise flow records, packet captures, authentication logs or other publicly available telemetry."*
- **Status:** **HONESTLY DEFERRED.**
- **Rationale:** Real-time line-rate network threat anticipation operates at the packet/flow level ($64,400\text{ samples/sec}$). Ingesting host authentication logs introduces asynchronous clock-skew synchronization latencies across distributed Active Directory / Kerberos domain controllers.

### D. Test-Time Adaptive Standardization (TTA)
- **Status:** **PLANNED EXTENSION.**
- **Rationale:** Addresses zero-shot domain gaps across heterogeneous enterprise subnets (such as the documented UNSW-NB15 semantic inversion) via online streaming exponential moving average (EMA) normalization.
