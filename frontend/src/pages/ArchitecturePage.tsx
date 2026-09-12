import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  BrainCircuit,
  Route,
  ShieldCheck,
  Eye,
  Layers,
  Zap,
  CheckCircle2,
  Lock,
  Cpu,
  GitBranch,
  Blocks,
} from "lucide-react";
import { PipelineDiagram } from "../components/PipelineDiagram";

const ARCHITECTURE_TABS = [
  {
    id: "backbone",
    label: "Neural World Model Backbone",
    icon: BrainCircuit,
    tag: "Core Engine",
  },
  {
    id: "rollout",
    label: "Autoregressive K-Step Rollout",
    icon: Route,
    tag: "Proactive Forecast",
  },
  {
    id: "mitigation",
    label: "Counterfactual Trajectory Engine",
    icon: GitBranch,
    tag: "Safety Shield",
  },
  {
    id: "explainability",
    label: "Integrated Gradients Attribution",
    icon: Eye,
    tag: "Constraint C2",
  },
  {
    id: "features",
    label: "Dual-Level Telemetry Schema",
    icon: Layers,
    tag: "77 Flow + 7 Packet",
  },
  {
    id: "fabric",
    label: "Cross-CII Fabric Consensus",
    icon: Blocks,
    tag: "Multi-Node Blockchain",
  },
  {
    id: "auth",
    label: "Enterprise OAuth2 / Keycloak IdP",
    icon: Lock,
    tag: "RBAC & Zero-Trust",
  },
];

export function ArchitecturePage() {
  const [activeTab, setActiveTab] = useState<string>("backbone");

  return (
    <div className="w-full flex flex-col gap-8 pb-16">
      {/* Header Banner */}
      <motion.section
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col justify-between gap-6 rounded-2xl border p-8 lg:flex-row lg:items-end glow-box"
        style={{
          borderColor: "var(--color-border)",
          background:
            "linear-gradient(135deg, var(--color-panel), color-mix(in srgb, var(--color-accent) 6%, var(--color-panel)))",
        }}
      >
        <div className="max-w-4xl">
          <div className="inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-[var(--color-accent)] border-[var(--color-accent)]/30 bg-[var(--color-accent)]/10 mb-3">
            <Cpu size={13} />
            ShieldNet · Technical Architecture Specification
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-[var(--color-text-primary)] sm:text-4xl">
            Recurrent State-Space Neural World Model (RSS-WM)
          </h1>
          <p className="mt-3 text-sm leading-relaxed text-[var(--color-text-secondary)]">
            A proactive cybersecurity intelligence framework that learns continuous network state dynamics, forecasts multi-step attack progression before payload execution, simulates counterfactual interventions, and enforces safety policy invariants.
          </p>
        </div>

        <div className="flex flex-wrap gap-2.5 shrink-0 font-mono text-xs">
          <div className="rounded-xl border px-4 py-3 bg-[var(--color-panel-raised)]" style={{ borderColor: "var(--color-border)" }}>
            <div className="text-[var(--color-text-muted)] text-[10px]">PARAMETERS</div>
            <div className="mt-0.5 font-bold text-[var(--color-accent)]">260,904</div>
          </div>
          <div className="rounded-xl border px-4 py-3 bg-[var(--color-panel-raised)]" style={{ borderColor: "var(--color-border)" }}>
            <div className="text-[var(--color-text-muted)] text-[10px]">LATENCY (K=5)</div>
            <div className="mt-0.5 font-bold text-[var(--color-normal)]">4.03 ms</div>
          </div>
          <div className="rounded-xl border px-4 py-3 bg-[var(--color-panel-raised)]" style={{ borderColor: "var(--color-border)" }}>
            <div className="text-[var(--color-text-muted)] text-[10px]">DEPLOYMENT</div>
            <div className="mt-0.5 font-bold text-[var(--color-elevated)]">100% Offline (C4)</div>
          </div>
        </div>
      </motion.section>

      {/* Interactive System Pipeline Flow */}
      <section className="rounded-2xl border p-6 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="font-mono text-xs uppercase tracking-wider text-[var(--color-accent)]">
              END-TO-END DATAFLOW
            </div>
            <h2 className="mt-1 text-lg font-semibold text-[var(--color-text-primary)]">
              Temporal State-Space Ingestion &amp; Inference Pipeline
            </h2>
          </div>
          <span className="rounded bg-[var(--color-accent)]/10 px-2.5 py-1 font-mono text-xs text-[var(--color-accent)] border border-[var(--color-accent)]/30">
            7 Continuous Stages
          </span>
        </div>
        <PipelineDiagram />
      </section>

      {/* Architecture Deep Dive Tabs */}
      <section className="rounded-2xl border p-6 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
        <div className="mb-6 flex flex-wrap items-center gap-2 border-b pb-4" style={{ borderColor: "var(--color-border)" }}>
          {ARCHITECTURE_TABS.map((tab) => {
            const Icon = tab.icon;
            const isSelected = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`inline-flex items-center gap-2.5 rounded-lg px-3.5 py-2 text-xs font-medium transition-all ${
                  isSelected
                    ? "border border-[var(--color-accent)] bg-[var(--color-accent)]/15 text-[var(--color-accent)] shadow-sm"
                    : "border border-transparent text-[var(--color-text-secondary)] hover:bg-[var(--color-panel-raised)] hover:text-[var(--color-text-primary)]"
                }`}
              >
                <Icon size={14} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        <AnimatePresence mode="wait">
          {activeTab === "backbone" && (
            <motion.div
              key="backbone"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="grid grid-cols-1 gap-6 lg:grid-cols-2"
            >
              <div className="flex flex-col gap-4">
                <h3 className="text-base font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                  <BrainCircuit className="text-[var(--color-accent)]" size={18} />
                  2-Layer Gated Recurrent Unit (GRU) with Temporal Attention Pooling
                </h3>
                <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                  The backbone models temporal state evolution S_(t-L:t) where context window L=3 and feature dimension D=84. It processes incoming telemetry without collapsing historical state, passing through a multi-head temporal attention mechanism that computes attention weights α_t = softmax(W_a h_t + b_a) over past context steps.
                </p>

                <div className="rounded-xl border p-4 font-mono text-xs bg-[var(--color-base)] space-y-2 text-[var(--color-text-primary)]" style={{ borderColor: "var(--color-border)" }}>
                  <div className="text-[var(--color-text-muted)] uppercase text-[10px] tracking-wider font-bold">
                    Composite Multi-Task Loss Formulation:
                  </div>
                  <div className="text-[var(--color-accent)] font-bold">
                    L_total = λ_MSE · L_State + L_Focal(γ=2.0) + λ_MITRE · L_CE + λ_Order · L_BCE
                  </div>
                  <ul className="list-disc list-inside text-[11px] text-[var(--color-text-secondary)] space-y-1 pt-1">
                    <li><strong>State MSE Head:</strong> Regresses next continuous network state Ŝ_(t+1).</li>
                    <li><strong>Focal Classification Head:</strong> Multi-class threat head with γ=2.0 overcoming severe class imbalance.</li>
                    <li><strong>MITRE Killchain Head:</strong> Maps threat trajectory to 6 killchain stages.</li>
                    <li><strong>Temporal Order BCE Head:</strong> Self-supervised sequence order verification.</li>
                  </ul>
                </div>
              </div>

              <div className="rounded-xl border p-5 bg-[var(--color-panel-raised)] flex flex-col justify-between" style={{ borderColor: "var(--color-border)" }}>
                <div>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-accent)] mb-3">
                    Model Layer Specification
                  </h4>
                  <table className="w-full text-left font-mono text-xs">
                    <tbody className="divide-y divide-[var(--color-border)] text-[var(--color-text-secondary)]">
                      <tr>
                        <td className="py-2 text-[var(--color-text-muted)]">Input Layer</td>
                        <td className="py-2 text-right text-[var(--color-text-primary)]">84 Features (77 Flow + 7 Packet)</td>
                      </tr>
                      <tr>
                        <td className="py-2 text-[var(--color-text-muted)]">Sequence Length</td>
                        <td className="py-2 text-right text-[var(--color-text-primary)]">L = 3 sliding windows (10s stride)</td>
                      </tr>
                      <tr>
                        <td className="py-2 text-[var(--color-text-muted)]">Recurrent Backbone</td>
                        <td className="py-2 text-right text-[var(--color-text-primary)]">2-Layer GRU (H=128, Dropout=0.2)</td>
                      </tr>
                      <tr>
                        <td className="py-2 text-[var(--color-text-muted)]">Attention Layer</td>
                        <td className="py-2 text-right text-[var(--color-text-primary)]">Multi-Head Temporal Softmax Pooling</td>
                      </tr>
                      <tr>
                        <td className="py-2 text-[var(--color-text-muted)]">Total Parameters</td>
                        <td className="py-2 text-right font-bold text-[var(--color-accent)]">260,904 trainable weights</td>
                      </tr>
                      <tr>
                        <td className="py-2 text-[var(--color-text-muted)]">Weight Checkpoint</td>
                        <td className="py-2 text-right font-bold text-[var(--color-normal)]">world_model_v1.pt (SHA-256 locked)</td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                <div className="mt-4 rounded border border-[var(--color-normal)]/30 bg-[var(--color-normal)]/10 p-2.5 font-mono text-[11px] text-[var(--color-normal)] flex items-center gap-2">
                  <CheckCircle2 size={14} />
                  <span>3.52σ statistical significance verified over shuffled-time ablation baseline.</span>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === "rollout" && (
            <motion.div
              key="rollout"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="grid grid-cols-1 gap-6 lg:grid-cols-2"
            >
              <div className="flex flex-col gap-4">
                <h3 className="text-base font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                  <Route className="text-[var(--color-accent)]" size={18} />
                  Autoregressive Forward Simulation (K=1..5 Steps)
                </h3>
                <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                  Unlike reactive signature matching that alerts only after an exploit executes, the World Model recursively rolls out its own state predictions forward in time: Ŝ_(t+k) = M_θ(Ŝ_(t+k-L:t+k-1)). This exposes whether a stealthy port-scan or slowloris connection pool is accelerating toward full compromise before the payload arrives.
                </p>

                <div className="rounded-xl border p-4 font-mono text-xs bg-[var(--color-base)] text-[var(--color-text-primary)]" style={{ borderColor: "var(--color-border)" }}>
                  <div className="text-[var(--color-text-muted)] uppercase text-[10px] font-bold mb-1.5">
                    Uncertainty &amp; Confidence Propagation:
                  </div>
                  <div className="text-xs text-[var(--color-accent)] font-bold mb-2">
                    Confidence(k) = exp(-λ_decay · k) · (1.0 - EpistemicVariance(k))
                  </div>
                  <p className="text-[11px] text-[var(--color-text-secondary)] leading-relaxed">
                    Forecast confidence gently decays as horizon k increases, visually ghosting forward steps on the dashboard to provide calibrated uncertainty estimates to SOC operators.
                  </p>
                </div>
              </div>

              <div className="rounded-xl border p-5 bg-[var(--color-panel-raised)]" style={{ borderColor: "var(--color-border)" }}>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-accent)] mb-3">
                  Horizon Latency &amp; Accuracy Profile
                </h4>
                <div className="space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: "var(--color-border)" }}>
                    <span className="text-[var(--color-text-secondary)]">T+1 (10s Horizon)</span>
                    <span className="font-bold text-[var(--color-normal)]">0.82 ms / 94.2% Confidence</span>
                  </div>
                  <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: "var(--color-border)" }}>
                    <span className="text-[var(--color-text-secondary)]">T+2 (20s Horizon)</span>
                    <span className="font-bold text-[var(--color-normal)]">1.61 ms / 89.4% Confidence</span>
                  </div>
                  <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: "var(--color-border)" }}>
                    <span className="text-[var(--color-text-secondary)]">T+3 (30s Horizon)</span>
                    <span className="font-bold text-[var(--color-accent)]">2.42 ms / 84.1% Confidence</span>
                  </div>
                  <div className="flex items-center justify-between border-b pb-2" style={{ borderColor: "var(--color-border)" }}>
                    <span className="text-[var(--color-text-secondary)]">T+4 (40s Horizon)</span>
                    <span className="font-bold text-[var(--color-accent)]">3.24 ms / 78.5% Confidence</span>
                  </div>
                  <div className="flex items-center justify-between" style={{ borderColor: "var(--color-border)" }}>
                    <span className="text-[var(--color-text-secondary)]">T+5 (50s Horizon)</span>
                    <span className="font-bold text-[var(--color-elevated)]">4.03 ms / 72.8% Confidence</span>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === "mitigation" && (
            <motion.div
              key="mitigation"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="grid grid-cols-1 gap-6 lg:grid-cols-2"
            >
              <div className="flex flex-col gap-4">
                <h3 className="text-base font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                  <ShieldCheck className="text-[var(--color-normal)]" size={18} />
                  Counterfactual Intervention Operator &amp; Safety Shield
                </h3>
                <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                  Defenders can simulate the forward effect of defensive action operators T(S_t, a) before executing them on live firewalls. The Counterfactual Engine branches the world model state into parallel timelines to quantify predicted risk reduction against operational disruption cost.
                </p>

                <div className="rounded-xl border p-4 font-mono text-xs bg-[var(--color-base)] text-[var(--color-text-primary)]" style={{ borderColor: "var(--color-border)" }}>
                  <div className="text-[var(--color-text-muted)] uppercase text-[10px] font-bold mb-1.5">
                    Mitigation Utility Objective:
                  </div>
                  <div className="text-xs text-[var(--color-normal)] font-bold mb-2">
                    Utility(a) = ΔRisk(a) - λ_cost · OperationalCost(a)
                  </div>
                  <p className="text-[11px] text-[var(--color-text-secondary)]">
                    The Safety Shield enforces strict policy invariants (e.g. Guardrail G-01: Prohibits host isolation on critical assets with historic benign dominance) preventing accidental operational outages.
                  </p>
                </div>
              </div>

              <div className="rounded-xl border p-5 bg-[var(--color-panel-raised)]" style={{ borderColor: "var(--color-border)" }}>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-accent)] mb-3">
                  Supported Defense Operators
                </h4>
                <div className="space-y-2.5 font-mono text-xs">
                  <div className="rounded border p-2.5 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
                    <div className="font-bold text-[var(--color-text-primary)]">RATE_LIMIT</div>
                    <div className="text-[11px] text-[var(--color-text-secondary)]">Dampens flow bandwidth &amp; SYN burst rates by 85%. Low cost (0.15).</div>
                  </div>
                  <div className="rounded border p-2.5 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
                    <div className="font-bold text-[var(--color-normal)]">RESET_CONNECTIONS (Recommended)</div>
                    <div className="text-[11px] text-[var(--color-text-secondary)]">Injects TCP RST packets into active suspicious 5-tuples. Minimal disruption (0.05).</div>
                  </div>
                  <div className="rounded border p-2.5 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
                    <div className="font-bold text-[var(--color-elevated)]">BLOCK_IP</div>
                    <div className="text-[11px] text-[var(--color-text-secondary)]">Drops edge ingress/egress for attacking source IP. Medium cost (0.50).</div>
                  </div>
                  <div className="rounded border p-2.5 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
                    <div className="font-bold text-[var(--color-critical)]">ISOLATE_HOST</div>
                    <div className="text-[11px] text-[var(--color-text-secondary)]">Quarantines host to remediation VLAN. High cost (0.85, Shield Guardrail protected).</div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === "explainability" && (
            <motion.div
              key="explainability"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="grid grid-cols-1 gap-6 lg:grid-cols-2"
            >
              <div className="flex flex-col gap-4">
                <h3 className="text-base font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                  <Eye className="text-[var(--color-accent)]" size={18} />
                  Axiomatic Feature Attribution (Integrated Gradients)
                </h3>
                <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                  To strictly satisfy Problem Statement Constraint C2 (Explainability), ShieldNet integrates path-based gradient attribution. It computes feature importance along a straight line path from a neutral benign baseline x' to the input sequence x:
                </p>

                <div className="rounded-xl border p-4 font-mono text-xs bg-[var(--color-base)] text-[var(--color-text-primary)]" style={{ borderColor: "var(--color-border)" }}>
                  <div className="text-[var(--color-text-muted)] uppercase text-[10px] font-bold mb-1.5">
                    Integrated Gradients Mathematical Definition:
                  </div>
                  <div className="text-xs text-[var(--color-accent)] font-bold mb-2">
                    Attr_i(x) = (x_i - x'_i) · ∫ [∂F(x' + α(x - x')) / ∂x_i] dα
                  </div>
                  <p className="text-[11px] text-[var(--color-text-secondary)] leading-relaxed">
                    Satisfies Completeness, Implementation Invariance, and Sensitivity axioms, translating mathematical attributions into plain-language SOC driver summaries.
                  </p>
                </div>
              </div>

              <div className="rounded-xl border p-5 bg-[var(--color-panel-raised)]" style={{ borderColor: "var(--color-border)" }}>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-accent)] mb-3">
                  Top Attributed Telemetry Features
                </h4>
                <div className="space-y-2.5 font-mono text-xs">
                  <div className="flex items-center justify-between border-b pb-1.5" style={{ borderColor: "var(--color-border)" }}>
                    <span className="text-[var(--color-text-primary)]">Flow Bytes/s</span>
                    <span className="text-[var(--color-accent)] font-bold">DoS / Exfiltration Driver</span>
                  </div>
                  <div className="flex items-center justify-between border-b pb-1.5" style={{ borderColor: "var(--color-border)" }}>
                    <span className="text-[var(--color-text-primary)]">Bwd Packet Length Mean</span>
                    <span className="text-[var(--color-accent)] font-bold">C2 Beaconing / Download Driver</span>
                  </div>
                  <div className="flex items-center justify-between border-b pb-1.5" style={{ borderColor: "var(--color-border)" }}>
                    <span className="text-[var(--color-text-primary)]">SYN / FIN Flag Ratio</span>
                    <span className="text-[var(--color-accent)] font-bold">Reconnaissance Sweep Driver</span>
                  </div>
                  <div className="flex items-center justify-between border-b pb-1.5" style={{ borderColor: "var(--color-border)" }}>
                    <span className="text-[var(--color-text-primary)]">Flow Inter-Arrival Time Std</span>
                    <span className="text-[var(--color-accent)] font-bold">Jittered Heartbeat Driver</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[var(--color-text-primary)]">Destination Port Entropy</span>
                    <span className="text-[var(--color-accent)] font-bold">PortScan Dispersal Driver</span>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === "features" && (
            <motion.div
              key="features"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="grid grid-cols-1 gap-6 lg:grid-cols-2"
            >
              <div className="flex flex-col gap-4">
                <h3 className="text-base font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
                  <Layers className="text-[var(--color-accent)]" size={18} />
                  Dual-Level Feature Representation (84 Dimensions)
                </h3>
                <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                  ShieldNet avoids relying solely on aggregate flow summaries by combining macro flow statistics with fine-grained packet burst dynamics, creating an 84-dimensional standardized state representation per time-window.
                </p>

                <div className="rounded-xl border p-4 font-mono text-xs bg-[var(--color-base)] text-[var(--color-text-primary)]" style={{ borderColor: "var(--color-border)" }}>
                  <div className="text-[var(--color-text-muted)] uppercase text-[10px] font-bold mb-1.5">
                    Feature Normalization &amp; Scaling:
                  </div>
                  <div className="text-xs text-[var(--color-normal)] font-bold mb-2">
                    z = (x - μ_train) / (σ_train + 1e-6), clamped to [-10.0, 10.0]
                  </div>
                  <p className="text-[11px] text-[var(--color-text-secondary)]">
                    Robust z-score scaling fitted exclusively on training distributions prevents data leakage while preserving heavy-tailed distribution anomalies.
                  </p>
                </div>
              </div>

              <div className="rounded-xl border p-5 bg-[var(--color-panel-raised)]" style={{ borderColor: "var(--color-border)" }}>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-accent)] mb-3">
                  Feature Breakdown by Category
                </h4>
                <div className="space-y-2 font-mono text-xs text-[var(--color-text-secondary)]">
                  <div className="flex justify-between border-b pb-1.5" style={{ borderColor: "var(--color-border)" }}>
                    <span>Flow Duration &amp; Rates (Bytes/s, Pkts/s)</span>
                    <span className="font-bold text-[var(--color-text-primary)]">12 features</span>
                  </div>
                  <div className="flex justify-between border-b pb-1.5" style={{ borderColor: "var(--color-border)" }}>
                    <span>Packet Length Statistics (Mean, Std, Max, Min)</span>
                    <span className="font-bold text-[var(--color-text-primary)]">24 features</span>
                  </div>
                  <div className="flex justify-between border-b pb-1.5" style={{ borderColor: "var(--color-border)" }}>
                    <span>TCP Flags &amp; Connection State (SYN, RST, PSH, ACK)</span>
                    <span className="font-bold text-[var(--color-text-primary)]">18 features</span>
                  </div>
                  <div className="flex justify-between border-b pb-1.5" style={{ borderColor: "var(--color-border)" }}>
                    <span>Inter-Arrival Time (IAT) Dynamics</span>
                    <span className="font-bold text-[var(--color-text-primary)]">23 features</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Packet Burst &amp; Payload Entropy Metrics</span>
                    <span className="font-bold text-[var(--color-accent)]">7 features</span>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === "fabric" && (
            <motion.div
              key="fabric"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="space-y-6 font-sans text-sm leading-relaxed text-[var(--color-text-secondary)]"
            >
              <div className="grid gap-6 lg:grid-cols-2">
                <div className="rounded-xl border p-5 bg-[var(--color-base)] space-y-3" style={{ borderColor: "var(--color-border)" }}>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-amber-400">
                    Cross-CII Collaborative Endorsement Architecture
                  </h4>
                  <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                    Rather than relying on isolated single-enterprise firewalls, ShieldNet links critical power substations (Wardha 765kV, Jabalpur 400kV, Indore 400kV) and the National Load Despatch Centre (NRLDC) into an immutable permissioned Hyperledger Fabric channel.
                  </p>
                  <ul className="space-y-2 text-xs font-mono text-[var(--color-text-primary)]">
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={13} className="text-amber-400 shrink-0" />
                      <span>2-of-3 Peer Endorsement Threshold before block commit</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={13} className="text-amber-400 shrink-0" />
                      <span>Crash Fault Tolerant (CFT) Raft Ordering Node</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={13} className="text-amber-400 shrink-0" />
                      <span>Sub-85ms Byzantine Gossip Protocol IoC Replication</span>
                    </li>
                  </ul>
                </div>

                <div className="rounded-xl border p-5 bg-[var(--color-base)] space-y-3" style={{ borderColor: "var(--color-border)" }}>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                    Dual-Tier Evidence Ledger
                  </h4>
                  <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                    Separates the Notary role (cryptographic audit proof) from the Executioner role (firewall boundary), guaranteeing that all SOAR automated mitigations are non-repudiable under Section 65B of the Indian Evidence Act.
                  </p>
                  <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] text-cyan-300">
                    Block_Hash = SHA256(Prev_Hash || MerkleRoot(Telemetry_DPI) || XAI_Attribution)
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === "auth" && (
            <motion.div
              key="auth"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="space-y-6 font-sans text-sm leading-relaxed text-[var(--color-text-secondary)]"
            >
              <div className="grid gap-6 lg:grid-cols-2">
                <div className="rounded-xl border p-5 bg-[var(--color-base)] space-y-3" style={{ borderColor: "var(--color-border)" }}>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-pink-400">
                    Standards-Compliant OAuth2 / Keycloak IdP
                  </h4>
                  <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                    ShieldNet embeds a full enterprise OpenID Connect (OIDC) identity provider with PBKDF2-HMAC-SHA256 user directories, RS256 cryptographic signing, and single-use refresh token rotation.
                  </p>
                  <ul className="space-y-2 text-xs font-mono text-[var(--color-text-primary)]">
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={13} className="text-pink-400 shrink-0" />
                      <span>RFC 7517 JSON Web Key Set (JWKS) public descriptor endpoint</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={13} className="text-pink-400 shrink-0" />
                      <span>OIDC Discovery Configuration (/.well-known/openid-configuration)</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle2 size={13} className="text-pink-400 shrink-0" />
                      <span>Zero-Trust Persona Switcher for instant SOC analyst evaluation</span>
                    </li>
                  </ul>
                </div>

                <div className="rounded-xl border p-5 bg-[var(--color-base)] space-y-3" style={{ borderColor: "var(--color-border)" }}>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                    4 Operational Clearance Roles (RBAC)
                  </h4>
                  <div className="space-y-2 font-mono text-xs">
                    <div className="flex justify-between border-b pb-1.5 border-slate-800">
                      <span className="font-bold text-rose-400">Level 5: CISO_Admin</span>
                      <span className="text-slate-300">Full Sovereign SOAR Policy Enforcement</span>
                    </div>
                    <div className="flex justify-between border-b pb-1.5 border-slate-800">
                      <span className="font-bold text-amber-400">Level 4: Forensic_Auditor</span>
                      <span className="text-slate-300">Read-Only Immutable Hash Verification</span>
                    </div>
                    <div className="flex justify-between border-b pb-1.5 border-slate-800">
                      <span className="font-bold text-cyan-400">Level 3: SecOps_Analyst</span>
                      <span className="text-slate-300">Alert Triage &amp; False-Positive Overrides</span>
                    </div>
                    <div className="flex justify-between border-slate-800">
                      <span className="font-bold text-slate-400">Level 2: Gateway_Ingress</span>
                      <span className="text-slate-300">Air-Gapped Telemetry Push Only</span>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* Summary Cards */}
      <section className="grid gap-6 lg:grid-cols-2">
        <article className="rounded-2xl border p-6 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
          <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-[var(--color-accent)] mb-2">
            <Zap size={14} />
            State Transitions Over Static Signatures
          </div>
          <h3 className="text-lg font-semibold text-[var(--color-text-primary)] mb-2">
            Why Signature-Based IDS Fails on Multi-Stage APTs
          </h3>
          <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
            Traditional signature IDS rules fire only when a known exploit string matches a payload, which is often too late when attacks leverage encrypted C2 channels or living-off-the-land techniques. The World Model treats the network as a continuous state-space dynamical system, detecting abnormal transition velocities across time windows.
          </p>
        </article>

        <article className="rounded-2xl border p-6 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
          <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-[var(--color-normal)] mb-2">
            <Lock size={14} />
            Critical Information Infrastructure (CII)
          </div>
          <h3 className="text-lg font-semibold text-[var(--color-text-primary)] mb-2">
            Power Grid &amp; Banking Network Defense (NTRO Scope)
          </h3>
          <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
            Critical infrastructure environments require strict air-gapped offline compliance (Constraint C4) and sub-5ms operational decisions. ShieldNet runs entirely on premise with zero cloud dependencies, enabling defensive teams to simulate and act before compromise becomes irreversible.
          </p>
        </article>
      </section>
    </div>
  );
}

