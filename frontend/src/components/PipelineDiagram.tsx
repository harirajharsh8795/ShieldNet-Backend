import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Database,
  ShieldCheck,
  BrainCircuit,
  Route,
  Blocks,
  Network,
  Lock,
  ArrowRight,
  Zap,
  CheckCircle2,
  Cpu
} from "lucide-react";

interface PipelineStage {
  id: string;
  step: string;
  name: string;
  shortName: string;
  layer: "data" | "model" | "rollout" | "blockchain" | "explain" | "auth";
  color: string;
  accentHex: string;
  glow: string;
  badge: string;
  subtitle: string;
  formula: string;
  techSpecs: string[];
  description: string;
  icon: any;
}

const PIPELINE_STAGES: PipelineStage[] = [
  {
    id: "stage_ingest",
    step: "01",
    name: "Multi-Source Telemetry Ingestion & Schema Adapter",
    shortName: "Ingestion & Schema Adapter",
    layer: "data",
    color: "text-cyan-400",
    accentHex: "#06B6D4",
    glow: "rgba(6,182,212,0.4)",
    badge: "77 Flow + 7 Packet (84-Dim)",
    subtitle: "PCAP DPI + NetFlow + CICIoT2023 + LANL Auth Logs",
    formula: "\\mathbf{x}_t = \\text{Adapter}(\\text{PCAP} \\oplus \\text{NetFlow} \\oplus \\text{Auth}) \\in \\mathbb{R}^{84}",
    techSpecs: [
      "Deep Packet Inspection (DPI) via Scapy (TTL variance, TCP window)",
      "CICIoT2023 46-feature IoT schema deterministic mapping",
      "LANL Kerberos/NTLM authentication sliding-window fuser (±5s alignment)",
      "Universal CrossDatasetSchemaAdapter with auto-signature detection"
    ],
    description: "Ingests raw pcap captures, NetFlow streams, IoT flow telemetry, and enterprise authentication event logs. Translates disparate formats into a unified 84-dimensional continuous state vector.",
    icon: Database,
  },
  {
    id: "stage_guard",
    step: "02",
    name: "Production Guards & OOD Drift Detector",
    shortName: "Scaler Guard & OOD Detector",
    layer: "data",
    color: "text-purple-400",
    accentHex: "#A855F7",
    glow: "rgba(168,85,247,0.4)",
    badge: "Z-Score Drift Gate",
    subtitle: "Frozen Reference Scaler + Dynamic PCAP Imputer",
    formula: "Z_{\\text{drift}} = \\|(\\mathbf{x}_t - \\boldsymbol{\\mu}_{\\text{ref}}) / \\boldsymbol{\\sigma}_{\\text{ref}}\\|_2 > \\tau_{\\text{ood}}",
    techSpecs: [
      "Frozen Reference Scaler: Strict 84-channel baseline freezing (Zero-Leakage)",
      "Dynamic PCAP Imputer: Imputes packet micro-dynamics from flow burst physics",
      "Multivariate Z-Score OOD boundary with automated probability penalty",
      "Explainable drift attribution for security analyst telemetry review"
    ],
    description: "Prevents model hallucination during covariate network shifts. Computes statistical deviations from in-distribution baselines and flags anomalous telemetry before passing to neural layers.",
    icon: ShieldCheck,
  },
  {
    id: "stage_world_model",
    step: "03",
    name: "Dual-Engine Neural World Model Ensemble",
    shortName: "Dual-Engine World Model",
    layer: "model",
    color: "text-emerald-400",
    accentHex: "#10B981",
    glow: "rgba(16,185,129,0.4)",
    badge: "90.64% Balanced Acc (21.52M Param)",
    subtitle: "60% GRU+Attn Backbone + 40% Instantaneous Linear",
    formula: "\\mathbf{P}(y) = \\text{Calibrate}(0.6 \\cdot \\mathbf{P}_{\\text{WM}} + 0.4 \\cdot \\mathbf{P}_{\\text{Tabular}})",
    techSpecs: [
      "2-Layer GRU Backbone (128 hidden) with Multi-Head Temporal Attention Pooling",
      "Instantaneous Tabular Linear Classifier for sharp zero-day boundary detection",
      "Nelder-Mead Optimal Class Calibration: 90.64% Balanced Acc, 97.85% Overall Acc",
      "0.0155 ms inference latency (64,000 predictions/sec throughput)"
    ],
    description: "ShieldNet's champion dual-engine neural architecture. Blends temporal historical memory (30s context window) with instantaneous packet metrics, eliminating RNN bias on rare tail-class intrusions.",
    icon: BrainCircuit,
  },
  {
    id: "stage_rollout",
    step: "04",
    name: "Autoregressive K-Step Rollout & Counterfactual Engine",
    shortName: "K-Step Rollout & CF Engine",
    layer: "rollout",
    color: "text-rose-400",
    accentHex: "#F43F5E",
    glow: "rgba(244,63,94,0.4)",
    badge: "4.03 ms 5-Step Horizon",
    subtitle: "Autoregressive s_t → s_{t+K} + Minimal Intervention Δs",
    formula: "\\hat{\\mathbf{s}}_{t+k} = f_{\\theta}(\\hat{\\mathbf{s}}_{t+k-1}), \\quad \\min_{\\Delta \\mathbf{s}} \\|\\Delta \\mathbf{s}\\|_2 \\text{ s.t. } \\mathbf{P}_{\\text{attack}} < 0.15",
    techSpecs: [
      "Autoregressive Latent Space Rollout across K=1 to K=10 future horizons",
      "Bayesian Confidence Decay Model: C(k) = \\max(0.50, 1.0 - 0.06k)",
      "Counterfactual Gradient Engine: Euler/Adam optimizer for minimal feature perturbation",
      "Preserves network operational invariants while neutralizing threat vector"
    ],
    description: "Forecasts future network states before attacker payload execution completes. Simultaneously optimizes a counterfactual trajectory to identify the exact minimum firewall intervention needed to de-escalate the attack.",
    icon: Route,
  },
  {
    id: "stage_ledger",
    step: "05",
    name: "Dual-Tier Blockchain Ledger & Cross-CII Consensus",
    shortName: "SIERL & Fabric Consortium",
    layer: "blockchain",
    color: "text-amber-400",
    accentHex: "#F59E0B",
    glow: "rgba(245,158,11,0.4)",
    badge: "2-of-3 Raft Consensus",
    subtitle: "SHA-256 Merkle Chain + 3-Node Hyperledger Fabric",
    formula: "H_b = \\text{SHA256}(H_{b-1} \\parallel \\text{MerkleRoot}(\\text{Evidence}) \\parallel \\text{Signatures}_{2/3})",
    techSpecs: [
      "Tier 1: Single-Node SIERL Hash Chain (SHA-256 Merkle root, SQLite fallback)",
      "Tier 2: 3-Substation Cross-CII Hyperledger Fabric Network (Wardha, Jabalpur, Indore)",
      "Crash Fault Tolerant (CFT) Raft Orderer Node (NRLDC) with Gossip Protocol replication",
      "Immutable False-Positive Retraining Ledger for human analyst audit overrides"
    ],
    description: "Provides tamper-proof legal evidence anchoring (Section 65B Indian Evidence Act compliant). Collaborative Cross-CII consensus allows interconnected power substations to endorse and replicate threat IoCs within 85ms.",
    icon: Blocks,
  },
  {
    id: "stage_mitre",
    step: "06",
    name: "Symbolic MITRE Knowledge Graph & SOAR Defense",
    shortName: "MITRE KG & SOAR Defense",
    layer: "explain",
    color: "text-sky-400",
    accentHex: "#38BDF8",
    glow: "rgba(56,189,248,0.4)",
    badge: "Axiomatic Completeness",
    subtitle: "Integrated Gradients + Automated iptables/ACL Rules",
    formula: "\\sum_{i=1}^{84} \\phi_i = F(\\mathbf{x}) - F(\\mathbf{x}'), \\quad \\phi_i \\to \\text{Graph}(\\text{Tactics} \\to \\text{Techniques})",
    techSpecs: [
      "Integrated Gradients Axiomatic Attribution (m=100 Riemann approximation steps)",
      "Symbolic MITRE ATT&CK & CAPEC Knowledge Graph directed causal traversal",
      "Dynamic SOAR Rule Synthesis: Cisco ACL, Linux iptables, and Suricata signatures",
      "Proactive projected risk reduction rating (mean -84.6% risk reduction)"
    ],
    description: "Transforms deep neural weights into crystal-clear human explanations. Links numerical feature attributions to MITRE tactics and immediately generates syntactically correct firewall block rules.",
    icon: Network,
  },
  {
    id: "stage_auth",
    step: "07",
    name: "Zero-Trust Enterprise IdP & SecOps Cockpit",
    shortName: "Zero-Trust IdP & Cockpit",
    layer: "auth",
    color: "text-pink-400",
    accentHex: "#EC4899",
    glow: "rgba(236,72,153,0.4)",
    badge: "OIDC RFC 7517 + 4 Clearances",
    subtitle: "Keycloak OAuth2 JWT + Role-Based Access Control",
    formula: "\\text{JWT} = \\text{Sign}_{\\text{RS256}}(\\text{Header} \\parallel \\text{Claims}_{\\text{Clearance}})",
    techSpecs: [
      "Enterprise OAuth2 / Keycloak-compatible IdP Server (Password Grant & Refresh Token)",
      "4 Operational Clearance Roles: CISO_Admin (L5), SecOps_Analyst (L3), Auditor (L4), Gateway (L2)",
      "Cryptographic RS256 JWKS Key Descriptors & OIDC Discovery Metadata (.well-known)",
      "Interactive 60 FPS React Dashboard: 100% Offline-Capable (Constraint C4 Compliance)"
    ],
    description: "Enterprise zero-trust perimeter protecting critical grid operations. Enforces strict role-based access control so only cleared CISO admins can trigger firewall drops while analysts inspect evidence.",
    icon: Lock,
  },
];

export function PipelineDiagram() {
  const [selectedStageId, setSelectedStageId] = useState<string>("stage_world_model");
  const [selectedFilter, setSelectedFilter] = useState<string>("all");

  const activeStage = PIPELINE_STAGES.find((s) => s.id === selectedStageId) || PIPELINE_STAGES[2];

  const filteredStages = PIPELINE_STAGES.filter((s) => {
    if (selectedFilter === "all") return true;
    if (selectedFilter === "ai") return s.layer === "model" || s.layer === "rollout";
    if (selectedFilter === "data") return s.layer === "data";
    if (selectedFilter === "trust") return s.layer === "blockchain" || s.layer === "explain" || s.layer === "auth";
    return true;
  });

  return (
    <div className="w-full flex flex-col gap-6">
      {/* Category Filter Pills */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex flex-wrap items-center gap-2">
          {[
            { id: "all", label: "All End-to-End Pipeline (7 Stages)" },
            { id: "data", label: "📥 Ingestion & Safety Guards (2)" },
            { id: "ai", label: "🧠 AI World Model & Rollout (2)" },
            { id: "trust", label: "🔐 Trust, Consensus & SOAR (3)" },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setSelectedFilter(tab.id)}
              className={`px-3 py-1.5 rounded-lg font-mono text-xs font-semibold transition-all ${
                selectedFilter === tab.id
                  ? "bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20"
                  : "bg-slate-900 text-slate-300 hover:text-white border border-slate-700 hover:border-slate-500"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <span className="font-mono text-xs text-emerald-400 bg-emerald-500/10 px-3 py-1 rounded border border-emerald-500/30 flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          Full Operational Integrity
        </span>
      </div>

      {/* Horizontal High-Contrast Interactive Stage Cards */}
      <div className="w-full overflow-x-auto pb-4 pt-1">
        <div className="flex items-stretch gap-3 min-w-[1240px]">
          {filteredStages.map((stage, i) => {
            const isSelected = selectedStageId === stage.id;
            const Icon = stage.icon;

            return (
              <div key={stage.id} className="flex items-center">
                {/* Stage Interactive Card */}
                <div
                  onClick={() => setSelectedStageId(stage.id)}
                  onMouseEnter={() => setSelectedStageId(stage.id)}
                  className={`group relative flex flex-col justify-between w-[168px] h-[190px] rounded-xl p-4 cursor-pointer transition-all duration-200 select-none hover:-translate-y-1 ${
                    isSelected
                      ? "bg-slate-900 border-2 shadow-lg"
                      : "bg-slate-950/90 border hover:bg-slate-900/80 hover:border-slate-500"
                  }`}
                  style={{
                    borderColor: isSelected ? stage.accentHex : "#334155",
                    boxShadow: isSelected ? `0 0 20px ${stage.glow}, inset 0 0 12px ${stage.glow}` : "none",
                  }}
                >
                  {/* Top header: step number + icon */}
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-slate-400">
                      {stage.step}
                    </span>
                    <div
                      className="rounded-lg p-2 transition-all group-hover:scale-110"
                      style={{
                        backgroundColor: `${stage.accentHex}20`,
                        color: stage.accentHex,
                        border: `1px solid ${stage.accentHex}40`,
                      }}
                    >
                      <Icon size={16} />
                    </div>
                  </div>

                  {/* Stage Name */}
                  <div>
                    <h3 className="text-xs font-bold text-white leading-tight group-hover:text-cyan-300">
                      {stage.shortName}
                    </h3>
                    <p className="font-mono text-[9px] text-slate-400 mt-1 line-clamp-2">
                      {stage.subtitle}
                    </p>
                  </div>

                  {/* Bottom Pill Badge */}
                  <div className="mt-2">
                    <span
                      className="block truncate rounded-md px-1.5 py-0.5 font-mono text-[9.5px] font-semibold text-center"
                      style={{
                        backgroundColor: `${stage.accentHex}18`,
                        color: stage.accentHex,
                        border: `1px solid ${stage.accentHex}35`,
                      }}
                    >
                      {stage.badge}
                    </span>
                  </div>

                  {/* Selected indicator triangle */}
                  {isSelected && (
                    <div
                      className="absolute -bottom-2 left-1/2 -translate-x-1/2 w-0 h-0 border-l-[6px] border-l-transparent border-r-[6px] border-r-transparent border-t-[8px]"
                      style={{ borderTopColor: stage.accentHex }}
                    />
                  )}
                </div>

                {/* Animated Arrow Connector */}
                {i < filteredStages.length - 1 && (
                  <div className="flex items-center px-1.5 text-slate-500">
                    <ArrowRight size={15} className="animate-pulse text-cyan-400/70" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Stage Deep-Dive Architectural Spec Drawer */}
      <AnimatePresence mode="wait">
        {activeStage && (
          <motion.div
            key={activeStage.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.15 }}
            className="rounded-2xl border p-6 bg-slate-900/90 shadow-2xl relative overflow-hidden"
            style={{ borderColor: activeStage.accentHex }}
          >
            {/* Top accent glow line */}
            <div
              className="absolute top-0 left-0 right-0 h-1"
              style={{ backgroundColor: activeStage.accentHex }}
            />

            <div className="flex flex-col lg:flex-row items-start justify-between gap-6">
              {/* Left Column: Title, Description, Formula */}
              <div className="space-y-4 max-w-2xl">
                <div className="flex items-center gap-3">
                  <span
                    className="font-mono text-xs font-bold px-2.5 py-1 rounded-md"
                    style={{
                      backgroundColor: `${activeStage.accentHex}25`,
                      color: activeStage.accentHex,
                      border: `1px solid ${activeStage.accentHex}50`,
                    }}
                  >
                    STAGE {activeStage.step}
                  </span>
                  <h3 className="text-lg font-bold text-white">{activeStage.name}</h3>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {activeStage.description}
                </p>

                {/* Mathematical Formulation Box */}
                <div className="rounded-xl border border-slate-800 bg-slate-950 p-3.5 font-mono text-xs">
                  <div className="text-[10px] text-slate-400 uppercase font-semibold mb-1 flex items-center gap-1.5">
                    <Cpu size={12} className="text-cyan-400" />
                    <span>Mathematical Invariant &amp; Formulation</span>
                  </div>
                  <code className="text-cyan-300 font-semibold text-[11px] block overflow-x-auto py-1">
                    {activeStage.formula}
                  </code>
                </div>
              </div>

              {/* Right Column: Verified Technical Specifications */}
              <div className="w-full lg:w-[420px] rounded-xl border border-slate-800 bg-slate-950/80 p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="font-mono text-xs font-bold text-white flex items-center gap-1.5">
                    <Zap size={14} style={{ color: activeStage.accentHex }} />
                    Verified Technical Specifications
                  </span>
                  <span
                    className="font-mono text-[10px] font-bold px-2 py-0.5 rounded"
                    style={{ backgroundColor: `${activeStage.accentHex}20`, color: activeStage.accentHex }}
                  >
                    {activeStage.badge}
                  </span>
                </div>

                <ul className="space-y-2 font-mono text-xs text-slate-300">
                  {activeStage.techSpecs.map((spec, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <CheckCircle2 size={13} className="shrink-0 mt-0.5" style={{ color: activeStage.accentHex }} />
                      <span className="leading-snug">{spec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
