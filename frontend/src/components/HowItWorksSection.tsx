import { motion } from "framer-motion";
import { Gauge } from "lucide-react";

interface StepProps {
  number: string;
  title: string;
  description: string;
  inputLabel: string;
  inputItems?: string[];
  visualization: "flow" | "temporal" | "risk" | "mapping";
  index: number;
}

function StepVisualization({ type }: { type: "flow" | "temporal" | "risk" | "mapping" }) {
  if (type === "flow") {
    return (
      <motion.svg
        viewBox="0 0 280 100"
        className="w-full h-20"
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ delay: 0.3 }}
      >
        {/* CSV box */}
        <rect x="10" y="35" width="45" height="30" rx="4" fill="color-mix(in srgb, var(--color-accent) 15%, transparent)" stroke="var(--color-accent)" strokeWidth="1.5" />
        <text x="32.5" y="55" textAnchor="middle" fontSize="10" fill="var(--color-accent)" fontWeight="500">CSV</text>

        {/* Arrow 1 */}
        <motion.g initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} transition={{ delay: 0.5 }}>
          <line x1="55" y1="50" x2="85" y2="50" stroke="var(--color-accent)" strokeWidth="2" />
          <polygon points="85,50 80,47 82,50 80,53" fill="var(--color-accent)" />
        </motion.g>

        {/* PCAP box */}
        <rect x="85" y="35" width="45" height="30" rx="4" fill="color-mix(in srgb, var(--color-normal) 15%, transparent)" stroke="var(--color-normal)" strokeWidth="1.5" />
        <text x="107.5" y="55" textAnchor="middle" fontSize="10" fill="var(--color-normal)" fontWeight="500">PCAP</text>

        {/* Arrow 2 */}
        <motion.g initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} transition={{ delay: 0.7 }}>
          <line x1="130" y1="50" x2="160" y2="50" stroke="var(--color-accent)" strokeWidth="2" />
          <polygon points="160,50 155,47 157,50 155,53" fill="var(--color-accent)" />
        </motion.g>

        {/* Local Data box */}
        <rect x="160" y="35" width="100" height="30" rx="4" fill="color-mix(in srgb, var(--color-elevated) 15%, transparent)" stroke="var(--color-elevated)" strokeWidth="1.5" />
        <text x="210" y="55" textAnchor="middle" fontSize="10" fill="var(--color-elevated)" fontWeight="500">Local Data</text>
      </motion.svg>
    );
  }

  if (type === "temporal") {
    return (
      <motion.svg
        viewBox="0 0 280 100"
        className="w-full h-20"
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ delay: 0.3 }}
      >
        {/* Past */}
        <circle cx="50" cy="50" r="8" fill="color-mix(in srgb, var(--color-text-muted) 40%, transparent)" stroke="var(--color-text-muted)" strokeWidth="1.5" />
        <text x="50" y="68" textAnchor="middle" fontSize="9" fill="var(--color-text-muted)">Past</text>

        {/* Arrow 1 */}
        <motion.g initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} transition={{ delay: 0.5 }}>
          <line x1="60" y1="50" x2="120" y2="50" stroke="var(--color-accent)" strokeWidth="2" strokeDasharray="4,4" />
        </motion.g>

        {/* Current */}
        <circle cx="140" cy="50" r="10" fill="color-mix(in srgb, var(--color-accent) 25%, transparent)" stroke="var(--color-accent)" strokeWidth="2" />
        <text x="140" y="70" textAnchor="middle" fontSize="9" fill="var(--color-accent)" fontWeight="600">Current</text>

        {/* Arrow 2 */}
        <motion.g initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} transition={{ delay: 0.7 }}>
          <line x1="152" y1="50" x2="210" y2="50" stroke="var(--color-normal)" strokeWidth="2" />
          <polygon points="210,50 205,47 207,50 205,53" fill="var(--color-normal)" />
        </motion.g>

        {/* Future */}
        <circle cx="230" cy="50" r="8" fill="color-mix(in srgb, var(--color-normal) 40%, transparent)" stroke="var(--color-normal)" strokeWidth="1.5" />
        <text x="230" y="68" textAnchor="middle" fontSize="9" fill="var(--color-normal)">Future</text>
      </motion.svg>
    );
  }

  if (type === "risk") {
    return (
      <motion.svg
        viewBox="0 0 280 100"
        className="w-full h-20"
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ delay: 0.3 }}
      >
        {/* Grid background */}
        <line x1="20" y1="60" x2="260" y2="60" stroke="var(--color-border)" strokeWidth="1" opacity="0.3" />
        <line x1="20" y1="40" x2="260" y2="40" stroke="var(--color-border)" strokeWidth="1" opacity="0.3" />
        <line x1="20" y1="20" x2="260" y2="20" stroke="var(--color-border)" strokeWidth="1" opacity="0.3" />

        {/* Y-axis label */}
        <text x="10" y="65" fontSize="8" fill="var(--color-text-muted)">Risk</text>

        {/* X-axis */}
        <line x1="20" y1="65" x2="260" y2="65" stroke="var(--color-border)" strokeWidth="1" />

        {/* Current point marker */}
        <circle cx="80" cy="55" r="3" fill="var(--color-accent)" />
        <line x1="80" y1="65" x2="80" y2="70" stroke="var(--color-accent)" strokeWidth="1" opacity="0.5" />
        <text x="80" y="82" textAnchor="middle" fontSize="8" fill="var(--color-accent)" fontWeight="500">Now</text>

        {/* Rising risk line */}
        <motion.polyline
          points="80,55 120,50 160,35 200,15 240,8"
          fill="none"
          stroke="var(--color-critical)"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          initial={{ pathLength: 0 }}
          whileInView={{ pathLength: 1 }}
          transition={{ delay: 0.5, duration: 1 }}
          viewport={{ once: true }}
        />

        {/* K-step future marker */}
        <circle cx="240" cy="8" r="4" fill="var(--color-critical)" opacity="0.6" />
        <text x="240" y="85" textAnchor="middle" fontSize="8" fill="var(--color-critical)" fontWeight="500">K Steps</text>

        {/* Alert indicator */}
        <motion.g
          initial={{ opacity: 0, scale: 0 }}
          whileInView={{ opacity: 1, scale: 1 }}
          transition={{ delay: 1, duration: 0.3 }}
          viewport={{ once: true }}
        >
          <rect x="160" y="8" width="20" height="16" rx="2" fill="var(--color-critical)" opacity="0.2" stroke="var(--color-critical)" strokeWidth="1" />
          <text x="170" y="18" textAnchor="middle" fontSize="8" fill="var(--color-critical)" fontWeight="600">⚠</text>
        </motion.g>
      </motion.svg>
    );
  }

  if (type === "mapping") {
    return (
      <motion.svg
        viewBox="0 0 280 100"
        className="w-full h-20"
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ delay: 0.3 }}
      >
        {/* Top Features box */}
        <rect x="15" y="8" width="60" height="24" rx="3" fill="color-mix(in srgb, var(--color-accent) 15%, transparent)" stroke="var(--color-accent)" strokeWidth="1" />
        <text x="45" y="22" textAnchor="middle" fontSize="9" fill="var(--color-accent)" fontWeight="500">Features</text>

        {/* Arrow down */}
        <motion.g initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} transition={{ delay: 0.5 }}>
          <line x1="45" y1="32" x2="45" y2="44" stroke="var(--color-accent)" strokeWidth="2" />
          <polygon points="45,44 42,39 45,41 48,39" fill="var(--color-accent)" />
        </motion.g>

        {/* Risk Explanation box */}
        <rect x="15" y="44" width="60" height="24" rx="3" fill="color-mix(in srgb, var(--color-normal) 15%, transparent)" stroke="var(--color-normal)" strokeWidth="1" />
        <text x="45" y="58" textAnchor="middle" fontSize="9" fill="var(--color-normal)" fontWeight="500">Risk Expl.</text>

        {/* Arrow down */}
        <motion.g initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} transition={{ delay: 0.7 }}>
          <line x1="45" y1="68" x2="45" y2="80" stroke="var(--color-accent)" strokeWidth="2" />
          <polygon points="45,80 42,75 45,77 48,75" fill="var(--color-accent)" />
        </motion.g>

        {/* MITRE box */}
        <rect x="15" y="80" width="60" height="16" rx="3" fill="color-mix(in srgb, var(--color-elevated) 15%, transparent)" stroke="var(--color-elevated)" strokeWidth="1" />
        <text x="45" y="90" textAnchor="middle" fontSize="8" fill="var(--color-elevated)" fontWeight="500">MITRE ATT&CK</text>

        {/* Right side MITRE tactics */}
        <motion.g initial={{ opacity: 0, x: 20 }} whileInView={{ opacity: 1, x: 0 }} transition={{ delay: 0.9 }}>
          <text x="100" y="22" fontSize="8" fill="var(--color-text-secondary)" fontWeight="500">Reconnaissance</text>
          <text x="100" y="40" fontSize="8" fill="var(--color-text-secondary)" fontWeight="500">Lateral Movement</text>
          <text x="100" y="58" fontSize="8" fill="var(--color-text-secondary)" fontWeight="500">Command & Control</text>
          <text x="100" y="76" fontSize="8" fill="var(--color-text-secondary)" fontWeight="500">Exfiltration</text>
        </motion.g>

        {/* Connection lines */}
        <motion.g initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} transition={{ delay: 1 }}>
          <line x1="75" y1="22" x2="100" y2="22" stroke="var(--color-border)" strokeWidth="1" opacity="0.4" strokeDasharray="2,2" />
          <line x1="75" y1="40" x2="100" y2="40" stroke="var(--color-border)" strokeWidth="1" opacity="0.4" strokeDasharray="2,2" />
          <line x1="75" y1="58" x2="100" y2="58" stroke="var(--color-border)" strokeWidth="1" opacity="0.4" strokeDasharray="2,2" />
          <line x1="75" y1="76" x2="100" y2="76" stroke="var(--color-border)" strokeWidth="1" opacity="0.4" strokeDasharray="2,2" />
        </motion.g>
      </motion.svg>
    );
  }

  return null;
}

function Step({ number, title, description, inputLabel, inputItems, visualization, index }: StepProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.15 }}
      transition={{ duration: 0.5, delay: index * 0.12, ease: "easeOut" }}
      className="flex flex-col h-full"
    >
      <div className="rounded-2xl border backdrop-blur-sm transition-all duration-300 glow-box overflow-hidden group hover:border-[var(--color-accent)] h-full flex flex-col"
        style={{
          borderColor: "var(--color-border)",
          backgroundColor: "color-mix(in srgb, var(--color-panel) 85%, transparent)",
          boxShadow: "0 0 32px -8px rgba(34, 211, 238, 0.0), inset 0 0 32px -16px rgba(34, 211, 238, 0.03)"
        }}
      >
        {/* Hover glow effect */}
        <div className="pointer-events-none absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            boxShadow: "inset 0 0 24px rgba(34, 211, 238, 0.15)"
          }}
        />

        <div className="relative z-10 p-6 flex flex-col h-full">
          {/* Step number */}
          <div className="flex items-center gap-3 mb-4">
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              whileInView={{ scale: 1, opacity: 1 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.12 + 0.2 }}
              className="inline-flex items-center justify-center h-10 w-10 rounded-lg font-mono text-sm font-bold"
              style={{
                background: "linear-gradient(135deg, var(--color-accent) 0%, color-mix(in srgb, var(--color-accent) 60%, transparent) 100%)",
                color: "var(--color-base)",
                boxShadow: "0 0 16px rgba(34, 211, 238, 0.3)"
              }}
            >
              {number}
            </motion.div>
          </div>

          {/* Title */}
          <h3 className="text-xl font-semibold text-[var(--color-text-primary)] mb-2 group-hover:text-[var(--color-accent)] transition-colors duration-300">
            {title}
          </h3>

          {/* Description */}
          <p className="text-sm leading-relaxed text-[var(--color-text-secondary)] mb-5">
            {description}
          </p>

          {/* Visualization */}
          <div className="mb-5 p-4 rounded-lg border"
            style={{
              borderColor: "color-mix(in srgb, var(--color-border) 50%, transparent)",
              backgroundColor: "color-mix(in srgb, var(--color-accent) 3%, transparent)"
            }}
          >
            <StepVisualization type={visualization} />
          </div>

          {/* Input label */}
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true }}
            transition={{ delay: index * 0.12 + 0.4 }}
            className="pt-4 border-t mt-auto"
            style={{
              borderColor: "color-mix(in srgb, var(--color-border) 50%, transparent)"
            }}
          >
            <p className="text-xs uppercase tracking-widest text-[var(--color-text-muted)] mb-2 font-semibold">
              {inputLabel}
            </p>
            {inputItems && (
              <p className="text-sm text-[var(--color-text-secondary)] font-medium">
                {inputItems.join(" • ")}
              </p>
            )}
          </motion.div>
        </div>
      </div>
    </motion.div>
  );
}

export function HowItWorksSection() {
  const steps: StepProps[] = [
    {
      number: "01",
      title: "Dual-Scale Telemetry Ingestion",
      description: "Extracts micro-packet dynamics (inter-arrival jitter, packet lengths) and macro-flow metrics into an 84-dimensional canonical state S_t with FrozenReferenceScalerGuard.",
      inputLabel: "Telemetry Ingestion & State Space",
      inputItems: ["Raw PCAP", "NetFlow CSV", "84-Dim State S_t"],
      visualization: "flow",
      index: 0,
    },
    {
      number: "02",
      title: "Recurrent State-Space World Model",
      description: "A 2-layer GRU backbone augmented with Multi-Head Temporal Self-Attention learns continuous state transition dynamics P(S_{t+1}|S_t) across 30s historical windows.",
      inputLabel: "Neural World Model Core",
      inputItems: ["2-Layer GRU", "Self-Attention", "State Transition P(S_{t+1}|S_t)"],
      visualization: "temporal",
      index: 1,
    },
    {
      number: "03",
      title: "K-Step Forward Horizon Rollout",
      description: "Autoregressively projects latent network states 50 seconds ahead (K=5), forecasting rising threat probability and mapping trajectories to MITRE ATT&CK lifecycle stages.",
      inputLabel: "Pre-Emptive Latent Simulation",
      inputItems: ["Horizon Rollout K=5", "MITRE Lifecycle", "Threat Forecast P(Attack)"],
      visualization: "risk",
      index: 2,
    },
    {
      number: "04",
      title: "SHAP Explainability & Defense Sandbox",
      description: "Decomposes forecasts into exact signed SHAP feature attributions (ϕ_i) and runs 'What-If' counterfactual policy simulations before deploying 1-click firewall containment.",
      inputLabel: "Axiomatic Attribution & Containment",
      inputItems: ["SHAP (ϕ_i)", "What-If Sandbox", "1-Click iptables / netsh"],
      visualization: "mapping",
      index: 3,
    },
  ];

  return (
    <motion.section
      id="how-it-works"
      initial={{ opacity: 0, y: 32 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.1 }}
      transition={{ duration: 0.6, ease: "easeOut" }}
      className="mt-20 py-4"
    >
      {/* Section Header */}
      <motion.div
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true, amount: 0.3 }}
        transition={{ duration: 0.5 }}
        className="mb-12"
      >
        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.3em] text-[var(--color-text-secondary)] mb-4">
          <Gauge size={14} style={{ color: "var(--color-accent)" }} />
          How ShieldNet Operates
        </div>
        <h2 className="text-4xl sm:text-5xl font-semibold tracking-tight text-[var(--color-text-primary)] mb-3">
          From Raw Telemetry to Pre-Emptive Sovereign Defense
        </h2>
        <p className="text-lg text-[var(--color-text-secondary)] max-w-3xl leading-relaxed">
          The 4 core stages of ShieldNet: Dual-scale packet ingestion, recurrent state-space World Modeling, K-step forward latent forecasting, and axiomatic SHAP explainability with automated firewall containment.
        </p>
      </motion.div>

      {/* Steps Grid with Pipeline */}
      <div className="grid gap-6 lg:gap-6 grid-cols-1 md:grid-cols-2 lg:grid-cols-4">
        {steps.map((step) => (
          <div key={step.number}>
            <Step {...step} />
          </div>
        ))}
      </div>

      {/* Mobile vertical pipeline visualization */}
      <motion.div
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ delay: 0.5 }}
        className="xl:hidden mt-8 pt-8 text-center"
      >
        <p className="text-xs uppercase tracking-widest text-[var(--color-text-muted)] mb-4">Pipeline Flow</p>
        <svg
          viewBox="0 0 60 180"
          className="w-12 h-48 mx-auto"
          style={{ color: "var(--color-accent)" }}
        >
          <g stroke="currentColor" strokeWidth="2" fill="none">
            <circle cx="30" cy="15" r="4" fill="currentColor" />
            <line x1="30" y1="20" x2="30" y2="45" markerEnd="url(#arrowsmall)" />

            <circle cx="30" cy="60" r="4" fill="currentColor" />
            <line x1="30" y1="65" x2="30" y2="90" markerEnd="url(#arrowsmall)" />

            <circle cx="30" cy="105" r="4" fill="currentColor" />
            <line x1="30" y1="110" x2="30" y2="135" markerEnd="url(#arrowsmall)" />

            <circle cx="30" cy="150" r="4" fill="currentColor" />
          </g>
          <defs>
            <marker id="arrowsmall" markerWidth="4" markerHeight="4" refX="2" refY="2" orient="auto">
              <polygon points="0,0 4,2 0,4" fill="currentColor" />
            </marker>
          </defs>
        </svg>
      </motion.div>
    </motion.section>
  );
}
