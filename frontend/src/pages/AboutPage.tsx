import { motion } from "framer-motion";
import { BrainCircuit, Database, Eye, Gauge, Layers3, ShieldCheck, Workflow, Lock, Server } from "lucide-react";

const techStack = [
  "PyTorch 2.6 (Neural World Model)",
  "FastAPI (Production Inference Backend)",
  "React 19 + Vite 8",
  "TypeScript",
  "Tailwind CSS v4 (Command-Center Design)",
  "Framer Motion (Hardware-Accelerated UI)",
  "Recharts (State Trajectory Visualization)",
  "Three.js (3D Particle Canvas)",
  "Integrated Gradients (Captum / Axiomatic XAI)",
  "Scapy & PyArrow (PCAP / Parquet Telemetry Engine)",
];

const pillars = [
  {
    icon: BrainCircuit,
    title: "Temporal World Model",
    text: "Learns continuous transition dynamics between network states instead of scoring isolated flows in a vacuum.",
  },
  {
    icon: Workflow,
    title: "Autoregressive Forecasting",
    text: "Rolls the transition model forward K steps to expose accelerating threat trajectories before full compromise.",
  },
  {
    icon: Eye,
    title: "Explainability by Design",
    text: "Strictly complies with Constraint C2, pairing every forecast with flow-level Integrated Gradients and MITRE killchain tactics.",
  },
];

export function AboutPage() {
  return (
    <div className="w-full flex flex-col gap-8 pb-16">
      {/* Hero Banner */}
      <motion.section
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45 }}
        className="relative overflow-hidden rounded-2xl border p-8 lg:p-12 glow-box"
        style={{
          borderColor: "var(--color-border)",
          background:
            "linear-gradient(135deg, var(--color-panel), color-mix(in srgb, var(--color-accent) 7%, var(--color-panel)))",
        }}
      >
        <div className="relative max-w-4xl">
          <div className="mb-4 inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-[var(--color-accent)] border-[var(--color-accent)]/30 bg-[var(--color-accent)]/10">
            <ShieldCheck size={13} />
            Smart India Hackathon 2026 · Problem Statement ShieldNet
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-[var(--color-text-primary)] sm:text-4xl lg:text-5xl">
            See the attack trajectory,<br />
            <span className="text-[var(--color-accent)]">not just the isolated alert.</span>
          </h1>
          <p className="mt-4 max-w-3xl text-sm leading-relaxed text-[var(--color-text-secondary)] sm:text-base">
            Conventional intrusion detection systems (IDS) evaluate incoming network packets in isolation, alerting defenders only after a malicious payload executes. ShieldNet models the temporal transition between network states — reconnaissance sweeps, credential brute force, command-and-control heartbeats, and lateral movement — forecasting future risk before compromise becomes irreversible.
          </p>
        </div>
      </motion.section>

      {/* Core Pillars */}
      <section className="grid gap-4 md:grid-cols-3">
        {pillars.map(({ icon: Icon, title, text }, i) => (
          <motion.article
            key={title}
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.05 }}
            className="rounded-xl border p-6 glow-box"
            style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
          >
            <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg bg-[var(--color-accent)]/10 text-[var(--color-accent)]">
              <Icon size={20} />
            </div>
            <h2 className="text-base font-semibold text-[var(--color-text-primary)]">{title}</h2>
            <p className="mt-2 text-xs leading-relaxed text-[var(--color-text-secondary)]">{text}</p>
          </motion.article>
        ))}
      </section>

      {/* Problem Context & Operational Scope */}
      <section className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
        <div className="rounded-2xl border p-6 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
          <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-[var(--color-accent)] mb-3">
            <Database size={15} />
            Mathematical State Transition Formulation
          </div>
          <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed mb-4">
            The neural world model estimates the continuous transition probability distribution of future network states conditioned on observed historical context:
          </p>
          <div className="rounded-xl border p-5 font-mono text-sm bg-[var(--color-base)] text-[var(--color-text-primary)]" style={{ borderColor: "var(--color-border)" }}>
            <div className="text-base font-bold text-[var(--color-accent)]">
              P(S_(t+1) | S_(t-L:t), a_t)
            </div>
            <p className="mt-2 text-xs text-[var(--color-text-secondary)] leading-relaxed">
              Where S_t represents the standardized 84-dimensional network state vector, L=3 represents historical context sequence length, and a_t represents active mitigation interventions.
            </p>
          </div>
        </div>

        <div className="rounded-2xl border p-6 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
          <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-[var(--color-accent)] mb-3">
            <Gauge size={15} />
            Multi-Step Forecast Horizons
          </div>
          <div className="space-y-2.5 font-mono text-xs">
            <div className="flex items-center justify-between rounded-lg border px-3.5 py-2.5 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
              <span className="text-[var(--color-text-muted)]">t (Current State)</span>
              <span className="text-[var(--color-text-primary)] font-bold">Observed Telemetry Window</span>
            </div>
            <div className="flex items-center justify-between rounded-lg border px-3.5 py-2.5 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
              <span className="text-[var(--color-accent)]">t+1 (Horizon +10s)</span>
              <span className="text-[var(--color-accent)] font-bold">Next State Estimation</span>
            </div>
            <div className="flex items-center justify-between rounded-lg border px-3.5 py-2.5 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
              <span className="text-[var(--color-elevated)]">t+K (Horizon +50s)</span>
              <span className="text-[var(--color-elevated)] font-bold">Autoregressive Trajectory</span>
            </div>
          </div>
        </div>
      </section>

      {/* Target Infrastructure & Problem Statement Specifics */}
      <section className="grid gap-4 lg:grid-cols-2">
        <article className="rounded-xl border p-6 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
          <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--color-accent)]/10 text-[var(--color-accent)]">
            <Layers3 size={18} />
          </div>
          <h3 className="text-base font-semibold text-[var(--color-text-primary)]">Dual-Level Telemetry Intelligence</h3>
          <p className="mt-2 text-xs leading-relaxed text-[var(--color-text-secondary)]">
            Volumetric floods and fast scans appear in aggregate flow rates and port sweeps. Stealthy APTs manifest in subtle inter-arrival timing jitter, packet length deviations, and connection persistence. ShieldNet extracts 77 flow statistics and 7 packet burst metrics to detect both vectors.
          </p>
        </article>

        <article className="rounded-xl border p-6 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
          <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--color-normal)]/10 text-[var(--color-normal)]">
            <Lock size={18} />
          </div>
          <h3 className="text-base font-semibold text-[var(--color-text-primary)]">Critical Information Infrastructure (CII)</h3>
          <p className="mt-2 text-xs leading-relaxed text-[var(--color-text-secondary)]">
            Designed for high-security environments like power grids, nuclear control facilities, and banking networks (NTRO scope) where cloud connectivity is prohibited. ShieldNet operates in 100% air-gapped offline environments with sub-5ms decision cycles.
          </p>
        </article>
      </section>

      {/* Technology Stack Grid */}
      <section>
        <div className="mb-3 text-xs font-mono uppercase tracking-wider text-[var(--color-text-muted)] flex items-center gap-2">
          <Server size={13} />
          Validated Engineering &amp; Technology Stack
        </div>
        <div className="flex flex-wrap gap-2.5">
          {techStack.map((item) => (
            <span
              key={item}
              className="rounded-lg border px-3.5 py-1.5 font-mono text-xs text-[var(--color-text-primary)] bg-[var(--color-panel)]"
              style={{ borderColor: "var(--color-border)" }}
            >
              {item}
            </span>
          ))}
        </div>
      </section>
    </div>
  );
}

