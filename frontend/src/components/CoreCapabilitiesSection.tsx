import { motion } from "framer-motion";
import { Brain, TrendingUp, Map, Lightbulb, Zap, Lock, Sparkles } from "lucide-react";

interface CapabilityCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  impact: string;
  isNew?: boolean;
  index: number;
}

function CapabilityCard({ icon, title, description, impact, isNew, index }: CapabilityCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2 }}
      transition={{ duration: 0.5, delay: index * 0.1, ease: "easeOut" }}
      whileHover={{ y: -8, transition: { duration: 0.3 } }}
      className="group relative h-full"
    >
      <div className="relative h-full rounded-2xl border p-6 backdrop-blur-sm transition-all duration-300 glow-box hover:border-[var(--color-accent)]"
        style={{
          borderColor: "var(--color-border)",
          backgroundColor: "color-mix(in srgb, var(--color-panel) 80%, transparent)",
          boxShadow: "0 0 32px -8px rgba(34, 211, 238, 0.0), inset 0 0 32px -16px rgba(34, 211, 238, 0.03)"
        }}
      >
        {/* Hover glow effect */}
        <div className="pointer-events-none absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            boxShadow: "inset 0 0 24px rgba(34, 211, 238, 0.15), 0 0 40px -8px rgba(34, 211, 238, 0.2)"
          }}
        />

        {/* Content */}
        <div className="relative z-10">
          {/* Icon and Badge */}
          <div className="flex items-start justify-between mb-4">
            <motion.div
              whileHover={{ scale: 1.1, rotate: 5 }}
              transition={{ type: "spring", stiffness: 400, damping: 10 }}
              className="flex h-14 w-14 items-center justify-center rounded-xl"
              style={{
                backgroundColor: "color-mix(in srgb, var(--color-accent) 12%, transparent)",
              }}
            >
              <div style={{ color: "var(--color-accent)" }}>
                {icon}
              </div>
            </motion.div>
            {isNew && (
              <motion.div
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: index * 0.1 + 0.3 }}
                className="px-2 py-1 rounded-full text-xs font-semibold uppercase tracking-wider"
                style={{
                  backgroundColor: "color-mix(in srgb, var(--color-accent) 20%, transparent)",
                  color: "var(--color-accent)",
                  border: "1px solid var(--color-accent)"
                }}
              >
                New
              </motion.div>
            )}
          </div>

          {/* Title */}
          <h3 className="text-lg font-semibold text-[var(--color-text-primary)] mb-2 group-hover:text-[var(--color-accent)] transition-colors duration-300">
            {title}
          </h3>

          {/* Description */}
          <p className="text-sm leading-relaxed text-[var(--color-text-secondary)] mb-4">
            {description}
          </p>

          {/* Impact Box */}
          <motion.div
            whileHover={{ boxShadow: "0 0 16px rgba(34, 211, 238, 0.2)" }}
            className="mt-4 pt-4 border-t rounded-lg p-3 transition-all duration-300"
            style={{
              borderColor: "color-mix(in srgb, var(--color-border) 60%, transparent)",
              backgroundColor: "color-mix(in srgb, var(--color-accent) 5%, transparent)",
            }}
          >
            <p className="text-xs uppercase tracking-widest text-[var(--color-text-muted)] mb-1">Impact</p>
            <p className="text-sm font-medium text-[var(--color-text-secondary)] group-hover:text-[var(--color-accent)] transition-colors duration-300">
              {impact}
            </p>
          </motion.div>
        </div>
      </div>
    </motion.div>
  );
}

export function CoreCapabilitiesSection() {
  const capabilities: CapabilityCardProps[] = [
    {
      icon: <Brain size={28} />,
      title: "World Model Core",
      description: "Learns network state transitions instead of scoring isolated flows.",
      impact: "Understands the story of your network, not just single events.",
      index: 0,
    },
    {
      icon: <TrendingUp size={28} />,
      title: "K-Step Forecasting",
      description: "Rolls the model forward to expose where an attack trajectory is headed.",
      impact: "See attacks before they happen, not after.",
      index: 1,
    },
    {
      icon: <Map size={28} />,
      title: "MITRE ATT&CK Mapping",
      description: "Translates predictions into real attacker tactics using MITRE ATT&CK.",
      impact: "Clear attacker intent mapped to industry standards.",
      isNew: true,
      index: 2,
    },
    {
      icon: <Lightbulb size={28} />,
      title: "Explainability",
      description: "Shows the top features driving each forecast in plain language.",
      impact: "Trust the model with human-readable reasons.",
      index: 3,
    },
    {
      icon: <Zap size={28} />,
      title: "Dual-Level Features",
      description: "Combines flow-level and packet-level telemetry to catch stealthy patterns.",
      impact: "Detect what others miss.",
      index: 4,
    },
    {
      icon: <Lock size={28} />,
      title: "Fully Offline",
      description: "Everything runs locally — your data never leaves your control.",
      impact: "100% privacy. Zero cloud dependency.",
      index: 5,
    },
  ];

  return (
    <motion.section
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
          <Sparkles size={14} style={{ color: "var(--color-accent)" }} />
          Core Capabilities
        </div>
        <h2 className="text-4xl sm:text-5xl font-semibold tracking-tight text-[var(--color-text-primary)] mb-3">
          AI-Powered Capabilities
        </h2>
        <p className="text-lg text-[var(--color-text-secondary)] max-w-2xl leading-relaxed">
          AI-powered capabilities that understand, predict and explain network attacks.
        </p>
      </motion.div>

      {/* Cards Grid */}
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        {capabilities.map((cap, idx) => (
          <CapabilityCard key={cap.title} {...cap} index={idx} />
        ))}
      </div>
    </motion.section>
  );
}
