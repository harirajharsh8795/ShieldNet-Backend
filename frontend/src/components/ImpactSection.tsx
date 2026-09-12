import { motion } from "framer-motion";
import { Zap, Shield, BarChart3, Lock } from "lucide-react";

interface ImpactItemProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  index: number;
}

function ImpactItem({ icon, title, description, index }: ImpactItemProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2 }}
      transition={{ duration: 0.5, delay: index * 0.08, ease: "easeOut" }}
      whileHover={{ y: -4, transition: { duration: 0.2 } }}
      className="group relative"
    >
      <div className="rounded-xl border p-5 backdrop-blur-sm transition-all duration-300 glow-box hover:border-[var(--color-accent)]"
        style={{
          borderColor: "var(--color-border)",
          backgroundColor: "color-mix(in srgb, var(--color-panel) 80%, transparent)",
          boxShadow: "0 0 24px -6px rgba(34, 211, 238, 0.0), inset 0 0 24px -12px rgba(34, 211, 238, 0.02)"
        }}
      >
        {/* Hover glow */}
        <div className="pointer-events-none absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
          style={{
            boxShadow: "inset 0 0 20px rgba(34, 211, 238, 0.12), 0 0 30px -8px rgba(34, 211, 238, 0.15)"
          }}
        />

        <div className="relative z-10">
          {/* Icon */}
          <motion.div
            whileHover={{ scale: 1.15, rotate: -5 }}
            transition={{ type: "spring", stiffness: 400, damping: 10 }}
            className="inline-flex h-12 w-12 items-center justify-center rounded-lg mb-4"
            style={{
              backgroundColor: "color-mix(in srgb, var(--color-accent) 15%, transparent)",
            }}
          >
            <div style={{ color: "var(--color-accent)" }}>
              {icon}
            </div>
          </motion.div>

          {/* Title */}
          <h3 className="text-lg font-semibold text-[var(--color-text-primary)] mb-2 group-hover:text-[var(--color-accent)] transition-colors duration-300">
            {title}
          </h3>

          {/* Description */}
          <p className="text-sm leading-relaxed text-[var(--color-text-secondary)]">
            {description}
          </p>
        </div>
      </div>
    </motion.div>
  );
}

export function ImpactSection() {
  const impacts: ImpactItemProps[] = [
    {
      icon: <Zap size={24} />,
      title: "Earlier Detection",
      description: "Detect threats minutes to hours earlier.",
      index: 0,
    },
    {
      icon: <Shield size={24} />,
      title: "Higher Accuracy",
      description: "Reduce false alarms with temporal understanding.",
      index: 1,
    },
    {
      icon: <BarChart3 size={24} />,
      title: "Actionable Insights",
      description: "Get clear reasons and attacker intent, not just alerts.",
      index: 2,
    },
    {
      icon: <Lock size={24} />,
      title: "Total Privacy",
      description: "100% offline. Your data stays with you.",
      index: 3,
    },
  ];

  return (
    <motion.section
      initial={{ opacity: 0, y: 32 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.15 }}
      transition={{ duration: 0.6, ease: "easeOut" }}
      className="mt-20 py-4"
    >
      {/* Section Header */}
      <motion.div
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true, amount: 0.3 }}
        transition={{ duration: 0.5 }}
        className="text-center mb-12"
      >
        <h2 className="text-4xl sm:text-5xl font-semibold tracking-tight text-[var(--color-text-primary)] mb-3">
          The Impact
        </h2>
        <p className="text-lg text-[var(--color-text-secondary)] mx-auto max-w-2xl leading-relaxed">
          Measurable outcomes that transform your cybersecurity posture.
        </p>
      </motion.div>

      {/* Impact Cards Grid */}
      <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {impacts.map((impact, idx) => (
          <ImpactItem key={impact.title} {...impact} index={idx} />
        ))}
      </div>
    </motion.section>
  );
}
