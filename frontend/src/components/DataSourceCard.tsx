import type { ReactNode } from "react";
import { motion } from "framer-motion";

interface DataSourceCardProps {
  icon: ReactNode;
  title: string;
  description: string;
  meta?: string;
  onClick: () => void;
  disabled?: boolean;
}

export function DataSourceCard({
  icon,
  title,
  description,
  meta,
  onClick,
  disabled,
}: DataSourceCardProps) {
  return (
    <motion.button
      whileHover={disabled ? undefined : { y: -3 }}
      whileTap={disabled ? undefined : { scale: 0.98 }}
      onClick={onClick}
      disabled={disabled}
      className="group flex h-full flex-col items-start gap-4 rounded-xl border p-6 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-50 glow-box"
      style={{
        borderColor: "var(--color-border)",
        backgroundColor: "var(--color-panel)",
      }}
      onMouseEnter={(e) => {
        if (!disabled) e.currentTarget.style.borderColor = "var(--color-accent)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "var(--color-border)";
      }}
    >
      <div
        className="flex h-11 w-11 items-center justify-center rounded-lg"
        style={{
          backgroundColor: "color-mix(in srgb, var(--color-accent) 14%, transparent)",
          color: "var(--color-accent)",
        }}
      >
        {icon}
      </div>
      <div>
        <h3 className="text-base font-semibold text-[var(--color-text-primary)]">{title}</h3>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{description}</p>
      </div>
      {meta && (
        <span className="mt-auto font-mono text-[11px] uppercase tracking-wide text-[var(--color-text-muted)]">
          {meta}
        </span>
      )}
    </motion.button>
  );
}
