import { motion } from "framer-motion";
import type { FlaggedFlow, Severity } from "../data/types";
import { FlaggedFlowRow } from "./FlaggedFlowRow";

interface FlaggedFlowsListProps {
  flows: FlaggedFlow[];
  filter: Severity | "all";
  onFilterChange: (filter: Severity | "all") => void;
}

const FILTERS: (Severity | "all")[] = ["all", "critical", "elevated", "watch", "normal"];

export function FlaggedFlowsList({ flows, filter, onFilterChange }: FlaggedFlowsListProps) {
  const filtered = filter === "all" ? flows : flows.filter((f) => f.severity === filter);

  return (
    <div
      className="flex h-full flex-col rounded-xl border glow-box"
      style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
    >
      <div className="flex items-center justify-between border-b px-4 py-3" style={{ borderColor: "var(--color-border)" }}>
        <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">Flagged flows</h3>
        <span className="font-mono text-xs text-[var(--color-text-muted)]">{filtered.length}</span>
      </div>
      <div className="flex flex-wrap gap-1 border-b px-3 py-2" style={{ borderColor: "var(--color-border)" }}>
        {FILTERS.map((f) => (
          <button
            key={f}
            onClick={() => onFilterChange(f)}
            className="rounded px-2 py-1 font-mono text-[10px] uppercase tracking-wide transition-colors"
            style={{
              color: filter === f ? "var(--color-base)" : "var(--color-text-secondary)",
              backgroundColor: filter === f ? "var(--color-accent)" : "transparent",
            }}
          >
            {f}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <p className="px-4 py-6 text-center text-xs text-[var(--color-text-muted)]">
            No flows flagged in this window.
          </p>
        ) : (
          filtered.map((flow, i) => (
            <motion.div
              key={flow.id}
              initial={{ opacity: 0, x: 16 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3, delay: Math.min(i, 12) * 0.04 }}
            >
              <FlaggedFlowRow flow={flow} />
            </motion.div>
          ))
        )}
      </div>
    </div>
  );
}
