import { motion } from "framer-motion";
import type { Explanation } from "../data/types";

interface SHAPBarChartProps {
  explanations: Explanation[];
}

export function SHAPBarChart({ explanations }: SHAPBarChartProps) {
  const maxScore = Math.max(...explanations.map((e) => Math.abs(e.contributionScore)), 0.01);
  const sorted = [...explanations].sort((a, b) => a.rank - b.rank);

  return (
    <div className="flex flex-col gap-3">
      {sorted.map((exp, i) => {
        const widthPct = (Math.abs(exp.contributionScore) / maxScore) * 100;
        return (
          <div key={exp.id}>
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="text-[var(--color-text-primary)]">{exp.featureName}</span>
              <span className="font-mono text-[var(--color-accent)]">
                +{exp.contributionScore.toFixed(3)}
              </span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--color-panel-raised)]">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${widthPct}%` }}
                transition={{ duration: 0.55, delay: i * 0.08, ease: "easeOut" }}
                className="h-full rounded-full"
                style={{ backgroundColor: "var(--color-accent)" }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
