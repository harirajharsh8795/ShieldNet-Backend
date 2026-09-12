import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X } from "lucide-react";
import type { Explanation, TimelinePoint } from "../data/types";
import { getExplanation } from "../data/api";
import { SHAPBarChart } from "./SHAPBarChart";
import { MITREStageBadge } from "./MITREStageBadge";

interface ExplainabilityPanelProps {
  point: TimelinePoint | null;
  onClose: () => void;
}

function summarize(explanations: Explanation[]): string {
  if (explanations.length === 0) return "No contributing features available.";
  const top = explanations.slice(0, 2).map((e) => e.featureName.toLowerCase());
  if (top.length === 1) return `${capitalize(top[0])} is driving this prediction.`;
  return `${capitalize(top[0])} and ${top[1]} are driving this prediction.`;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function ExplainabilityPanel({ point, onClose }: ExplainabilityPanelProps) {
  const [explanations, setExplanations] = useState<Explanation[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!point) return;
    setLoading(true);
    getExplanation(point.predictionId).then((data) => {
      setExplanations(data);
      setLoading(false);
    });
  }, [point?.predictionId]);

  return (
    <AnimatePresence>
      {point && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 z-40 bg-black/50"
          />
          <motion.aside
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", damping: 28, stiffness: 260 }}
            className="fixed right-0 top-0 z-50 h-full w-full max-w-md overflow-y-auto border-l p-6"
            style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
            role="dialog"
            aria-label="Prediction explainability panel"
          >
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
                  Why this prediction
                </h2>
                <p className="mt-1 font-mono text-xs text-[var(--color-text-muted)]">
                  {new Date(point.timestamp).toLocaleString()}
                  {point.isProjection ? ` · T+${point.kStepOffset} projected` : " · observed"}
                </p>
              </div>
              <button
                onClick={onClose}
                aria-label="Close explainability panel"
                className="rounded-md p-1.5 text-[var(--color-text-secondary)] hover:bg-[var(--color-panel-raised)] hover:text-[var(--color-text-primary)]"
              >
                <X size={18} />
              </button>
            </div>

            <div className="mt-4 flex items-center gap-3">
              <MITREStageBadge stage={point.predictedMitreStage} size="lg" />
              <span className="font-mono text-xl font-semibold text-[var(--color-accent)]">
                {(point.infiltrationProbability * 100).toFixed(1)}%
              </span>
            </div>

            <p className="mt-4 rounded-lg border p-3 text-sm text-[var(--color-text-primary)] glow-box" style={{ borderColor: "var(--color-border)" }}>
              {loading ? "Loading contributing features…" : summarize(explanations)}
            </p>

            <div className="mt-6">
              <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                Top contributing features
              </h3>
              {loading ? (
                <p className="text-xs text-[var(--color-text-muted)]">Computing SHAP values…</p>
              ) : (
                <SHAPBarChart explanations={explanations} />
              )}
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}
