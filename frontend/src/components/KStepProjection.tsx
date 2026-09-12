import { motion } from "framer-motion";
import type { TimelinePoint } from "../data/types";
import { getMitreStageColor } from "./MITREStageBadge";
import { ConfidenceDecayIndicator } from "./ConfidenceDecayIndicator";

interface KStepProjectionProps {
  projectedPoints: TimelinePoint[];
  onSelect?: (point: TimelinePoint) => void;
  selectedPredictionId?: string | null;
}

export function KStepProjection({
  projectedPoints,
  onSelect,
  selectedPredictionId,
}: KStepProjectionProps) {
  const maxK = Math.max(...projectedPoints.map((p) => p.kStepOffset), 1);

  return (
    <div
      className="rounded-xl border p-5 glow-box"
      style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
    >
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
            K-step forward simulation
          </h3>
          <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
            World Model rollout — each step feeds its own prediction back in as the next
            input, {maxK} windows ahead.
          </p>
        </div>
        <ConfidenceDecayIndicator />
      </div>

      <div className="mt-5 flex items-end gap-1.5">
        {projectedPoints.map((point, i) => {
          const opacity = Math.max(0.18, 1 - (i / (projectedPoints.length - 1 || 1)) * 0.8);
          const isSelected = point.predictionId === selectedPredictionId;
          const heightPct = Math.max(8, point.infiltrationProbability * 100);
          return (
            <button
              key={point.predictionId}
              onClick={() => onSelect?.(point)}
              className="group flex flex-1 flex-col items-center gap-1.5"
              aria-label={`T+${point.kStepOffset}: ${(point.infiltrationProbability * 100).toFixed(0)}% probability, ${point.predictedMitreStage}`}
            >
              <span
                className="font-mono text-[10px]"
                style={{ color: `color-mix(in srgb, var(--color-text-secondary) ${opacity * 100}%, transparent)` }}
              >
                {(point.infiltrationProbability * 100).toFixed(0)}%
              </span>
              <div className="relative flex h-24 w-full items-end justify-center rounded-sm bg-[var(--color-panel-raised)]">
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: `${heightPct}%` }}
                  transition={{ duration: 0.6, delay: 0.15 + i * 0.06, ease: "easeOut" }}
                  className="w-full rounded-sm"
                  style={{
                    backgroundColor: getMitreStageColor(point.predictedMitreStage),
                    opacity,
                    outline: isSelected ? "2px solid var(--color-accent)" : "none",
                    outlineOffset: 1,
                  }}
                />
              </div>
              <span className="font-mono text-[10px] text-[var(--color-text-muted)] group-hover:text-[var(--color-accent)]">
                T+{point.kStepOffset}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
