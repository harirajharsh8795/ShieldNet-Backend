import { useMemo } from "react";
import {
  ResponsiveContainer,
  ComposedChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  Dot,
} from "recharts";
import type { TimelinePoint } from "../data/types";
import { getMitreStageColor } from "./MITREStageBadge";

interface ProbabilityTimelineProps {
  data: TimelinePoint[];
  onPointClick?: (point: TimelinePoint) => void;
  selectedPredictionId?: string | null;
}

interface ChartRow {
  timestamp: string;
  index: number;
  observed: number | null;
  projected: number | null;
  point: TimelinePoint;
}

export function ProbabilityTimeline({
  data,
  onPointClick,
  selectedPredictionId,
}: ProbabilityTimelineProps) {
  const rows = useMemo<ChartRow[]>(() => {
    const sorted = [...data].sort((a, b) => a.kStepOffset - b.kStepOffset);
    const lastObservedIdx = sorted.findIndex((p) => p.isProjection);
    return sorted.map((point, i) => {
      const isBridge = lastObservedIdx > 0 && i === lastObservedIdx - 1;
      return {
        timestamp: new Date(point.timestamp).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
        index: i,
        observed: !point.isProjection ? point.infiltrationProbability : null,
        projected: point.isProjection || isBridge ? point.infiltrationProbability : null,
        point,
      };
    });
  }, [data]);

  const firstProjectionIndex = rows.findIndex((r) => r.point.isProjection);

  return (
    <div className="h-full w-full">
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={rows} margin={{ top: 12, right: 16, bottom: 8, left: 0 }}>
          <defs>
            <linearGradient id="projectionFade" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="var(--color-accent)" stopOpacity={0.95} />
              <stop offset="100%" stopColor="var(--color-accent)" stopOpacity={0.15} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--color-border)" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="timestamp"
            tick={{ fill: "var(--color-text-muted)", fontSize: 10, fontFamily: "var(--font-mono)" }}
            axisLine={{ stroke: "var(--color-border)" }}
            tickLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            domain={[0, 1]}
            tickFormatter={(v) => `${Math.round(v * 100)}%`}
            tick={{ fill: "var(--color-text-muted)", fontSize: 10, fontFamily: "var(--font-mono)" }}
            axisLine={false}
            tickLine={false}
            width={40}
          />
          <ReferenceLine y={0.8} stroke="var(--color-critical)" strokeDasharray="3 3" strokeOpacity={0.5} />
          <ReferenceLine y={0.5} stroke="var(--color-elevated)" strokeDasharray="3 3" strokeOpacity={0.35} />
          {firstProjectionIndex > 0 && (
            <ReferenceLine
              x={rows[firstProjectionIndex - 1]?.timestamp}
              stroke="var(--color-text-muted)"
              strokeDasharray="2 2"
              label={{
                value: "NOW",
                position: "insideTopLeft",
                fill: "var(--color-text-secondary)",
                fontSize: 10,
                fontFamily: "var(--font-mono)",
              }}
            />
          )}
          <Tooltip content={<CustomTooltip />} />
          <Line
            type="monotone"
            dataKey="observed"
            stroke="var(--color-accent)"
            strokeWidth={2}
            dot={false}
            isAnimationActive
            animationDuration={1400}
            animationEasing="ease-out"
            connectNulls={false}
          />
          <Line
            type="monotone"
            dataKey="projected"
            stroke="url(#projectionFade)"
            strokeWidth={2}
            strokeDasharray="5 4"
            dot={(props: any) => {
              const row = rows[props.index];
              if (!row?.point.isProjection) return <g key={props.key} />;
              const isSelected = row.point.predictionId === selectedPredictionId;
              return (
                <Dot
                  key={props.key}
                  cx={props.cx}
                  cy={props.cy}
                  r={isSelected ? 5 : 3}
                  fill="var(--color-base)"
                  stroke={getMitreStageColor(row.point.predictedMitreStage)}
                  strokeWidth={2}
                  onClick={() => onPointClick?.(row.point)}
                  cursor="pointer"
                />
              );
            }}
            isAnimationActive
            animationDuration={1000}
            animationBegin={1200}
            connectNulls
          />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}

function CustomTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const row: ChartRow = payload[0]?.payload;
  if (!row) return null;
  const { point } = row;
  return (
    <div
      className="rounded-md border px-3 py-2 font-mono text-xs shadow-lg"
      style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel-raised)" }}
    >
      <div className="text-[var(--color-text-secondary)]">
        {point.isProjection ? `T+${point.kStepOffset} (projected)` : "Observed"}
      </div>
      <div className="mt-1 text-sm" style={{ color: "var(--color-accent)" }}>
        {(point.infiltrationProbability * 100).toFixed(1)}% infiltration probability
      </div>
      <div className="mt-1" style={{ color: getMitreStageColor(point.predictedMitreStage) }}>
        {point.predictedMitreStage}
      </div>
    </div>
  );
}
