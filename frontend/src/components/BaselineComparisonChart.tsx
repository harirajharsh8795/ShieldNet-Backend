import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";
import type { ModelRun } from "../data/types";

interface BaselineComparisonChartProps {
  runs: ModelRun[];
}

const METRIC_LABELS: { key: keyof ModelRun; label: string }[] = [
  { key: "f1Score", label: "F1 Score" },
  { key: "precision", label: "Precision" },
  { key: "recall", label: "Recall" },
  { key: "falsePositiveRate", label: "False Positive Rate" },
];

export function BaselineComparisonChart({ runs }: BaselineComparisonChartProps) {
  const worldModel = runs.find((r) => r.modelType === "lstm" || r.modelType === "transformer" || r.modelType === "gnn");
  const baseline = runs.find((r) => r.modelType === "baseline_lr");

  const data = METRIC_LABELS.map(({ key, label }) => ({
    metric: label,
    "World Model": worldModel ? Number(worldModel[key]) : 0,
    Baseline: baseline ? Number(baseline[key]) : 0,
  }));

  return (
    <div className="h-80 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 12, right: 16, bottom: 8, left: 0 }}>
          <CartesianGrid stroke="var(--color-border)" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="metric"
            tick={{ fill: "var(--color-text-secondary)", fontSize: 11 }}
            axisLine={{ stroke: "var(--color-border)" }}
            tickLine={false}
          />
          <YAxis
            tickFormatter={(v) => `${Math.round(v * 100)}%`}
            tick={{ fill: "var(--color-text-muted)", fontSize: 10, fontFamily: "var(--font-mono)" }}
            axisLine={false}
            tickLine={false}
            width={40}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "var(--color-panel-raised)",
              border: "1px solid var(--color-border)",
              borderRadius: 6,
              fontSize: 12,
              fontFamily: "var(--font-mono)",
            }}
            formatter={(v) => `${(Number(v) * 100).toFixed(1)}%`}
          />
          <Legend wrapperStyle={{ fontSize: 12, color: "var(--color-text-secondary)" }} />
          <Bar dataKey="World Model" fill="var(--color-accent)" radius={[3, 3, 0, 0]} isAnimationActive animationDuration={800} />
          <Bar dataKey="Baseline" fill="var(--color-text-muted)" radius={[3, 3, 0, 0]} isAnimationActive animationDuration={800} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
