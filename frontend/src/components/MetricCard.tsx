interface MetricCardProps {
  label: string;
  value: string;
  delta?: string;
  deltaPositive?: boolean;
  accent?: string;
}

export function MetricCard({ label, value, delta, deltaPositive, accent }: MetricCardProps) {
  return (
    <div
      className="rounded-lg border p-4 glow-box"
      style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
    >
      <div className="text-[11px] uppercase tracking-wider text-[var(--color-text-secondary)]">
        {label}
      </div>
      <div
        className="mt-1.5 font-mono text-2xl font-semibold"
        style={{ color: accent ?? "var(--color-text-primary)" }}
      >
        {value}
      </div>
      {delta && (
        <div
          className="mt-1 font-mono text-xs"
          style={{ color: deltaPositive ? "var(--color-normal)" : "var(--color-critical)" }}
        >
          {delta}
        </div>
      )}
    </div>
  );
}
