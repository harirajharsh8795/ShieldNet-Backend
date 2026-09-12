export function ConfidenceDecayIndicator() {
  return (
    <div className="flex items-center gap-2">
      <div
        className="h-1.5 w-24 rounded-full"
        style={{
          background: "linear-gradient(to right, var(--color-accent), transparent)",
        }}
      />
      <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--color-text-muted)]">
        Confidence decays with horizon
      </span>
    </div>
  );
}
