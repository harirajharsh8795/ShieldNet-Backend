import type { FlaggedFlow, Severity } from "../data/types";

const SEVERITY_COLOR: Record<Severity, string> = {
  normal: "var(--color-normal)",
  watch: "var(--color-watch)",
  elevated: "var(--color-elevated)",
  critical: "var(--color-critical)",
};

interface FlaggedFlowRowProps {
  flow: FlaggedFlow;
}

export function FlaggedFlowRow({ flow }: FlaggedFlowRowProps) {
  return (
    <div
      className="flex items-center gap-3 border-b px-3 py-2.5 text-xs last:border-b-0"
      style={{ borderColor: "var(--color-border)" }}
    >
      <span
        className="h-2 w-2 shrink-0 rounded-full"
        style={{ backgroundColor: SEVERITY_COLOR[flow.severity] }}
        aria-label={`${flow.severity} severity`}
      />
      <div className="min-w-0 flex-1 font-mono text-[var(--color-text-primary)]">
        <div className="truncate">
          {flow.srcIp}:{flow.srcPort}{" "}
          <span className="text-[var(--color-text-muted)]">→</span> {flow.dstIp}:{flow.dstPort}
        </div>
      </div>
      <span className="shrink-0 font-mono text-[10px] text-[var(--color-text-muted)]">
        {flow.protocol}
      </span>
      <span
        className="shrink-0 rounded px-1.5 py-0.5 font-mono text-[10px] uppercase"
        style={{
          color: SEVERITY_COLOR[flow.severity],
          backgroundColor: `color-mix(in srgb, ${SEVERITY_COLOR[flow.severity]} 14%, transparent)`,
        }}
      >
        {flow.severity}
      </span>
    </div>
  );
}
