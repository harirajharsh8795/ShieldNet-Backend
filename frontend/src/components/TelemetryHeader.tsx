import { Activity, Cpu, Radio } from "lucide-react";

export function TelemetryHeader() {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-2.5 glow-box mb-6 font-mono text-xs" style={{ borderColor: "var(--color-border)", backgroundColor: "rgba(15, 23, 42, 0.75)" }}>
      {/* Left: Organization Badge */}
      <div className="flex items-center gap-2">
        <span className="flex h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
        <span className="font-bold tracking-wider text-[var(--color-accent)]">
          NTRO // NCIIPC CII DEFENSE ENGINE
        </span>
        <span className="hidden sm:inline text-[var(--color-text-secondary)]">|</span>
        <span className="hidden sm:inline text-[var(--color-text-secondary)]">
          AIR-GAPPED SOVEREIGN NIDS
        </span>
      </div>

      {/* Right: Real-time Telemetry Stats */}
      <div className="flex flex-wrap items-center gap-4 text-[11px] text-[var(--color-text-secondary)]">
        <div className="flex items-center gap-1.5">
          <Activity size={13} className="text-cyan-400" />
          <span>INGESTION: <strong className="text-white">64,400 flows/s</strong></span>
        </div>

        <div className="flex items-center gap-1.5">
          <Cpu size={13} className="text-purple-400" />
          <span>LATENCY: <strong className="text-white">0.0155 ms</strong></span>
        </div>

        <div className="flex items-center gap-1.5">
          <Radio size={13} className="text-emerald-400" />
          <span>STATUS: <strong className="text-emerald-400">OFFLINE - SECURE</strong></span>
        </div>
      </div>
    </div>
  );
}
