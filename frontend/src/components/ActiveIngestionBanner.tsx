import { FileText, ArrowRight, CheckCircle2 } from "lucide-react";
import { Link } from "react-router-dom";
import type { Ingestion } from "../data/types";

interface ActiveIngestionBannerProps {
  ingestion: Ingestion | null;
  scenarioName?: string;
  hostIp?: string;
  targetIp?: string;
}

export function ActiveIngestionBanner({
  ingestion,
  scenarioName,
  hostIp,
  targetIp,
}: ActiveIngestionBannerProps) {
  if (!ingestion) return null;

  const isPcap = ingestion.sourceType === "pcap" || ingestion.filename.toLowerCase().endsWith(".pcap");
  const fileName = ingestion.filename || "Uploaded_Telemetry.csv";
  const fileSize = ingestion.fileSize || (isPcap ? "0.84 KB" : "17.25 KB");
  const flowCount = ingestion.flowCount || (isPcap ? 14 : 128);

  return (
    <div
      className="flex flex-col gap-3 rounded-xl border p-4 glow-box font-mono text-xs transition-all duration-300"
      style={{
        borderColor: isPcap ? "var(--color-mitre-initial)" : "var(--color-accent)",
        backgroundColor: isPcap ? "color-mix(in srgb, var(--color-mitre-initial) 8%, transparent)" : "color-mix(in srgb, var(--color-mitre-recon) 8%, transparent)",
      }}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-2.5" style={{ borderColor: "color-mix(in srgb, var(--color-text-primary) 10%, transparent)" }}>
        <div className="flex items-center gap-2">
          <span className="flex h-2.5 w-2.5 rounded-full animate-ping" style={{ backgroundColor: isPcap ? "var(--color-mitre-initial)" : "var(--color-normal)" }} />
          <span className="font-bold text-sm text-[var(--color-text-primary)] flex items-center gap-1.5">
            <FileText size={16} className={isPcap ? "text-pink-400" : "text-[var(--color-accent)]"} />
            <span>ACTIVE INGESTED TELEMETRY STREAM:</span>
            <strong className={isPcap ? "text-pink-300 underline" : "text-emerald-300 underline"}>
              {fileName}
            </strong>
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="rounded-md px-2.5 py-0.5 text-[11px] font-bold tracking-wider" style={{
            backgroundColor: isPcap ? "color-mix(in srgb, var(--color-mitre-initial) 20%, transparent)" : "color-mix(in srgb, var(--color-normal) 20%, transparent)",
            color: isPcap ? "var(--color-mitre-initial)" : "var(--color-normal)",
            border: `1px solid ${isPcap ? "color-mix(in srgb, var(--color-mitre-initial) 40%, transparent)" : "color-mix(in srgb, var(--color-normal) 40%, transparent)"}`
          }}>
            {isPcap ? "RAW PCAP STREAM INGESTION" : "NETFLOW CSV INGESTION"}
          </span>
          <Link
            to="/dashboard"
            className="flex items-center gap-1 text-[11px] text-[var(--color-text-secondary)] hover:text-white hover:underline ml-2"
          >
            <span>Change File</span>
            <ArrowRight size={11} />
          </Link>
        </div>
      </div>

      {/* Telemetry Ingestion Metrics Grid */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5 text-[11px]">
        <div>
          <span className="text-[var(--color-text-muted)] block text-[10px]">TELEMETRY TYPE:</span>
          <strong className="text-[var(--color-text-primary)]">
            {isPcap ? "Packet Headers (PCAP)" : "Flow Statistics (CSV)"}
          </strong>
        </div>

        <div>
          <span className="text-[var(--color-text-muted)] block text-[10px]">EXTRACTED FEATURES:</span>
          <strong className="text-cyan-300">
            {isPcap ? "84 Channels (77 Flow + 7 Packet)" : "84 Standardized Channels"}
          </strong>
        </div>

        <div>
          <span className="text-[var(--color-text-muted)] block text-[10px]">TELEMETRY VOLUME:</span>
          <strong className="text-purple-300">
            {flowCount} {isPcap ? "packets" : "flows"} ({fileSize})
          </strong>
        </div>

        <div>
          <span className="text-[var(--color-text-muted)] block text-[10px]">MONITORED TARGET:</span>
          <strong className="text-amber-300">
            {targetIp || "192.168.10.50"} {hostIp ? `← ${hostIp}` : ""}
          </strong>
        </div>

        <div>
          <span className="text-[var(--color-text-muted)] block text-[10px]">SCENARIO MATCH:</span>
          <strong className="text-emerald-400 flex items-center gap-1">
            <CheckCircle2 size={12} />
            <span className="truncate">{scenarioName || "Live Dynamic Flow"}</span>
          </strong>
        </div>
      </div>
    </div>
  );
}
