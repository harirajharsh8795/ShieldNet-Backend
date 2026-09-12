import { useState, useEffect } from "react";
import { X, Copy, Check, Download, ShieldCheck, Terminal, AlertTriangle } from "lucide-react";
import { getDefenseRules, type DefenseRulesResponse } from "../data/api";

interface IncidentDossierModalProps {
  isOpen: boolean;
  onClose: () => void;
  scenarioName?: string;
  hostIp: string;
  targetIp: string;
  predictedClass: string;
  confidence: number;
}

export function IncidentDossierModal({
  isOpen,
  onClose,
  hostIp,
  targetIp,
  predictedClass,
  confidence,
}: IncidentDossierModalProps) {
  const [dossier, setDossier] = useState<DefenseRulesResponse | null>(null);
  const [copiedType, setCopiedType] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      getDefenseRules({
        predicted_class: predictedClass,
        confidence: confidence,
        host_ip: hostIp,
        target_ip: targetIp,
        top_feature_name: "retransmission_count",
        projected_risk_reduction_pct: 78.4,
      }).then(setDossier);
    }
  }, [isOpen, predictedClass, confidence, hostIp, targetIp]);

  if (!isOpen) return null;

  function handleCopy(text: string, type: string) {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  }

  function handleDownload() {
    if (!dossier) return;
    const blob = new Blob([dossier.dossier_markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${dossier.incident_id}_Sovereign_Dossier.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div
        className="relative flex flex-col max-h-[90vh] w-full max-w-4xl rounded-2xl border shadow-2xl overflow-hidden glow-box"
        style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b px-6 py-4" style={{ borderColor: "var(--color-border)" }}>
          <div className="flex items-center gap-2.5">
            <ShieldCheck size={22} className="text-emerald-400" />
            <div>
              <h2 className="font-bold text-base text-[var(--color-text-primary)]">
                SOVEREIGN NCIIPC / CERT-IN INCIDENT DOSSIER & DEFENSE SYNTHESIS
              </h2>
              <p className="text-xs font-mono text-[var(--color-text-secondary)]">
                REF: {dossier?.incident_id || "NCIIPC-INC-2026-26153"} | CLASSIFICATION: RESTRICTED // CII
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-[var(--color-text-secondary)] hover:bg-white/10 hover:text-white"
          >
            <X size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Key Incident Metadata Bar */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 rounded-xl p-3 border font-mono text-xs" style={{ backgroundColor: "rgba(15, 23, 42, 0.6)", borderColor: "var(--color-border)" }}>
            <div>
              <span className="text-[var(--color-text-secondary)] block">ADVERSARY SOURCE:</span>
              <strong className="text-rose-400">{hostIp}</strong>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)] block">CII TARGET:</span>
              <strong className="text-cyan-400">{targetIp}</strong>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)] block">PROJECTED THREAT:</span>
              <strong className="text-amber-400">{predictedClass}</strong>
            </div>
            <div>
              <span className="text-[var(--color-text-secondary)] block">PROACTIVE DROP:</span>
              <strong className="text-emerald-400">-{dossier?.projected_risk_reduction_pct || 78.4}% RISK</strong>
            </div>
          </div>

          {/* National Vulnerability Database (CVE/NVD) Threat Intelligence Card */}
          <div className="rounded-xl border p-3.5 bg-[var(--color-base)] space-y-1.5" style={{ borderColor: "var(--color-border)" }}>
            <div className="flex items-center justify-between font-mono text-xs">
              <span className="text-[var(--color-text-secondary)] flex items-center gap-1.5 font-bold">
                <AlertTriangle size={14} className="text-amber-400" />
                <span>NATIONAL VULNERABILITY DATABASE (NVD / CVE) THREAT ADVISORY:</span>
              </span>
              <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[10px] font-bold font-mono">
                CVSS SEVERITY: {dossier?.cvss_score || (predictedClass.includes("SSH") ? 7.5 : predictedClass.includes("SCADA") ? 8.8 : 9.8)} / 10.0
              </span>
            </div>
            <div className="flex flex-col sm:flex-row sm:items-center gap-1.5 font-mono text-xs">
              <span className="text-[var(--color-accent)] font-bold">
                {dossier?.cve_id || (predictedClass.includes("SSH") ? "CVE-2016-0777" : predictedClass.includes("SCADA") ? "CVE-2021-22779" : predictedClass.includes("Bot") ? "CVE-2019-11510" : "CVE-2021-41773")}
              </span>
              <span className="hidden sm:inline text-[var(--color-text-muted)]">|</span>
              <span className="text-[var(--color-text-secondary)]">
                {dossier?.remediation_advisory || (predictedClass.includes("SSH") ? "Update OpenSSH to >=8.4p1, enforce Ed25519 authentication keys, and disable password auth." : predictedClass.includes("SCADA") ? "Enforce air-gapped unidirectional data diodes and block Modbus Function 0x05." : "Deploy emergency perimeter filtering and apply vendor security patch.")}
              </span>
            </div>
          </div>

          {/* Snort / Suricata Signature */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-[var(--color-text-secondary)] flex items-center gap-1.5">
                <Terminal size={14} className="text-[var(--color-accent)]" />
                <span>SYNTHESIZED SNORT / SURICATA SIGNATURE:</span>
              </span>
              <button
                onClick={() => dossier && handleCopy(dossier.snort_rule, "snort")}
                className="flex items-center gap-1 text-[var(--color-accent)] hover:underline"
              >
                {copiedType === "snort" ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                <span>{copiedType === "snort" ? "Copied" : "Copy Snort Rule"}</span>
              </button>
            </div>
            <pre className="rounded-lg p-3 text-xs font-mono bg-black/60 border border-white/10 text-emerald-300 overflow-x-auto whitespace-pre-wrap">
              {dossier?.snort_rule}
            </pre>
          </div>

          {/* Linux iptables / nftables Command */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-[var(--color-text-secondary)] flex items-center gap-1.5">
                <Terminal size={14} className="text-pink-400" />
                <span>SOVEREIGN FIREWALL POLICY (iptables / nftables):</span>
              </span>
              <button
                onClick={() => dossier && handleCopy(dossier.iptables_cmd, "iptables")}
                className="flex items-center gap-1 text-pink-400 hover:underline"
              >
                {copiedType === "iptables" ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                <span>{copiedType === "iptables" ? "Copied" : "Copy iptables"}</span>
              </button>
            </div>
            <pre className="rounded-lg p-3 text-xs font-mono bg-black/60 border border-white/10 text-pink-300 overflow-x-auto whitespace-pre-wrap">
              {dossier?.iptables_cmd}
            </pre>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t px-6 py-4" style={{ borderColor: "var(--color-border)" }}>
          <span className="text-xs font-mono text-[var(--color-text-secondary)]">
            Compliant with NCIIPC Sovereign Mandate (CAF/OT-2026)
          </span>
          <div className="flex items-center gap-3">
            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 rounded-lg px-4 py-2 text-xs font-medium text-white transition-all shadow-md hover:scale-105"
              style={{ backgroundColor: "var(--color-accent)" }}
            >
              <Download size={14} />
              <span>Download Official Report (.md)</span>
            </button>
            <button
              onClick={onClose}
              className="rounded-lg px-4 py-2 text-xs font-medium border text-[var(--color-text-secondary)] hover:bg-white/5"
              style={{ borderColor: "var(--color-border)" }}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
