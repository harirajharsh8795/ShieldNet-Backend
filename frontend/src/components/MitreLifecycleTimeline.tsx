import { useState } from "react";
import { 
  Search, 
  Briefcase, 
  Mail, 
  Zap, 
  Anchor, 
  Radio, 
  Target, 
  ExternalLink, 
  AlertCircle, 
  ArrowRight,
  ShieldCheck
} from "lucide-react";
import type { MitreReasoningResponse } from "../data/api";

interface MitreLifecycleTimelineProps {
  reasoning: MitreReasoningResponse | null;
  currentStage: number;
}

interface KillChainStageDetail {
  id: number;
  name: string;
  tacticCode: string;
  icon: any;
  tag: string;
  description: string;
  techniques: { name: string; code: string }[];
  defensiveCounter: string;
  mitigationAction: string;
}

const KILL_CHAIN_STAGES: KillChainStageDetail[] = [
  {
    id: 1,
    name: "Reconnaissance",
    tacticCode: "TA0043",
    icon: Search,
    tag: "Reconnaissance (TA0043)",
    description: "Adversary probes the network perimeter, enumerating open ports, services, and live host IPs.",
    techniques: [
      { name: "Network Service Discovery", code: "T1046" },
      { name: "IP Address Sweep", code: "T1595.001" },
      { name: "Vulnerability Scanning", code: "T1595.002" },
    ],
    defensiveCounter: "TCP SYN rate-limiting; block aggressive ICMP echo sweeps; deploy honeypots for decoy telemetry.",
    mitigationAction: "RATE_LIMIT_PORT_SCAN",
  },
  {
    id: 2,
    name: "Weaponization",
    tacticCode: "PRE-ATTACK",
    icon: Briefcase,
    tag: "Weaponization (Pre-Compromise)",
    description: "Attacker bundles exploit payload with backdoor or automated credential dictionaries targeting known vulnerabilities.",
    techniques: [
      { name: "Exploit Crafting", code: "T1587.001" },
      { name: "Credential Dictionary Assembly", code: "T1589.001" },
      { name: "Obfuscated PowerShell Scripting", code: "T1027" },
    ],
    defensiveCounter: "Threat intelligence feeds; zero-trust software signing verification; heuristic pre-filter at ingress.",
    mitigationAction: "INGRESS_PAYLOAD_FILTER",
  },
  {
    id: 3,
    name: "Delivery",
    tacticCode: "TA0001",
    icon: Mail,
    tag: "Initial Delivery (TA0001)",
    description: "Transmission of exploit or malicious brute-force stream to enterprise perimeter gateways or public-facing services.",
    techniques: [
      { name: "Exploit Public-Facing Application", code: "T1190" },
      { name: "External Remote Services", code: "T1133" },
      { name: "Password Guessing / Brute Force", code: "T1110.001" },
    ],
    defensiveCounter: "WAF ingress inspection; multi-factor authentication (MFA); dynamic Geo-IP filtering and port knocking.",
    mitigationAction: "BLOCK_BRUTE_FORCE_IP",
  },
  {
    id: 4,
    name: "Exploitation",
    tacticCode: "TA0002",
    icon: Zap,
    tag: "Exploitation (TA0002)",
    description: "Triggering exploit code on target service to achieve remote code execution (RCE) or authentication bypass.",
    techniques: [
      { name: "Remote Code Execution", code: "T1210" },
      { name: "Command and Scripting Interpreter", code: "T1059" },
      { name: "Authentication Bypass", code: "T1068" },
    ],
    defensiveCounter: "Immediate connection reset (TCP RST injection); kernel memory ASLR; patch critical CVEs in public services.",
    mitigationAction: "RESET_ACTIVE_CONNECTIONS",
  },
  {
    id: 5,
    name: "Installation",
    tacticCode: "TA0003",
    icon: Anchor,
    tag: "Persistence & Installation (TA0003)",
    description: "Installing persistent foothold on the host, modifying registry run keys, scheduled tasks, or SSH authorized keys.",
    techniques: [
      { name: "Boot or Logon Autostart Execution", code: "T1547" },
      { name: "Scheduled Task/Job", code: "T1053" },
      { name: "SSH Authorized Keys Manipulation", code: "T1098.004" },
    ],
    defensiveCounter: "Endpoint integrity monitoring; read-only root filesystems; automated quarantine of unverified processes.",
    mitigationAction: "ISOLATE_HOST_ENDPOINT",
  },
  {
    id: 6,
    name: "C2",
    tacticCode: "TA0011",
    icon: Radio,
    tag: "Command and Control (TA0011)",
    description: "Establishing covert bi-directional communication channels for remote tasking, heartbeats, and lateral coordination.",
    techniques: [
      { name: "Encrypted Channel / TLS", code: "T1573.002" },
      { name: "Application Layer Protocol", code: "T1071.001" },
      { name: "Fallback Channels & Periodic Jitter", code: "T1008" },
    ],
    defensiveCounter: "Egress traffic TLS fingerprinting; JA3/JA4 hash blocking; beaconing jitter statistical analysis.",
    mitigationAction: "QUARANTINE_C2_CHANNEL",
  },
  {
    id: 7,
    name: "Actions on Objectives",
    tacticCode: "TA0010/40",
    icon: Target,
    tag: "Exfiltration / Impact (TA0010/40)",
    description: "The payoff — stealing confidential data, encrypting for ransom, or disrupting Critical Infrastructure operations.",
    techniques: [
      { name: "Exfiltration Over C2 Channel", code: "T1041" },
      { name: "Data Encrypted for Impact", code: "T1486" },
      { name: "Inhibit Response / SCADA Overwrite", code: "T0831" },
    ],
    defensiveCounter: "DLP; anomalous data-transfer volume limits; backup integrity & mass-file-change alerts; SCADA coil lock.",
    mitigationAction: "ENFORCE_SCADA_EMERGENCY_LOCKDOWN",
  },
];

export function MitreLifecycleTimeline({ reasoning, currentStage }: MitreLifecycleTimelineProps) {
  // Map internal stage (1..5) to 7-stage explorer index:
  // 1 -> Stage 1 (Recon)
  // 2 -> Stage 3 (Delivery / Initial Access)
  // 3 -> Stage 5 (Installation / Lateral)
  // 4 -> Stage 6 (C2)
  // 5 -> Stage 7 (Actions on Objectives / Impact)
  const defaultMappedStage = 
    currentStage === 1 ? 1 :
    currentStage === 2 ? 3 :
    currentStage === 3 ? 5 :
    currentStage === 4 ? 6 :
    currentStage === 5 ? 7 : 7;

  const [selectedStageId, setSelectedStageId] = useState<number>(defaultMappedStage);

  const selectedStage = KILL_CHAIN_STAGES.find((s) => s.id === selectedStageId) || KILL_CHAIN_STAGES[6];
  const IconComponent = selectedStage.icon;

  return (
    <div className="flex flex-col gap-4 rounded-xl border p-5 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
      {/* Header matching user's reference */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-3" style={{ borderColor: "var(--color-border)" }}>
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold tracking-tight text-[var(--color-text-primary)]">
              Kill Chain Explorer
            </h2>
            <span className="font-mono text-[10px] text-cyan-300 bg-cyan-500/15 border border-cyan-500/30 px-2 py-0.5 rounded font-semibold">
              MITRE ATT&CK® MAPPED
            </span>
          </div>
          <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
            Click any stage. Each maps to real ATT&amp;CK tactics, common techniques, and a proactive defensive counter-move.
          </p>
        </div>

        {reasoning?.risk_acceleration && (
          <span className="rounded-full px-2.5 py-0.5 text-xs font-mono font-medium" style={{ backgroundColor: "color-mix(in srgb, var(--color-mitre-exfil) 15%, transparent)", color: "color-mix(in srgb, var(--color-mitre-exfil) 75%, var(--color-text-primary))", border: "1px solid color-mix(in srgb, var(--color-mitre-exfil) 30%, transparent)" }}>
            Risk Acceleration: {reasoning.risk_acceleration}
          </span>
        )}
      </div>

      {/* 7 Interactive Stage Tabs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
        {KILL_CHAIN_STAGES.map((stage) => {
          const isSelected = stage.id === selectedStageId;
          const isActivePrediction = stage.id === defaultMappedStage;
          const StageIcon = stage.icon;

          return (
            <button
              key={stage.id}
              onClick={() => setSelectedStageId(stage.id)}
              className={`relative flex flex-col items-center justify-center p-3 rounded-xl border transition-all text-center group cursor-pointer ${
                isSelected
                  ? "border-rose-500/80 bg-rose-950/20 shadow-lg shadow-rose-950/30"
                  : "border-slate-800/80 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/80"
              }`}
            >
              {/* Active Prediction Glowing Indicator */}
              {isActivePrediction && (
                <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500"></span>
                </span>
              )}

              <span className="font-mono text-[9px] uppercase tracking-wider text-slate-400 mb-1.5 font-semibold">
                STAGE {stage.id}
              </span>

              <div className={`p-1.5 rounded-lg mb-1.5 transition-transform group-hover:scale-110 ${
                isSelected ? "text-rose-400" : "text-slate-300"
              }`}>
                <StageIcon size={18} />
              </div>

              <span className={`text-xs font-semibold truncate max-w-full ${
                isSelected ? "text-white" : "text-slate-300 group-hover:text-white"
              }`}>
                {stage.name}
              </span>

              {isActivePrediction && (
                <span className="font-mono text-[8px] text-rose-400 mt-1 font-bold">
                  ACTIVE PREDICTION
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Detail Panel for Selected Stage */}
      <div className="rounded-xl border p-5 bg-slate-950/60 flex flex-col gap-4" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          {/* Left: Tactic info & description */}
          <div className="flex flex-col gap-1.5 flex-1">
            <span className="font-mono text-[11px] text-rose-400 font-bold uppercase tracking-wider">
              {selectedStage.tag}
            </span>

            <div className="flex items-center gap-2">
              <IconComponent size={20} className="text-rose-400 shrink-0" />
              <h3 className="text-base font-bold text-white">
                {selectedStage.name}
              </h3>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed max-w-2xl mt-0.5">
              {selectedStage.description}
            </p>

            {/* Techniques T-Code Pills */}
            <div className="flex flex-wrap items-center gap-1.5 mt-2">
              {selectedStage.techniques.map((tech) => (
                <span
                  key={tech.code}
                  className="font-mono text-[10px] px-2.5 py-0.5 rounded-md bg-rose-950/40 text-rose-300 border border-rose-900/60 flex items-center gap-1.5"
                >
                  <span className="font-semibold">{tech.name}</span>
                  <span className="text-rose-400 font-bold">· {tech.code}</span>
                </span>
              ))}
            </div>
          </div>

          {/* Right: Defensive Counter Box (Exact match with user's screenshot) */}
          <div className="w-full lg:w-[380px] p-3.5 rounded-xl border border-emerald-900/40 bg-emerald-950/20 flex flex-col gap-1.5 shrink-0">
            <div className="flex items-center gap-1.5 font-mono text-[11px] font-bold text-emerald-400 uppercase tracking-wider">
              <ShieldCheck size={14} className="text-emerald-400" />
              <span>Defensive Counter</span>
            </div>

            <p className="text-xs text-emerald-200/90 leading-relaxed font-sans">
              {selectedStage.defensiveCounter}
            </p>

            <div className="pt-2 mt-1 border-t border-emerald-900/30 flex items-center justify-between font-mono text-[10px] text-emerald-400">
              <span>Recourse Operator: <code className="text-white font-bold">{selectedStage.mitigationAction}</code></span>
              <span className="flex items-center gap-1 text-cyan-300 font-bold hover:underline cursor-pointer">
                Simulate <ArrowRight size={10} />
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Deep Symbolic Forensic Narrative (if reasoning available) */}
      {reasoning && (
        <div className="rounded-lg p-3.5 text-xs leading-relaxed border flex flex-col gap-3" style={{ backgroundColor: "color-mix(in srgb, var(--color-base) 60%, transparent)", borderColor: "var(--color-border)" }}>
          {/* Sovereign Intelligence Badges Bar */}
          <div className="flex flex-wrap items-center gap-2 pb-2.5 border-b" style={{ borderColor: "color-mix(in srgb, var(--color-text-primary) 8%, transparent)" }}>
            {reasoning.cve_id && (
              <a
                href={reasoning.nvd_advisory || `https://nvd.nist.gov/vuln/detail/${reasoning.cve_id}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-rose-500/15 text-rose-300 border border-rose-500/40 hover:bg-rose-500/25 transition-colors"
                title="View National Vulnerability Database Advisory"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse"></span>
                <span>{reasoning.cve_id}</span>
                <span className="px-1 py-0.5 rounded bg-rose-950 text-rose-400 text-[9px]">
                  CVSS {reasoning.cvss_score?.toFixed(1) || "9.8"} {reasoning.cvss_severity || "CRITICAL"}
                </span>
                <ExternalLink size={9} />
              </a>
            )}

            {reasoning.nciipc_sector && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-indigo-500/15 text-indigo-300 border border-indigo-500/40">
                <ShieldCheck size={11} className="text-indigo-400" />
                <span>{reasoning.nciipc_sector}</span>
              </span>
            )}

            {reasoning.nciipc_sop && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[9px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                <span>{reasoning.nciipc_sop}</span>
              </span>
            )}

            {reasoning.target_critical_asset && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[9px] font-mono bg-slate-800 text-slate-300 border border-slate-700 ml-auto">
                <Target size={10} className="text-amber-400" />
                <span>Asset: {reasoning.target_critical_asset}</span>
              </span>
            )}
          </div>

          <div className="flex items-start gap-2.5">
            <AlertCircle size={15} className="text-[var(--color-accent)] mt-0.5 shrink-0" />
            <p className="text-[var(--color-text-primary)] font-sans leading-relaxed">
              {reasoning.forensic_narrative}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-2 border-t font-mono text-[11px]" style={{ borderColor: "color-mix(in srgb, var(--color-text-primary) 8%, transparent)" }}>
            <span className="text-[var(--color-text-secondary)]">
              TECHNIQUE: <strong className="text-[var(--color-accent)]">{reasoning.mitre_technique_id} ({reasoning.mitre_technique_name})</strong>
            </span>
            <span className="text-[var(--color-text-secondary)]">
              CAPEC: <strong className="text-pink-400">{reasoning.capec_id} ({reasoning.capec_name})</strong>
            </span>
            <span className="text-[var(--color-text-secondary)]">
              TRANSITION: <strong className="text-amber-400">{reasoning.lifecycle_transition}</strong>
            </span>
            {reasoning.mitre_url && (
              <a
                href={reasoning.mitre_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-[var(--color-accent)] hover:underline ml-auto"
              >
                <span>MITRE Docs</span>
                <ExternalLink size={10} />
              </a>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
