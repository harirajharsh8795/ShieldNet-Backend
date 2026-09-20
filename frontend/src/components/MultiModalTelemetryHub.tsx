import { useState } from "react";
import { 
  Database, 
  Layers, 
  CheckCircle2, 
  Zap, 
  Radio,
  Download
} from "lucide-react";
import { useAppStore } from "../store/useAppStore";
import { useNavigate } from "react-router-dom";
import type { SourceType, DatasetName } from "../data/types";

export interface SampleTelemetryFile {
  name: string;
  type: SourceType;
  size: string;
  scenarioId: string;
  label: string;
  desc: string;
  severity: "critical" | "elevated" | "normal";
  host_ip: string;
  target_ip: string;
  ground_truth: string;
  category: "attack" | "pcap" | "cii" | "benign";
}

export const SAMPLE_FILES: SampleTelemetryFile[] = [
  {
    name: "1_BENIGN_Normal_Enterprise_Traffic.csv",
    type: "csv",
    size: "17.2 KB",
    scenarioId: "sess_benign_normal",
    label: "Normal Enterprise Workstation Baseline",
    desc: "Stationary benign HTTPS/TLS & DNS queries. Baseline equilibrium with zero anomalous progression.",
    severity: "normal",
    host_ip: "192.168.10.15",
    target_ip: "192.168.10.1",
    ground_truth: "BENIGN (Normal Browsing)",
    category: "benign",
  },
  {
    name: "2_Botnet_Ares_C2_Periodic_Beacon.csv",
    type: "csv",
    size: "17.3 KB",
    scenarioId: "sess_bot_c2",
    label: "Botnet C2 Periodic Beaconing (ARES/Mirai)",
    desc: "Low-jitter periodic heartbeat beacons to external C2 controller with subtle payload expansion.",
    severity: "critical",
    host_ip: "192.168.10.14",
    target_ip: "172.16.0.1",
    ground_truth: "Botnet C2 (MITRE T1071)",
    category: "attack",
  },
  {
    name: "3_SSH_FTP_Patator_BruteForce.csv",
    type: "csv",
    size: "17.2 KB",
    scenarioId: "sess_ssh_patator",
    label: "SSH-Patator Automated Credential Assault",
    desc: "High-frequency dictionary brute force authentication attacking Port 22 with RST flag storms.",
    severity: "critical",
    host_ip: "192.168.10.8",
    target_ip: "192.168.10.50",
    ground_truth: "SSH-Patator (MITRE T1110)",
    category: "attack",
  },
  {
    name: "4_Volumetric_DDoS_Hulk_Flood.csv",
    type: "csv",
    size: "12.3 KB",
    scenarioId: "sess_slowloris_dos",
    label: "Slowloris & HTTP Volumetric Exhaustion",
    desc: "Massive socket pool exhaustion holding incomplete HTTP GET headers, starving enterprise web servers.",
    severity: "critical",
    host_ip: "192.168.10.5",
    target_ip: "192.168.10.50",
    ground_truth: "DoS Hulk / Slowloris (MITRE T1498)",
    category: "attack",
  },
  {
    name: "5_CII_SCADA_Infiltration_Attack.csv",
    type: "csv",
    size: "17.2 KB",
    scenarioId: "session-scada-grid-exfiltration",
    label: "NCIIPC Power Grid Substation Intrusion",
    desc: "Unauthorized Modbus/DNP3 industrial gateway command injection and ICS coil read/write bursts.",
    severity: "critical",
    host_ip: "10.0.100.42",
    target_ip: "192.168.10.50",
    ground_truth: "CII SCADA Infiltration (MITRE T0814)",
    category: "cii",
  },
  {
    name: "6_CICIoT2023_SmartGrid_IoT_Flood.csv",
    type: "csv",
    size: "1.4 KB",
    scenarioId: "session-ciciot-ddos-flood",
    label: "CICIoT2023 Smart-Grid IoT Botnet & DDoS Flood",
    desc: "Volumetric SYN/UDP flood across 46 IoT telemetry channels automatically adapted to ShieldNet 84-channel World Model state space.",
    severity: "critical",
    host_ip: "192.168.1.105",
    target_ip: "10.0.100.50",
    ground_truth: "CICIoT2023 DDoS-SYN_Flood (MITRE T1498)",
    category: "attack",
  },
  {
    name: "7_LANL_Enterprise_Kerberos_LateralMovement.csv",
    type: "csv",
    size: "1.2 KB",
    scenarioId: "sess_lanl_lateral_movement",
    label: "LANL Enterprise Kerberos/NTLM Lateral Movement",
    desc: "Red-team adversary credential harvesting via NTLM Pass-the-Hash, high auth velocity burst, and fan-out across critical Active Directory hosts.",
    severity: "critical",
    host_ip: "COMP_PIVOT_01",
    target_ip: "DC_01",
    ground_truth: "LANL Lateral Movement (MITRE T1078, T1021, T1550)",
    category: "attack",
  },
  {
    name: "sample_enterprise_capture.pcap",
    type: "pcap",
    size: "0.35 KB",
    scenarioId: "sess_ssh_patator",
    label: "Enterprise Raw Packet Capture (.pcap)",
    desc: "Raw tcpdump/Wireshark packet capture with TCP SYN/ACK handshakes and packet micro-dynamics.",
    severity: "elevated",
    host_ip: "192.168.1.105",
    target_ip: "192.168.1.1",
    ground_truth: "Enterprise Traffic Stream",
    category: "pcap",
  },
  {
    name: "sample_scada_modbus.pcap",
    type: "pcap",
    size: "0.84 KB",
    scenarioId: "session-scada-grid-exfiltration",
    label: "SCADA Modbus ICS Packet Stream (.pcap)",
    desc: "Industrial telemetry packets on Port 502 with coil read/write queries and function codes.",
    severity: "critical",
    host_ip: "10.0.100.42",
    target_ip: "192.168.10.50",
    ground_truth: "Industrial Modbus/TCP",
    category: "pcap",
  },
  {
    name: "outside_darpa1998_military.pcap",
    type: "pcap",
    size: "185 KB",
    scenarioId: "sess_ssh_patator",
    label: "DARPA 1998 Military Intrusion (.pcap)",
    desc: "Authentic US Department of Defense military cyber range packet trace with raw IP/TCP packets (PS Clause 64).",
    severity: "critical",
    host_ip: "172.16.112.50",
    target_ip: "172.16.114.168",
    ground_truth: "Military Cyber Range Attack",
    category: "pcap",
  },
];

interface KnowledgeBaseMeta {
  id: string;
  name: string;
  version: string;
  curator: string;
  purpose: string;
  keyEntities: { code: string; label: string; desc: string }[];
  complianceStandard: string;
}

const KNOWLEDGE_BASES: KnowledgeBaseMeta[] = [
  {
    id: "mitre-attack",
    name: "MITRE ATT&CK Enterprise Matrix",
    version: "v14.1",
    curator: "The MITRE Corporation",
    purpose: "Authoritative adversary tactics, techniques, and common knowledge mapping for cyber defense.",
    keyEntities: [
      { code: "TA0043 / T1046", label: "Network Service Discovery", desc: "Horizontal port scanning & SYN sweeps" },
      { code: "TA0001 / T1110", label: "Brute Force Authentication", desc: "SSH & FTP dictionary credential attacks" },
      { code: "TA0008 / T1021", label: "Remote Services / SCADA Infiltration", desc: "Modbus/DNP3 industrial command injection" },
      { code: "TA0011 / T1071", label: "C2 Web Beaconing", desc: "Periodic jittered outbound heartbeat loops" },
      { code: "TA0040 / T1498", label: "Network Denial of Service", desc: "Volumetric TCP/HTTP socket exhaustion" },
    ],
    complianceStandard: "NIST SP 800-53 Rev. 5 · Zero Opacity (Constraint C2)",
  },
  {
    id: "mitre-capec",
    name: "MITRE CAPEC (Attack Patterns)",
    version: "v3.9",
    curator: "MITRE / US Homeland Security DHS CISA",
    purpose: "Comprehensive dictionary of known adversary attack patterns and exploitation mechanisms.",
    keyEntities: [
      { code: "CAPEC-300", label: "Port Scanning", desc: "Systematic probing of listener ports to identify active daemons" },
      { code: "CAPEC-112", label: "Brute Force Password Guessing", desc: "High-frequency credential spraying against authentication services" },
      { code: "CAPEC-665", label: "SCADA Register & Coil Manipulation", desc: "Unauthorized write operations to PLC register addresses" },
      { code: "CAPEC-588", label: "Reverse Shell Command Loop", desc: "Outbound socket binding host shell to adversary C2 listener" },
      { code: "CAPEC-486", label: "HTTP / TCP Socket Exhaustion", desc: "Holding half-open connection slots to induce denial of service" },
    ],
    complianceStandard: "ISO/IEC 27001:2022 A.8.16 & A.8.23 Compliance",
  },
  {
    id: "cve-nvd-nciipc",
    name: "NIST NVD / CVE & NCIIPC Sovereign Mandate",
    version: "CVSS v3.1 / NCIIPC SOP v2.4",
    curator: "NIST NVD + National Critical Information Infrastructure Protection Centre (NTRO)",
    purpose: "Hardware/software vulnerability scoring correlated directly with India's Critical Sector SOPs.",
    keyEntities: [
      { code: "CVE-2022-29951", label: "SCADA Modbus RCE (CVSS 9.8)", desc: "NCIIPC Sector 1 (Power & Energy) · SOP-SEC1-04: Substation Isolation" },
      { code: "CVE-2018-15473", label: "OpenSSH User Enumeration (CVSS 7.5)", desc: "NCIIPC Sector 2 (BFSI / Banking) · SOP-SEC2-12: Zero-Trust Lockout" },
      { code: "CVE-2019-11510", label: "VPN Core Arbitrary Read (CVSS 9.8)", desc: "NCIIPC Sector 3 (Telecom) · SOP-SEC3-14: BGP Blackhole Routing" },
      { code: "CVE-2007-6750", label: "Apache Slowloris Exhaustion (CVSS 7.5)", desc: "NCIIPC Sector 2 (Payment Clearing) · SOP-SEC2-07: Ingress Scrubbing" },
      { code: "CVE-2020-1472", label: "Zerologon Netlogon PrivEsc (CVSS 10.0)", desc: "NCIIPC Sector 3 (Strategic R&D) · SOP-SEC3-19: AD Isolation" },
    ],
    complianceStandard: "Section 70 & 70A Information Technology Act 2000 · Section 65B Legal Evidence",
  },
];

interface MultiModalTelemetryHubProps {
  onLaunchFile?: (
    sourceType: SourceType,
    filename: string,
    datasetName: DatasetName,
    scenarioId?: string,
    fileSizeBytes?: number,
    rawCsvText?: string
  ) => void;
}

export function MultiModalTelemetryHub({ onLaunchFile }: MultiModalTelemetryHubProps) {
  const [activeTab, setActiveTab] = useState<"telemetry" | "knowledge" | "architecture">("telemetry");
  const [selectedFilter, setSelectedFilter] = useState<"all" | "attack" | "cii" | "pcap" | "benign">("all");
  const setActiveIngestion = useAppStore((s) => s.setActiveIngestion);
  const navigate = useNavigate();

  const handleLaunchFile = (file: SampleTelemetryFile) => {
    if (onLaunchFile) {
      onLaunchFile(file.type, file.name, "custom", file.scenarioId);
    } else {
      setActiveIngestion({
        id: file.scenarioId,
        sourceType: file.type,
        filename: file.name,
        datasetName: "custom",
        fileSize: file.size,
        flowCount: file.type === "pcap" ? 14 : 128,
        extractedFeatures: 84,
        uploadedAt: new Date().toISOString(),
        status: "ready",
        matchedScenarioId: file.scenarioId,
      });
      navigate(`/dashboard/simulation?session=${file.scenarioId}`);
    }
  };

  return (
    <div
      id="multimodal-telemetry-hub"
      className="rounded-xl border p-5 glow-box flex flex-col gap-5 transition-all"
      style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
    >
      {/* Main Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-4" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-[var(--color-accent)]/15 border border-[var(--color-accent)]/30 flex items-center justify-center text-[var(--color-accent)]">
            <Database size={19} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-[var(--color-text-primary)]">
                MULTI-MODAL TELEMETRY BENCHMARK &amp; KNOWLEDGE HUB
              </h2>
              <span className="font-mono text-[9px] px-2 py-0.5 rounded-full font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                PS 26153 NTRO MANDATED
              </span>
            </div>
            <p className="text-xs text-[var(--color-text-muted)] mt-0.5 font-sans">
              10 pre-loaded real telemetry captures (.csv &amp; .pcap) ready for offline inspection &amp; instant forward simulation rollout.
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1.5 p-1 rounded-lg bg-[var(--color-base)] border" style={{ borderColor: "var(--color-border)" }}>
          <button
            onClick={() => setActiveTab("telemetry")}
            className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-all ${
              activeTab === "telemetry"
                ? "bg-[var(--color-accent)] text-slate-950 shadow-sm"
                : "text-[var(--color-text-secondary)] hover:text-white"
            }`}
          >
            Telemetry Benchmarks &amp; Captures (10)
          </button>
          <button
            onClick={() => setActiveTab("knowledge")}
            className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-all ${
              activeTab === "knowledge"
                ? "bg-[var(--color-accent)] text-slate-950 shadow-sm"
                : "text-[var(--color-text-secondary)] hover:text-white"
            }`}
          >
            Sovereign Knowledge Bases (3)
          </button>
          <button
            onClick={() => setActiveTab("architecture")}
            className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-all ${
              activeTab === "architecture"
                ? "bg-[var(--color-accent)] text-slate-950 shadow-sm"
                : "text-[var(--color-text-secondary)] hover:text-white"
            }`}
          >
            84-Dim State Space
          </button>
        </div>
      </div>

      {/* TAB 1: 10 CONSOLIDATED TELEMETRY BENCHMARKS & CAPTURES */}
      {activeTab === "telemetry" && (
        <div className="flex flex-col gap-4">
          {/* Category Filter Tabs */}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              {[
                { id: "all", label: "All Telemetry (10)" },
                { id: "attack", label: "⚔️ Attack Scenarios (7)" },
                { id: "cii", label: "⚡ Critical CII SCADA (1)" },
                { id: "pcap", label: "🦈 Raw PCAP Captures (3)" },
                { id: "benign", label: "🟢 Benign Baseline (1)" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setSelectedFilter(tab.id as any)}
                  className={`px-3 py-1 rounded-md font-mono text-xs font-semibold transition-all ${
                    selectedFilter === tab.id
                      ? "bg-[var(--color-accent)] text-slate-950 shadow-sm"
                      : "bg-[var(--color-base)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)]"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <span className="font-mono text-xs text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/30">
              OFFLINE READY (C4 AIR-GAP)
            </span>
          </div>

          {/* Grid of Telemetry Cards */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {SAMPLE_FILES.filter(
              (f) =>
                selectedFilter === "all" ||
                f.category === selectedFilter ||
                (selectedFilter === "attack" && (f.category === "attack" || f.category === "cii"))
            ).map((file) => (
              <div
                key={file.name}
                className="flex flex-col justify-between rounded-lg border p-4 bg-[var(--color-base)] hover:border-[var(--color-accent)] transition-all group"
                style={{ borderColor: "var(--color-border)" }}
              >
                <div>
                  {/* Header badges */}
                  <div className="flex items-center justify-between mb-2 font-mono text-[10px]">
                    <span className={`rounded px-2 py-0.5 font-bold ${
                      file.type === "pcap" ? "bg-pink-500/20 text-pink-300 border border-pink-500/30" : "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                    }`}>
                      {file.type.toUpperCase()} · {file.size}
                    </span>
                    <span className={`rounded px-1.5 py-0.5 font-bold ${
                      file.severity === "critical"
                        ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                        : file.severity === "elevated"
                        ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                        : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                    }`}>
                      {file.severity.toUpperCase()}
                    </span>
                  </div>

                  {/* Title */}
                  <h4 className="text-xs font-semibold text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] mb-1">
                    {file.label}
                  </h4>

                  {/* Subnet Route */}
                  <div className="flex items-center gap-1.5 font-mono text-[10px] text-[var(--color-text-muted)] mb-2">
                    <span className="text-[var(--color-text-secondary)]">{file.host_ip}</span>
                    <span>→</span>
                    <span className="text-[var(--color-accent)]">{file.target_ip}</span>
                  </div>

                  {/* Ground Truth Label */}
                  <div className="mb-2">
                    <span className="inline-block font-mono text-[10px] text-purple-300 bg-purple-500/15 px-2 py-0.5 rounded border border-purple-500/25">
                      {file.ground_truth}
                    </span>
                  </div>

                  {/* Description */}
                  <p className="text-[11px] text-[var(--color-text-secondary)] line-clamp-2 mb-3">
                    {file.desc}
                  </p>
                </div>

                {/* Action Buttons: BOTH Download AND Launch Forecast! */}
                <div className="flex items-center gap-2 pt-2.5 border-t font-mono text-xs" style={{ borderColor: "var(--color-border)" }}>
                  <a
                    href={`/sample_telemetry/${file.name}`}
                    download={file.name}
                    className="flex-1 flex items-center justify-center gap-1.5 rounded py-1.5 bg-white/5 hover:bg-white/10 text-[var(--color-text-primary)] text-[11px] border border-white/10 transition-colors"
                    title={`Download authentic ${file.type.toUpperCase()} file to your computer`}
                  >
                    <Download size={12} />
                    <span>Download</span>
                  </a>
                  <button
                    onClick={() => handleLaunchFile(file)}
                    className="flex-1 flex items-center justify-center gap-1.5 rounded py-1.5 text-[11px] font-bold text-slate-950 shadow-sm hover:opacity-90 transition-all hover:scale-[1.02] cursor-pointer"
                    style={{ backgroundColor: file.type === "pcap" ? "var(--color-mitre-initial)" : "var(--color-accent)" }}
                    title="Run 84-Dim extraction & forward simulation"
                  >
                    <Zap size={12} />
                    <span>Launch Forecast</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: 3 SOVEREIGN KNOWLEDGE BASES */}
      {activeTab === "knowledge" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {KNOWLEDGE_BASES.map((kb) => (
            <div
              key={kb.id}
              className="flex flex-col justify-between rounded-xl border p-4 bg-[var(--color-base)]"
              style={{ borderColor: "var(--color-border)" }}
            >
              <div className="flex flex-col gap-3">
                {/* Header */}
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 font-bold">
                    {kb.version}
                  </span>
                  <span className="font-mono text-[10px] text-[var(--color-text-muted)]">
                    {kb.curator}
                  </span>
                </div>

                <div>
                  <h3 className="font-bold text-sm text-[var(--color-text-primary)]">
                    {kb.name}
                  </h3>
                  <p className="text-xs text-[var(--color-text-secondary)] mt-1 leading-relaxed">
                    {kb.purpose}
                  </p>
                </div>

                {/* Key Entities */}
                <div className="flex flex-col gap-2 pt-2 border-t" style={{ borderColor: "color-mix(in srgb, var(--color-text-primary) 8%, transparent)" }}>
                  <span className="font-mono text-[10px] text-[var(--color-accent)] font-bold uppercase tracking-wider">
                    Mapped Vectors &amp; Advisory Rules:
                  </span>
                  <div className="flex flex-col gap-1.5">
                    {kb.keyEntities.map((ent) => (
                      <div
                        key={ent.code}
                        className="rounded-md p-2 bg-[var(--color-panel-raised)] border border-white/5 flex flex-col gap-0.5"
                      >
                        <div className="flex items-center justify-between font-mono text-[10px]">
                          <strong className="text-cyan-300">{ent.code}</strong>
                          <span className="text-[var(--color-text-primary)] font-semibold">{ent.label}</span>
                        </div>
                        <p className="text-[10px] text-[var(--color-text-muted)] font-sans">
                          {ent.desc}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Compliance Standard */}
              <div className="pt-3 mt-3 border-t flex items-center gap-1.5 font-mono text-[10px] text-emerald-400" style={{ borderColor: "color-mix(in srgb, var(--color-text-primary) 8%, transparent)" }}>
                <CheckCircle2 size={13} className="shrink-0" />
                <span className="truncate">{kb.complianceStandard}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 3: 84-DIMENSIONAL CONTINUOUS STATE SPACE ARCHITECTURE */}
      {activeTab === "architecture" && (
        <div className="flex flex-col gap-4 rounded-xl border p-4 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 border-b pb-3" style={{ borderColor: "var(--color-border)" }}>
            <div>
              <h3 className="font-bold text-sm text-[var(--color-text-primary)]">
                Tri-Telemetry State Unification Pipeline (s_t &isin; &reals;⁸⁴ · 84 Dimensions)
              </h3>
              <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
                Deterministic transformation ensuring zero test-set leakage, cross-dataset alignment, and frozen reference scaling.
              </p>
            </div>
            <span className="font-mono text-xs px-2.5 py-1 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-bold">
              $L=3$ TEMPORAL SEQUENCE LENGTH
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="rounded-lg p-3 bg-[var(--color-panel-raised)] border border-cyan-900/40 flex flex-col gap-2">
              <div className="flex items-center gap-2 font-mono text-xs font-bold text-cyan-300">
                <Layers size={15} />
                <span>Tier 1: NetFlow Dynamics (77 Dims)</span>
              </div>
              <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                Standardized bidirectional statistical flow metrics: Flow Duration, IAT Mean/Std/Max/Min, Packet Length Variance, Subflow Fwd/Bwd Bytes, TCP Flags (SYN, RST, PSH, ACK, URG), and Flow Velocity (Packets/s, Bytes/s).
              </p>
              <span className="font-mono text-[10px] text-cyan-400 mt-auto">
                Source: CIC-IDS, UNSW-NB15, CTU-13
              </span>
            </div>

            <div className="rounded-lg p-3 bg-[var(--color-panel-raised)] border border-pink-900/40 flex flex-col gap-2">
              <div className="flex items-center gap-2 font-mono text-xs font-bold text-pink-300">
                <Radio size={15} />
                <span>Tier 2: L7 Packet Micro-Dynamics (7 Dims)</span>
              </div>
              <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                Extracted via native Scapy DPI or imputed via deterministic proxy: TCP Window Minimum, Retransmission Count, TTL Variance, Fragment Offset, Header Length Ratio, TCP Urgent Pointer, and Payload Entropy.
              </p>
              <span className="font-mono text-[10px] text-pink-400 mt-auto">
                Source: DARPA PCAP, UniversalPCAPExtractor
              </span>
            </div>

            <div className="rounded-lg p-3 bg-[var(--color-panel-raised)] border border-amber-900/40 flex flex-col gap-2">
              <div className="flex items-center gap-2 font-mono text-xs font-bold text-amber-300">
                <Zap size={15} />
                <span>Tier 3: Auth Velocity Fusion (Host Events)</span>
              </div>
              <p className="text-xs text-[var(--color-text-secondary)] leading-relaxed">
                Aggregated Kerberos/NTLM authentication stream: Authentication Velocity (attempts/10s), Failed Auth Burst Frequency, Destination Host Fan-Out Degree, and Privileged Credential Ticket Forgery indicators.
              </p>
              <span className="font-mono text-[10px] text-amber-400 mt-auto">
                Source: LANL Auth Logs (auth_log_fuser.py)
              </span>
            </div>
          </div>

          {/* Frozen Reference Scaler Notice */}
          <div className="rounded-lg p-3 bg-emerald-950/20 border border-emerald-900/30 flex items-center justify-between font-mono text-xs text-emerald-300">
            <div className="flex items-center gap-2">
              <CheckCircle2 size={15} className="text-emerald-400" />
              <span>Frozen Reference Scaler Guard (<code className="text-white">scaler_guard.py</code>): Absolute mathematical guarantee of zero runtime data leakage.</span>
            </div>
            <span className="text-emerald-400 font-bold">100% AIR-GAPPED (C4)</span>
          </div>
        </div>
      )}
    </div>
  );
}
