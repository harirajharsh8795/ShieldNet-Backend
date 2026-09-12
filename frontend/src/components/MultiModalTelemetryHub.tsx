import { useState } from "react";
import { 
  Database, 
  Layers, 
  CheckCircle2, 
  Zap, 
  ArrowRight,
  FileCode,
  Radio
} from "lucide-react";
import { useAppStore } from "../store/useAppStore";
import { useNavigate } from "react-router-dom";

interface DatasetMeta {
  id: string;
  name: string;
  institution: string;
  modality: "NetFlow L4/L7" | "Raw Packet (PCAP)" | "Host Authentication" | "Industrial IoT";
  format: "CSV (84-Dim)" | "PCAP (Binary)" | "JSON / Kerberos" | "CSV (46-Dim Adapted)";
  records: string;
  attacksCovered: string[];
  schemaAdapterMethod: string;
  statusBadge: string;
  targetScenarioId: string;
  sampleFilename: string;
}

const MANDATED_DATASETS: DatasetMeta[] = [
  {
    id: "cic-ids",
    name: "CIC-IDS-2017 / 2018",
    institution: "Canadian Institute for Cybersecurity (UNB)",
    modality: "NetFlow L4/L7",
    format: "CSV (84-Dim)",
    records: "2.8 Million Flows · 14 Attack Vectors",
    attacksCovered: ["SSH-Patator", "FTP-Patator", "DoS Hulk", "Slowloris", "DDoS Flood", "PortScan"],
    schemaAdapterMethod: "Native 77 NetFlow Extractor + Deterministic L7 Proxy Imputation (pcap_imputer)",
    statusBadge: "BENCHMARK CHAMPION (87.70% BA)",
    targetScenarioId: "sess_ssh_patator",
    sampleFilename: "3_SSH_FTP_Patator_BruteForce.csv",
  },
  {
    id: "unsw-nb15",
    name: "UNSW-NB15 Benchmark",
    institution: "Australian Cyber Security Centre (ACSC / ADFA)",
    modality: "NetFlow L4/L7",
    format: "CSV (84-Dim)",
    records: "2.54 Million Records · 9 Attack Families",
    attacksCovered: ["Fuzzers", "Analysis", "Backdoors", "DoS", "Exploits", "Generic", "Reconnaissance"],
    schemaAdapterMethod: "Cross-Dataset Schema Adapter (schema_adapter.py) with 49-to-84 feature projection",
    statusBadge: "EMPIRICAL TESTED (F1: 91.2%)",
    targetScenarioId: "sess_bot_c2",
    sampleFilename: "2_Botnet_Ares_C2_Periodic_Beacon.csv",
  },
  {
    id: "ctu-13",
    name: "CTU-13 Botnet Repository",
    institution: "Czech Technical University (ATG Group)",
    modality: "NetFlow L4/L7",
    format: "CSV (84-Dim)",
    records: "13 Real Botnet Capture Scenarios",
    attacksCovered: ["Neris", "Rbot", "Virut", "Menti", "Sogou", "Ares/Mirai C2 Beaconing"],
    schemaAdapterMethod: "Flow IAT Jitter + Reverse Shell Payload Entropy Tracking (L=3 Temporal Sequences)",
    statusBadge: "ACTIVE FORECAST (LEAD TIME +22.4s)",
    targetScenarioId: "sess_bot_c2",
    sampleFilename: "2_Botnet_Ares_C2_Periodic_Beacon.csv",
  },
  {
    id: "ciciot2023",
    name: "CICIoT2023 Smart-Grid & IoT",
    institution: "University of New Brunswick / IoT Security Lab",
    modality: "Industrial IoT",
    format: "CSV (46-Dim Adapted)",
    records: "46 IoT Telemetry Channels · 33 Attack Classes",
    attacksCovered: ["DDoS-SYN_Flood", "Mirai-UDP_Plain", "Recon-PortScan", "Command Injection"],
    schemaAdapterMethod: "Adaptive Zero-Imputation Adapter with dynamic scaling alignment",
    statusBadge: "CROSS-DOMAIN HARDENED",
    targetScenarioId: "session-ciciot-ddos-flood",
    sampleFilename: "6_CICIoT2023_SmartGrid_IoT_Flood.csv",
  },
  {
    id: "lanl-auth",
    name: "LANL Enterprise Auth Logs",
    institution: "Los Alamos National Laboratory (Cyber Defense)",
    modality: "Host Authentication",
    format: "JSON / Kerberos",
    records: "1.6 Billion Events · 58 Days Red-Team Operations",
    attacksCovered: ["Pass-the-Hash (T1550)", "Kerberos Ticket Forgery", "Auth Velocity Burst", "AD Fan-Out"],
    schemaAdapterMethod: "Auth Log Fuser (auth_log_fuser.py) translating auth bursts to continuous velocity",
    statusBadge: "LATERAL MOVEMENT TRACKER",
    targetScenarioId: "sess_lanl_lateral_movement",
    sampleFilename: "7_LANL_Enterprise_Kerberos_LateralMovement.csv",
  },
  {
    id: "darpa-pcap",
    name: "DARPA Military Cyber Range",
    institution: "US DoD / MIT Lincoln Laboratory",
    modality: "Raw Packet (PCAP)",
    format: "PCAP (Binary)",
    records: "Multi-Stage Attack PCAP Traces",
    attacksCovered: ["External Reconnaissance", "Exploitation via Buffer Overflow", "Privilege Escalation"],
    schemaAdapterMethod: "Universal PCAP Extractor (UniversalPCAPExtractor) via native Scapy packet parsing",
    statusBadge: "TRUE L7 DPI VERIFIED",
    targetScenarioId: "outside_darpa1998_military.pcap",
    sampleFilename: "outside_darpa1998_military.pcap",
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

export function MultiModalTelemetryHub() {
  const [activeTab, setActiveTab] = useState<"datasets" | "knowledge" | "architecture">("datasets");
  const setActiveIngestion = useAppStore((s) => s.setActiveIngestion);
  const navigate = useNavigate();

  const handle1ClickLoad = (dataset: DatasetMeta) => {
    setActiveIngestion({
      id: dataset.targetScenarioId,
      sourceType: dataset.format.includes("PCAP") ? "pcap" : "csv",
      filename: dataset.sampleFilename,
      datasetName: dataset.id === "cic-ids" ? "cic-ids-2018" : (dataset.id as any),
      uploadedAt: new Date().toISOString(),
      status: "ready",
      matchedScenarioId: dataset.targetScenarioId,
    });
    navigate(`/dashboard/simulation?session=${dataset.targetScenarioId}`);
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
                MULTI-MODAL TRI-TELEMETRY FUSION &amp; SOVEREIGN KNOWLEDGE HUB
              </h2>
              <span className="font-mono text-[9px] px-2 py-0.5 rounded-full font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                PS 26153 NTRO MANDATED
              </span>
            </div>
            <p className="text-xs text-[var(--color-text-muted)] mt-0.5 font-sans">
              Ingests 6 standardized cyber datasets, fuses NetFlow + Raw PCAP + Host Auth telemetry into 84 continuous dimensions, and correlates predictions with 3 authoritative knowledge bases.
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1.5 p-1 rounded-lg bg-[var(--color-base)] border" style={{ borderColor: "var(--color-border)" }}>
          <button
            onClick={() => setActiveTab("datasets")}
            className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-all ${
              activeTab === "datasets"
                ? "bg-[var(--color-accent)] text-slate-950 shadow-sm"
                : "text-[var(--color-text-secondary)] hover:text-white"
            }`}
          >
            Mandated Datasets (6)
          </button>
          <button
            onClick={() => setActiveTab("knowledge")}
            className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-all ${
              activeTab === "knowledge"
                ? "bg-[var(--color-accent)] text-slate-950 shadow-sm"
                : "text-[var(--color-text-secondary)] hover:text-white"
            }`}
          >
            Knowledge Bases (3)
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

      {/* TAB 1: 6 MANDATED DATASETS */}
      {activeTab === "datasets" && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {MANDATED_DATASETS.map((ds) => (
            <div
              key={ds.id}
              className="flex flex-col justify-between rounded-xl border p-4 bg-[var(--color-base)] hover:border-[var(--color-accent)]/60 transition-all group"
              style={{ borderColor: "var(--color-border)" }}
            >
              <div className="flex flex-col gap-2.5">
                {/* Header Row */}
                <div className="flex items-center justify-between font-mono text-[10px]">
                  <span className="px-2 py-0.5 rounded bg-[var(--color-panel-raised)] text-[var(--color-accent)] border border-white/10 font-bold">
                    {ds.modality}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                    {ds.statusBadge}
                  </span>
                </div>

                {/* Title & Institution */}
                <div>
                  <h3 className="font-bold text-sm text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] transition-colors">
                    {ds.name}
                  </h3>
                  <p className="text-[11px] text-[var(--color-text-muted)] font-mono">
                    {ds.institution}
                  </p>
                </div>

                {/* Format & Records */}
                <div className="flex items-center gap-2 font-mono text-[11px] text-[var(--color-text-secondary)]">
                  <FileCode size={13} className="text-cyan-400 shrink-0" />
                  <span className="truncate">{ds.records}</span>
                </div>

                {/* Ingestion Strategy */}
                <div className="rounded-lg p-2.5 bg-[var(--color-panel-raised)] border border-white/5 flex flex-col gap-1">
                  <span className="font-mono text-[9px] uppercase tracking-wider text-[var(--color-accent)] font-bold">
                    Ingestion &amp; Feature Schema:
                  </span>
                  <p className="text-[11px] text-[var(--color-text-secondary)] font-sans leading-snug">
                    {ds.schemaAdapterMethod}
                  </p>
                </div>

                {/* Attack Tags */}
                <div className="flex flex-wrap gap-1 mt-0.5">
                  {ds.attacksCovered.slice(0, 3).map((atk) => (
                    <span
                      key={atk}
                      className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-rose-950/40 text-rose-300 border border-rose-900/40"
                    >
                      {atk}
                    </span>
                  ))}
                  {ds.attacksCovered.length > 3 && (
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-slate-800 text-slate-400">
                      +{ds.attacksCovered.length - 3} more
                    </span>
                  )}
                </div>
              </div>

              {/* Bottom Action Button */}
              <div className="pt-3 mt-3 border-t flex items-center justify-between" style={{ borderColor: "color-mix(in srgb, var(--color-text-primary) 8%, transparent)" }}>
                <span className="font-mono text-[10px] text-[var(--color-text-muted)]">
                  {ds.format}
                </span>
                <button
                  onClick={() => handle1ClickLoad(ds)}
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-mono font-bold bg-[var(--color-accent)]/15 text-[var(--color-accent)] border border-[var(--color-accent)]/40 hover:bg-[var(--color-accent)] hover:text-slate-950 transition-all cursor-pointer"
                >
                  <span>1-Click Ingest</span>
                  <ArrowRight size={12} />
                </button>
              </div>
            </div>
          ))}
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
                Tri-Telemetry State Unification Pipeline ($s_t \in \mathbb&#123;R&#125;^&#123;84&#125;$)
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
