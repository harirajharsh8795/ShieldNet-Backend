import { useState } from "react";
import { motion } from "framer-motion";
import { Network, Shield, AlertTriangle, Cpu, Server, Zap } from "lucide-react";

interface TopologyNode {
  id: string;
  label: string;
  ip: string;
  type: "attacker" | "edge" | "dmz" | "internal" | "scada";
  x: number;
  y: number;
  status: "normal" | "warning" | "compromised" | "isolated";
  mitreStage?: string;
  flowCount: number;
}

interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  protocol: string;
  port: number;
  threatLevel: "benign" | "suspicious" | "critical";
  throughput: string;
}

interface ScenarioGraphData {
  title: string;
  description: string;
  threatScore: number;
  forecastStage: string;
  leadTime: string;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

const SCENARIOS: Record<string, ScenarioGraphData> = {
  ssh_patator: {
    title: "SSH-Patator Automated Credential Assault",
    description: "External probe breaching perimeter via high-rate Port 22 dictionary assault. World Model forecasts Initial Access compromise in +20s.",
    threatScore: 0.94,
    forecastStage: "MITRE TA0001: Initial Access (T1110.001)",
    leadTime: "Proactive Lead Time: +22.4s Pre-Compromise Warning",
    nodes: [
      { id: "ext", label: "External Ingress Probe", ip: "192.168.10.50", type: "attacker", x: 70, y: 150, status: "compromised", flowCount: 1840 },
      { id: "edge", label: "ShieldNet Edge Sensor", ip: "10.0.0.1", type: "edge", x: 260, y: 150, status: "warning", flowCount: 2450 },
      { id: "dmz", label: "DMZ SSH / Web Gateway", ip: "10.0.0.80", type: "dmz", x: 460, y: 100, status: "compromised", mitreStage: "Compromise Target in t+2", flowCount: 1620 },
      { id: "core", label: "Core Enterprise Active Directory", ip: "10.0.1.15", type: "internal", x: 670, y: 100, status: "normal", flowCount: 380 },
      { id: "scada", label: "Critical Substation PLC", ip: "172.16.1.10", type: "scada", x: 570, y: 220, status: "normal", flowCount: 95 },
    ],
    edges: [
      { id: "e1", source: "ext", target: "edge", protocol: "TCP SYN", port: 22, threatLevel: "critical", throughput: "1,240 pkts/s" },
      { id: "e2", source: "edge", target: "dmz", protocol: "SSH-2.0", port: 22, threatLevel: "critical", throughput: "1,180 pkts/s" },
      { id: "e3", source: "dmz", target: "core", protocol: "LDAP / Kerberos", port: 389, threatLevel: "benign", throughput: "45 pkts/s" },
      { id: "e4", source: "edge", target: "scada", protocol: "Modbus TCP", port: 502, threatLevel: "benign", throughput: "12 pkts/s" },
    ],
  },
  scada_grid: {
    title: "Critical Information Infrastructure (CII) SCADA Intrusion",
    description: "Multi-stage pivot from compromised enterprise jump-host executing unauthorized Modbus/DNP3 coil overwrite into power-grid substation.",
    threatScore: 0.98,
    forecastStage: "MITRE TA0040: Impact & ICS Manipulation (T0814)",
    leadTime: "Proactive Lead Time: +35.0s Pre-Trip Warning",
    nodes: [
      { id: "ext", label: "Foreign APT Ingress", ip: "198.51.100.24", type: "attacker", x: 70, y: 150, status: "compromised", flowCount: 650 },
      { id: "edge", label: "ShieldNet Edge Sensor", ip: "10.0.0.1", type: "edge", x: 260, y: 150, status: "warning", flowCount: 1950 },
      { id: "dmz", label: "Compromised Jump-Host", ip: "10.0.0.80", type: "dmz", x: 460, y: 100, status: "warning", mitreStage: "Pivot Stage 3", flowCount: 890 },
      { id: "core", label: "Industrial SCADA Master", ip: "10.0.1.15", type: "internal", x: 670, y: 100, status: "warning", flowCount: 540 },
      { id: "scada", label: "Substation 220kV Transformer PLC", ip: "172.16.1.10", type: "scada", x: 570, y: 220, status: "compromised", mitreStage: "CRITICAL CII TARGET", flowCount: 780 },
    ],
    edges: [
      { id: "e1", source: "ext", target: "edge", protocol: "HTTPS C2", port: 443, threatLevel: "suspicious", throughput: "180 pkts/s" },
      { id: "e2", source: "edge", target: "dmz", protocol: "RDP Tunnel", port: 3389, threatLevel: "suspicious", throughput: "310 pkts/s" },
      { id: "e3", source: "dmz", target: "core", protocol: "DNP3 Polling", port: 20000, threatLevel: "critical", throughput: "450 pkts/s" },
      { id: "e4", source: "core", target: "scada", protocol: "Modbus Function 05", port: 502, threatLevel: "critical", throughput: "520 pkts/s" },
    ],
  },
  bot_c2: {
    title: "Botnet Ares C2 Periodic Beaconing",
    description: "Low-jitter encrypted periodic heartbeats attempting Command & Control handshake before payload distribution.",
    threatScore: 0.89,
    forecastStage: "MITRE TA0011: Command & Control (T1071.001)",
    leadTime: "Proactive Lead Time: +18.5s Pre-Execution Warning",
    nodes: [
      { id: "ext", label: "Ares C2 Controller Server", ip: "172.16.0.1", type: "attacker", x: 70, y: 150, status: "compromised", flowCount: 320 },
      { id: "edge", label: "ShieldNet Edge Sensor", ip: "10.0.0.1", type: "edge", x: 260, y: 150, status: "warning", flowCount: 1400 },
      { id: "dmz", label: "Infected Enterprise Host", ip: "192.168.10.14", type: "dmz", x: 460, y: 100, status: "compromised", mitreStage: "Beaconing Active", flowCount: 420 },
      { id: "core", label: "Internal File Server", ip: "10.0.1.15", type: "internal", x: 670, y: 100, status: "normal", flowCount: 180 },
      { id: "scada", label: "Critical Substation PLC", ip: "172.16.1.10", type: "scada", x: 570, y: 220, status: "normal", flowCount: 40 },
    ],
    edges: [
      { id: "e1", source: "dmz", target: "edge", protocol: "TLS Periodic", port: 8443, threatLevel: "critical", throughput: "60 pkts/s" },
      { id: "e2", source: "edge", target: "ext", protocol: "Encrypted C2", port: 8443, threatLevel: "critical", throughput: "60 pkts/s" },
      { id: "e3", source: "dmz", target: "core", protocol: "SMB Read", port: 445, threatLevel: "suspicious", throughput: "95 pkts/s" },
      { id: "e4", source: "edge", target: "scada", protocol: "Telemetry Keepalive", port: 502, threatLevel: "benign", throughput: "8 pkts/s" },
    ],
  },
  benign_norm: {
    title: "Normal Enterprise Workstation Baseline",
    description: "Stationary baseline equilibrium with legitimate web browsing, DNS queries, and internal routine synchronization.",
    threatScore: 0.02,
    forecastStage: "MITRE: Equilibrium (BENIGN)",
    leadTime: "No Progression Detected (Clean Traffic Flow)",
    nodes: [
      { id: "ext", label: "Public Internet Gateways", ip: "8.8.8.8", type: "attacker", x: 70, y: 150, status: "normal", flowCount: 840 },
      { id: "edge", label: "ShieldNet Edge Sensor", ip: "10.0.0.1", type: "edge", x: 260, y: 150, status: "normal", flowCount: 3100 },
      { id: "dmz", label: "Enterprise Workstation", ip: "192.168.10.15", type: "dmz", x: 460, y: 100, status: "normal", mitreStage: "Clean", flowCount: 920 },
      { id: "core", label: "Core Active Directory", ip: "10.0.1.15", type: "internal", x: 670, y: 100, status: "normal", flowCount: 650 },
      { id: "scada", label: "Critical Substation PLC", ip: "172.16.1.10", type: "scada", x: 570, y: 220, status: "normal", flowCount: 110 },
    ],
    edges: [
      { id: "e1", source: "dmz", target: "edge", protocol: "HTTPS / TLS", port: 443, threatLevel: "benign", throughput: "540 pkts/s" },
      { id: "e2", source: "edge", target: "ext", protocol: "DNS Queries", port: 53, threatLevel: "benign", throughput: "80 pkts/s" },
      { id: "e3", source: "dmz", target: "core", protocol: "Kerberos Auth", port: 88, threatLevel: "benign", throughput: "120 pkts/s" },
      { id: "e4", source: "edge", target: "scada", protocol: "Periodic Heartbeat", port: 502, threatLevel: "benign", throughput: "15 pkts/s" },
    ],
  },
};

export function NetworkTopologyGraph() {
  const [selectedScenarioKey, setSelectedScenarioKey] = useState<string>("ssh_patator");
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);

  const scenario = SCENARIOS[selectedScenarioKey] || SCENARIOS.ssh_patator;

  // Helper to find node coordinates
  const getNode = (id: string) => scenario.nodes.find((n) => n.id === id);

  return (
    <div className="rounded-xl border p-5 glow-box flex flex-col gap-4" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-3" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[var(--color-accent)]/10 text-[var(--color-accent)]">
            <Network size={20} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-[var(--color-text-primary)]">
                DYNAMIC NETWORK TOPOLOGY GRAPH ($G_t = (V, E, X_t)$)
              </h2>
              <span className="font-mono text-[10px] text-[var(--color-accent)] bg-[var(--color-accent)]/10 border border-[var(--color-accent)]/30 px-2 py-0.5 rounded">
                CLAUSE 5 COMPLIANT
              </span>
            </div>
            <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
              Graph representation of host communication states, active flows, and forward-simulated attack progression across enterprise &amp; Critical Infrastructure (CII).
            </p>
          </div>
        </div>

        {/* Live Scenario Selector Buttons */}
        <div className="flex items-center gap-1.5 font-mono text-xs">
          <span className="text-[var(--color-text-muted)] mr-1 hidden sm:inline">Scenario:</span>
          {[
            { key: "ssh_patator", label: "SSH-Patator (Brute)" },
            { key: "scada_grid", label: "⚡ CII SCADA (Grid)" },
            { key: "bot_c2", label: "Botnet C2 (Ares)" },
            { key: "benign_norm", label: "🟢 Normal Benign" },
          ].map((item) => (
            <button
              key={item.key}
              onClick={() => {
                setSelectedScenarioKey(item.key);
                setSelectedNode(null);
              }}
              className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-all ${
                selectedScenarioKey === item.key
                  ? "bg-[var(--color-accent)] text-slate-950 shadow-sm"
                  : "bg-[var(--color-base)] text-[var(--color-text-secondary)] hover:text-white border border-[var(--color-border)]"
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* Scenario Status Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg border bg-[var(--color-base)] text-xs" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-full font-bold font-mono text-xs ${
            scenario.threatScore > 0.8
              ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
              : scenario.threatScore > 0.4
              ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
              : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
          }`}>
            {(scenario.threatScore * 100).toFixed(0)}% THREAT
          </div>
          <div>
            <div className="font-semibold text-[var(--color-text-primary)]">{scenario.title}</div>
            <div className="text-[11px] text-[var(--color-text-muted)]">{scenario.description}</div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 font-mono text-[11px]">
          <span className="px-2.5 py-1 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">
            {scenario.forecastStage}
          </span>
          <span className="px-2.5 py-1 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
            {scenario.leadTime}
          </span>
        </div>
      </div>

      {/* Interactive SVG Network Graph Canvas */}
      <div className="relative w-full h-[320px] rounded-xl border bg-slate-950/60 overflow-hidden flex items-center justify-center" style={{ borderColor: "var(--color-border)" }}>
        {/* Subtle background grid */}
        <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />

        <svg className="w-full h-full" viewBox="0 0 760 300">
          <defs>
            <linearGradient id="edgeGradCritical" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="edgeGradSuspicious" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.7" />
              <stop offset="100%" stopColor="#fbbf24" stopOpacity="0.7" />
            </linearGradient>
            <linearGradient id="edgeGradBenign" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.5" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.5" />
            </linearGradient>
            <filter id="glowFilter" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Render Flow Edges */}
          {scenario.edges.map((edge) => {
            const src = getNode(edge.source);
            const tgt = getNode(edge.target);
            if (!src || !tgt) return null;

            const isCritical = edge.threatLevel === "critical";
            const isSuspicious = edge.threatLevel === "suspicious";

            const strokeColor = isCritical
              ? "url(#edgeGradCritical)"
              : isSuspicious
              ? "url(#edgeGradSuspicious)"
              : "url(#edgeGradBenign)";

            const midX = (src.x + tgt.x) / 2;
            const midY = (src.y + tgt.y) / 2 - 12;

            return (
              <g key={edge.id} className="cursor-pointer">
                {/* Flow Line */}
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={tgt.x}
                  y2={tgt.y}
                  stroke={strokeColor}
                  strokeWidth={isCritical ? 3.5 : isSuspicious ? 2.5 : 1.5}
                  strokeDasharray={isCritical ? "6 3" : undefined}
                  filter={isCritical ? "url(#glowFilter)" : undefined}
                />

                {/* Animated Packet Pulse on active flows */}
                <circle r={isCritical ? 4 : 3} fill={isCritical ? "#ff4444" : "#22d3ee"}>
                  <animateMotion
                    path={`M ${src.x} ${src.y} L ${tgt.x} ${tgt.y}`}
                    dur={isCritical ? "1.2s" : "2.4s"}
                    repeatCount="indefinite"
                  />
                </circle>

                {/* Protocol & Port Tag */}
                <rect
                  x={midX - 38}
                  y={midY - 8}
                  width="76"
                  height="16"
                  rx="4"
                  fill="#0b0f19"
                  stroke={isCritical ? "#ef4444" : "#1e293b"}
                  strokeWidth="1"
                />
                <text
                  x={midX}
                  y={midY + 4}
                  textAnchor="middle"
                  fill={isCritical ? "#f87171" : "#94a3b8"}
                  fontSize="9"
                  fontFamily="monospace"
                >
                  {edge.protocol} :{edge.port}
                </text>
              </g>
            );
          })}

          {/* Render Host / Subnet Nodes */}
          {scenario.nodes.map((node) => {
            const isCompromised = node.status === "compromised";
            const isWarning = node.status === "warning";

            const nodeFill = isCompromised
              ? "#450a0a"
              : isWarning
              ? "#451a03"
              : node.type === "scada"
              ? "#1e1b4b"
              : "#0f172a";

            const nodeStroke = isCompromised
              ? "#ef4444"
              : isWarning
              ? "#f59e0b"
              : node.type === "scada"
              ? "#a855f7"
              : "#06b6d4";

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                className="cursor-pointer group"
                onClick={() => setSelectedNode(node)}
              >
                {/* Node Outer Halo */}
                {isCompromised && (
                  <circle
                    r="28"
                    fill="none"
                    stroke="#ef4444"
                    strokeWidth="1.5"
                    opacity="0.4"
                    className="animate-ping"
                  />
                )}

                <circle
                  r="22"
                  fill={nodeFill}
                  stroke={nodeStroke}
                  strokeWidth={selectedNode?.id === node.id ? "3" : "2"}
                  filter={isCompromised ? "url(#glowFilter)" : undefined}
                />

                {/* Icon inside Node */}
                <g transform="translate(-8, -8)" className="pointer-events-none">
                  {node.type === "attacker" && <AlertTriangle size={16} className={isCompromised ? "text-rose-400" : "text-cyan-400"} />}
                  {node.type === "edge" && <Shield size={16} className="text-cyan-400" />}
                  {node.type === "dmz" && <Server size={16} className={isCompromised ? "text-rose-400" : "text-amber-400"} />}
                  {node.type === "internal" && <Cpu size={16} className="text-blue-400" />}
                  {node.type === "scada" && <Zap size={16} className="text-purple-400" />}
                </g>

                {/* Node Label & IP */}
                <text
                  y="34"
                  textAnchor="middle"
                  fill="#f8fafc"
                  fontSize="10"
                  fontWeight="600"
                  className="select-none"
                >
                  {node.label}
                </text>
                <text
                  y="46"
                  textAnchor="middle"
                  fill="#64748b"
                  fontSize="9"
                  fontFamily="monospace"
                  className="select-none"
                >
                  {node.ip}
                </text>

                {/* Threat Badge */}
                {node.mitreStage && (
                  <g transform="translate(0, -28)">
                    <rect
                      x="-65"
                      y="-7"
                      width="130"
                      height="15"
                      rx="3"
                      fill="#7f1d1d"
                      stroke="#ef4444"
                      strokeWidth="0.8"
                    />
                    <text
                      textAnchor="middle"
                      y="4"
                      fill="#fecaca"
                      fontSize="8"
                      fontWeight="bold"
                      fontFamily="monospace"
                    >
                      {node.mitreStage}
                    </text>
                  </g>
                )}
              </g>
            );
          })}
        </svg>

        {/* Selected Node Inspector Drawer */}
        {selectedNode && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="absolute bottom-3 right-3 max-w-[280px] p-3 rounded-lg border bg-slate-900/95 backdrop-blur-md shadow-xl text-xs font-mono"
            style={{ borderColor: "var(--color-border)" }}
          >
            <div className="flex items-center justify-between border-b pb-1.5 mb-2" style={{ borderColor: "var(--color-border)" }}>
              <span className="font-bold text-[var(--color-text-primary)]">{selectedNode.label}</span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-[var(--color-text-muted)] hover:text-white"
              >
                ✕
              </button>
            </div>
            <div className="space-y-1 text-[11px] text-[var(--color-text-secondary)]">
              <div>IP: <span className="text-[var(--color-accent)]">{selectedNode.ip}</span></div>
              <div>Telemetry Volume: <span className="text-white">{selectedNode.flowCount} flows</span></div>
              <div>Status: <span className={selectedNode.status === "compromised" ? "text-rose-400 font-bold" : "text-emerald-400"}>{selectedNode.status.toUpperCase()}</span></div>
              {selectedNode.mitreStage && <div>Alert: <span className="text-purple-300">{selectedNode.mitreStage}</span></div>}
            </div>
          </motion.div>
        )}
      </div>

      {/* Graph Topological Statistics Matrix */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
        <div className="p-2.5 rounded-lg border bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
          <div className="text-[10px] text-[var(--color-text-muted)]">ACTIVE HOST NODES |V|</div>
          <div className="font-bold text-[var(--color-text-primary)] mt-0.5">5 Subnets / Endpoints</div>
        </div>
        <div className="p-2.5 rounded-lg border bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
          <div className="text-[10px] text-[var(--color-text-muted)]">ACTIVE FLOW EDGES |E|</div>
          <div className="font-bold text-cyan-400 mt-0.5">4 Bidirectional Streams</div>
        </div>
        <div className="p-2.5 rounded-lg border bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
          <div className="text-[10px] text-[var(--color-text-muted)]">GRAPH SPECTRAL ENTROPY</div>
          <div className="font-bold text-purple-400 mt-0.5">0.842 (Anomalous Shift)</div>
        </div>
        <div className="p-2.5 rounded-lg border bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
          <div className="text-[10px] text-[var(--color-text-muted)]">K-STEP PROJECTION HORIZON</div>
          <div className="font-bold text-emerald-400 mt-0.5">+50s Lead Time Warning</div>
        </div>
      </div>
    </div>
  );
}
