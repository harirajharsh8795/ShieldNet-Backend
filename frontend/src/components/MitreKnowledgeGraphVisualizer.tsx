import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Network,
  Zap,
  ShieldCheck,
  Activity,
  Fingerprint,
  FileCode
} from "lucide-react";

interface GraphNode {
  id: string;
  name: string;
  category: "precursor" | "stage" | "technique" | "mitigation";
  badge: string;
  color: string;
  glow: string;
  metric?: string;
  description: string;
  x: number;
  y: number;
}

interface GraphEdge {
  from: string;
  to: string;
  weight: number;
  label?: string;
  active: boolean;
}

interface MitreKnowledgeGraphVisualizerProps {
  scenarioId?: string;
  threatType?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
}

export function MitreKnowledgeGraphVisualizer({
  scenarioId = "sess_bot_c2",
  threatType = "Botnet Ares C2 Reverse Shell",
  mitreTactic = "Command & Control (TA0011)",
  mitreTechnique = "T1071.001 Web Protocols",
}: MitreKnowledgeGraphVisualizerProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string>("stage_c2");

  // Dynamic scenario graph topologies
  const getGraphData = () => {
    if (scenarioId === "sess_portscan_recon" || scenarioId === "sess_recon") {
      const nodes: GraphNode[] = [
        { id: "prec_syn", name: "SYN Spike (>42/s)", category: "precursor", badge: "TCP Flags", color: "#F43F5E", glow: "rgba(244,63,94,0.3)", metric: "+31% SHAP", description: "Extreme surge in unacknowledged SYN packets without 3-way handshakes.", x: 80, y: 80 },
        { id: "prec_entropy", name: "Port Entropy (2.84)", category: "precursor", badge: "Entropy", color: "#8B5CF6", glow: "rgba(139,92,246,0.3)", metric: "+42% SHAP", description: "Shannon entropy across destination ports indicating horizontal sweeps.", x: 80, y: 190 },
        { id: "prec_rst", name: "RST Ratio (0.85)", category: "precursor", badge: "Teardown", color: "#EC4899", glow: "rgba(236,72,153,0.3)", metric: "+12% SHAP", description: "Immediate closed port connection teardowns returned by target firewall.", x: 80, y: 300 },
        { id: "stage_recon", name: "Stage 1: Reconnaissance", category: "stage", badge: "TA0043", color: "#818CF8", glow: "rgba(129,140,248,0.4)", metric: "Progression: 98%", description: "Adversary actively mapping host vulnerabilities and accessible listening daemons.", x: 340, y: 190 },
        { id: "tech_scan", name: "T1046: Network Service Discovery", category: "technique", badge: "CAPEC-300", color: "#38BDF8", glow: "rgba(56,189,248,0.4)", metric: "Confidence: 0.99", description: "Automated port sweep across Class C /24 subnet using nmap SYN stealth mode.", x: 600, y: 190 },
        { id: "mit_filter", name: "M1037: Dynamic Ingress Filter", category: "mitigation", badge: "SOAR Rule", color: "#34D399", glow: "rgba(52,211,153,0.4)", metric: "Risk Drop: -84%", description: "Auto-synthesized iptables drop rule applied to border perimeter switch.", x: 860, y: 190 },
      ];
      const edges: GraphEdge[] = [
        { from: "prec_syn", to: "stage_recon", weight: 0.85, active: true },
        { from: "prec_entropy", to: "stage_recon", weight: 0.95, active: true },
        { from: "prec_rst", to: "stage_recon", weight: 0.65, active: true },
        { from: "stage_recon", to: "tech_scan", weight: 0.98, active: true },
        { from: "tech_scan", to: "mit_filter", weight: 0.92, active: true },
      ];
      return { nodes, edges };
    }

    if (scenarioId === "sess_slowloris_dos" || scenarioId === "sess_dos_hulk") {
      const nodes: GraphNode[] = [
        { id: "prec_bytes", name: "Flow Bytes (>4.8MB/s)", category: "precursor", badge: "Volume", color: "#EF4444", glow: "rgba(239,68,68,0.3)", metric: "+46% SHAP", description: "Saturating volumetric surge in inbound HTTP GET request streams.", x: 80, y: 80 },
        { id: "prec_psh", name: "PSH Flag Storm (980)", category: "precursor", badge: "TCP Push", color: "#F97316", glow: "rgba(249,115,22,0.3)", metric: "+28% SHAP", description: "Repeated data push requests without completing HTTP header terminations.", x: 80, y: 190 },
        { id: "prec_iat", name: "Micro IAT (0.0002s)", category: "precursor", badge: "Timing", color: "#F59E0B", glow: "rgba(245,158,11,0.3)", metric: "+18% SHAP", description: "Ultra-low packet inter-arrival times indicating synthetic bot generator.", x: 80, y: 300 },
        { id: "stage_impact", name: "Stage 5: Impact / Denial", category: "stage", badge: "TA0040", color: "#DC2626", glow: "rgba(220,38,38,0.4)", metric: "Progression: 99%", description: "Adversary attempting to starve enterprise web thread pool and crash gateway.", x: 340, y: 190 },
        { id: "tech_dos", name: "T1498: Network Denial of Service", category: "technique", badge: "CAPEC-486", color: "#F87171", glow: "rgba(248,113,113,0.4)", metric: "Confidence: 0.99", description: "Application layer connection hold flood exhausting TCP backlog buffers.", x: 600, y: 190 },
        { id: "mit_scrub", name: "M1037: BGP Rate Scrubbing", category: "mitigation", badge: "SOAR Rule", color: "#10B981", glow: "rgba(16,185,129,0.4)", metric: "Risk Drop: -92%", description: "Sovereign scrubbing rule redirecting volumetric traffic to null route.", x: 860, y: 190 },
      ];
      const edges: GraphEdge[] = [
        { from: "prec_bytes", to: "stage_impact", weight: 0.92, active: true },
        { from: "prec_psh", to: "stage_impact", weight: 0.88, active: true },
        { from: "prec_iat", to: "stage_impact", weight: 0.74, active: true },
        { from: "stage_impact", to: "tech_dos", weight: 0.99, active: true },
        { from: "tech_dos", to: "mit_scrub", weight: 0.95, active: true },
      ];
      return { nodes, edges };
    }

    if (scenarioId === "session-scada-grid-exfiltration" || scenarioId === "sess_lanl_lateral_movement") {
      const nodes: GraphNode[] = [
        { id: "prec_fanout", name: "Fan-Out Degree (>14 Hosts)", category: "precursor", badge: "Auth Sweep", color: "#A855F7", glow: "rgba(168,85,247,0.3)", metric: "+38% SHAP", description: "Suspicious lateral credential pivot across multiple substation domain controllers.", x: 80, y: 80 },
        { id: "prec_failburst", name: "Failed Auth Burst (5x)", category: "precursor", badge: "Kerberos/NTLM", color: "#EC4899", glow: "rgba(236,72,153,0.3)", metric: "+34% SHAP", description: "Rapid NTLM Pass-the-Hash authentication attempts against critical service accounts.", x: 80, y: 190 },
        { id: "prec_entropy", name: "Modbus Function Jitter", category: "precursor", badge: "Port 502", color: "#EAB308", glow: "rgba(234,179,8,0.3)", metric: "+22% SHAP", description: "Industrial coil read/write command bursts altering substation PLC registers.", x: 80, y: 300 },
        { id: "stage_lateral", name: "Stage 3: Lateral Movement", category: "stage", badge: "TA0008", color: "#FB923C", glow: "rgba(251,146,60,0.4)", metric: "Progression: 94%", description: "Adversary moving through internal OT/IT boundaries toward high-voltage relays.", x: 340, y: 190 },
        { id: "tech_remote", name: "T1021.002: SMB/PsExec Remote Exec", category: "technique", badge: "CAPEC-594", color: "#F97316", glow: "rgba(249,115,22,0.4)", metric: "Confidence: 0.96", description: "Unauthorized remote service execution targeting substation gateway gateway.", x: 600, y: 190 },
        { id: "mit_segment", name: "M1030: Sovereign Air-Gap Isolation", category: "mitigation", badge: "SOAR Rule", color: "#06B6D4", glow: "rgba(6,182,212,0.4)", metric: "Risk Drop: -88%", description: "Cross-CII Fabric consensus commits immediate VLAN partition and isolates compromised pivot.", x: 860, y: 190 },
      ];
      const edges: GraphEdge[] = [
        { from: "prec_fanout", to: "stage_lateral", weight: 0.94, active: true },
        { from: "prec_failburst", to: "stage_lateral", weight: 0.89, active: true },
        { from: "prec_entropy", to: "stage_lateral", weight: 0.72, active: true },
        { from: "stage_lateral", to: "tech_remote", weight: 0.97, active: true },
        { from: "tech_remote", to: "mit_segment", weight: 0.93, active: true },
      ];
      return { nodes, edges };
    }

    // Default: Ares Botnet C2 Heartbeat Scenario
    const nodes: GraphNode[] = [
      { id: "prec_bwd", name: "Bwd Packet Mean (284B)", category: "precursor", badge: "Payload Shape", color: "#06B6D4", glow: "rgba(6,182,212,0.3)", metric: "+38% SHAP", description: "Highly uniform backward payload length typical of encrypted reverse shell beacons.", x: 80, y: 80 },
      { id: "prec_jitter", name: "IAT Timing Jitter (0.042s)", category: "precursor", badge: "Heartbeat", color: "#3B82F6", glow: "rgba(59,130,246,0.3)", metric: "+27% SHAP", description: "Strict periodic 10-second polling cadence with sub-millisecond deviation.", x: 80, y: 190 },
      { id: "prec_synack", name: "SYN/ACK Asymmetry (1.00)", category: "precursor", badge: "TCP Flags", color: "#6366F1", glow: "rgba(99,102,241,0.3)", metric: "+16% SHAP", description: "Balanced single-connection persistent socket maintenance with external C2 IP.", x: 80, y: 300 },
      { id: "stage_c2", name: "Stage 4: Command & Control", category: "stage", badge: "TA0011", color: "#F43F5E", glow: "rgba(244,63,94,0.4)", metric: "Progression: 93%", description: "Compromised internal endpoint actively receiving instructions from external controller.", x: 340, y: 190 },
      { id: "tech_beacon", name: "T1071.001: Web Protocols (C2)", category: "technique", badge: "CAPEC-588", color: "#EC4899", glow: "rgba(236,72,153,0.4)", metric: "Confidence: 0.98", description: "Stealthy HTTP/TCP beacon channel disguising C2 traffic as normal web browsing.", x: 600, y: 190 },
      { id: "mit_ipdrop", name: "M1031: Network IPS Boundary Drop", category: "mitigation", badge: "SOAR Rule", color: "#10B981", glow: "rgba(16,185,129,0.4)", metric: "Risk Drop: -79%", description: "Automated perimeter firewall rule severing active socket and blacklisting C2 IP.", x: 860, y: 190 },
    ];
    const edges: GraphEdge[] = [
      { from: "prec_bwd", to: "stage_c2", weight: 0.91, active: true },
      { from: "prec_jitter", to: "stage_c2", weight: 0.86, active: true },
      { from: "prec_synack", to: "stage_c2", weight: 0.68, active: true },
      { from: "stage_c2", to: "tech_beacon", weight: 0.96, active: true },
      { from: "tech_beacon", to: "mit_ipdrop", weight: 0.90, active: true },
    ];
    return { nodes, edges };
  };

  const { nodes, edges } = getGraphData();
  const selectedNode = nodes.find((n) => n.id === selectedNodeId) || nodes[3];

  return (
    <div className="rounded-2xl border p-6 glow-box flex flex-col gap-6" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b pb-4" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex items-center gap-3">
          <div className="rounded-xl p-2.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Network size={20} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-[var(--color-text-primary)]">
                Symbolic MITRE ATT&amp;CK &amp; Precursor Knowledge Graph
              </h3>
              <span className="rounded-full bg-cyan-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-300 border border-cyan-500/30">
                DAG VISUALIZER
              </span>
            </div>
            <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
              Causal graph linking micro-telemetry signals $\to$ attack progression stage $\to$ MITRE technique $\to$ SOAR countermeasure.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs flex-wrap">
          <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            {threatType} · {mitreTechnique}
          </span>
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800/80 text-slate-300 border border-slate-700">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            {mitreTactic} · {nodes.length} Nodes
          </span>
        </div>
      </div>

      {/* SVG Directed Knowledge Graph Canvas */}
      <div className="relative w-full overflow-x-auto rounded-xl border bg-slate-950/90 p-4" style={{ borderColor: "var(--color-border)" }}>
        {/* Tier Column Headers */}
        <div className="flex justify-between min-w-[940px] px-8 mb-2 font-mono text-[11px] font-semibold text-slate-400 border-b border-slate-800 pb-2">
          <span className="w-56 text-left">① TELEMETRY PRECURSORS</span>
          <span className="w-56 text-center">② ATTACK STAGE (TACTIC)</span>
          <span className="w-56 text-center">③ MITRE ATT&amp;CK &amp; CAPEC</span>
          <span className="w-56 text-right">④ SOAR COUNTERMEASURE</span>
        </div>

        <svg viewBox="0 0 960 380" className="w-full min-w-[940px] h-[380px]" style={{ overflow: "visible" }}>
          <defs>
            <linearGradient id="edgeGradCyan" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#06B6D4" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#F43F5E" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="edgeGradRed" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#F43F5E" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#10B981" stopOpacity="0.8" />
            </linearGradient>
            <filter id="glowFilter" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Directed Edges (Bezier curves) */}
          {edges.map((edge, i) => {
            const sourceNode = nodes.find((n) => n.id === edge.from);
            const targetNode = nodes.find((n) => n.id === edge.to);
            if (!sourceNode || !targetNode) return null;

            const x1 = sourceNode.x + 95;
            const y1 = sourceNode.y + 28;
            const x2 = targetNode.x - 95;
            const y2 = targetNode.y + 28;
            const dx = (x2 - x1) / 2;
            const pathD = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

            return (
              <g key={`edge-${i}`}>
                {/* Background edge glow */}
                <path
                  d={pathD}
                  fill="none"
                  stroke={sourceNode.color}
                  strokeWidth={2}
                  strokeOpacity={0.4}
                />
                {/* Active animated pulse line */}
                <path
                  d={pathD}
                  fill="none"
                  stroke={sourceNode.color}
                  strokeWidth={2.5}
                  strokeDasharray="6 6"
                >
                  <animate
                    attributeName="stroke-dashoffset"
                    values="24;0"
                    dur="1.8s"
                    repeatCount="indefinite"
                  />
                </path>
                {/* Flow particle */}
                <circle r={3.5} fill={sourceNode.color} filter="url(#glowFilter)">
                  <animateMotion
                    path={pathD}
                    dur={`${2.2 - edge.weight * 0.5}s`}
                    repeatCount="indefinite"
                    begin={`${i * 0.3}s`}
                  />
                </circle>
              </g>
            );
          })}

          {/* Graph Nodes */}
          {nodes.map((node) => {
            const isSelected = selectedNodeId === node.id;
            const width = 190;
            const height = 58;
            const rx = node.x - width / 2;
            const ry = node.y;

            return (
              <g
                key={node.id}
                onClick={() => setSelectedNodeId(node.id)}
                className="cursor-pointer transition-all hover:scale-105"
                style={{ transformOrigin: `${node.x}px ${node.y + 29}px` }}
              >
                {/* Node Box */}
                <rect
                  x={rx}
                  y={ry}
                  width={width}
                  height={height}
                  rx={10}
                  fill="#0B1120"
                  stroke={node.color}
                  strokeWidth={isSelected ? 2.5 : 1.2}
                  style={{
                    filter: isSelected ? `drop-shadow(0 0 12px ${node.glow})` : `drop-shadow(0 2px 6px rgba(0,0,0,0.6))`,
                  }}
                />

                {/* Left color bar */}
                <rect
                  x={rx}
                  y={ry}
                  width={4}
                  height={height}
                  rx={2}
                  fill={node.color}
                />

                {/* Badge (top right) */}
                <rect
                  x={rx + width - 68}
                  y={ry + 6}
                  width={62}
                  height={15}
                  rx={4}
                  fill={`${node.color}22`}
                  stroke={`${node.color}55`}
                  strokeWidth={0.8}
                />
                <text
                  x={rx + width - 37}
                  y={ry + 17}
                  textAnchor="middle"
                  fill={node.color}
                  fontSize="8.5"
                  fontFamily="monospace"
                  fontWeight="bold"
                >
                  {node.badge}
                </text>

                {/* Metric text (top left) */}
                {node.metric && (
                  <text
                    x={rx + 12}
                    y={ry + 18}
                    fill="#94A3B8"
                    fontSize="9.5"
                    fontFamily="monospace"
                    fontWeight="600"
                  >
                    {node.metric}
                  </text>
                )}

                {/* Main Node Name */}
                <text
                  x={rx + 12}
                  y={ry + 38}
                  fill="#F8FAFC"
                  fontSize="11"
                  fontWeight="bold"
                  fontFamily="sans-serif"
                >
                  {node.name.length > 24 ? node.name.slice(0, 22) + "..." : node.name}
                </text>

                {/* Subtitle tag */}
                <text
                  x={rx + 12}
                  y={ry + 50}
                  fill="#64748B"
                  fontSize="8"
                  fontFamily="monospace"
                >
                  {node.category.toUpperCase()}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Selected Node Deep-Dive Card */}
      <AnimatePresence mode="wait">
        {selectedNode && (
          <motion.div
            key={selectedNode.id}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 rounded-xl border p-4 bg-slate-900/90"
            style={{ borderColor: selectedNode.color }}
          >
            <div className="flex items-start gap-3">
              <div
                className="rounded-lg p-2.5 mt-0.5 shrink-0"
                style={{ backgroundColor: `${selectedNode.color}20`, color: selectedNode.color }}
              >
                {selectedNode.category === "precursor" && <Fingerprint size={18} />}
                {selectedNode.category === "stage" && <Activity size={18} />}
                {selectedNode.category === "technique" && <FileCode size={18} />}
                {selectedNode.category === "mitigation" && <ShieldCheck size={18} />}
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs font-bold px-2 py-0.5 rounded" style={{ backgroundColor: `${selectedNode.color}25`, color: selectedNode.color }}>
                    {selectedNode.badge}
                  </span>
                  <h4 className="text-sm font-bold text-white">{selectedNode.name}</h4>
                  {selectedNode.metric && (
                    <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                      {selectedNode.metric}
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-300 mt-1.5 leading-relaxed max-w-3xl">
                  {selectedNode.description}
                </p>
              </div>
            </div>

            <div className="shrink-0 flex items-center gap-2 text-xs font-mono text-cyan-400 bg-cyan-500/10 px-3 py-1.5 rounded-lg border border-cyan-500/30 self-stretch sm:self-auto justify-center">
              <Zap size={13} />
              <span>Axiom Verified</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
