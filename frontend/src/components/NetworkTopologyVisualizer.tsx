import { useState } from "react";
import { Server, Radio, ShieldCheck } from "lucide-react";

interface NetworkTopologyVisualizerProps {
  attackerIp?: string;
  targetIp?: string;
  scenarioName?: string;
  threatProbability?: number;
  mitigationAction?: string;
}

interface Node {
  id: string;
  label: string;
  ip: string;
  type: "attacker" | "perimeter" | "switch" | "workstation" | "scada";
  x: number;
  y: number;
  status: "active" | "compromised" | "targeted" | "isolated" | "secure";
}

export function NetworkTopologyVisualizer({
  attackerIp = "172.16.0.1",
  targetIp = "192.168.10.50",
  scenarioName = "Ares Botnet / Infiltration",
  threatProbability = 0.88,
  mitigationAction = "RESET_CONNECTIONS",
}: NetworkTopologyVisualizerProps) {
  const [selectedNode, setSelectedNode] = useState<string | null>("target");

  const isIsolated = mitigationAction === "ISOLATE_HOST" || mitigationAction === "BLOCK_PORT";
  const isCritical = threatProbability >= 0.75;

  const nodes: Node[] = [
    {
      id: "attacker",
      label: "Adversary (WAN C2)",
      ip: attackerIp,
      type: "attacker",
      x: 60,
      y: 110,
      status: isIsolated ? "isolated" : "active",
    },
    {
      id: "perimeter",
      label: "Sovereign Border Firewall",
      ip: "10.0.0.1",
      type: "perimeter",
      x: 180,
      y: 110,
      status: isIsolated ? "secure" : "active",
    },
    {
      id: "switch",
      label: "Enterprise Core Switch (L3)",
      ip: "192.168.10.1",
      type: "switch",
      x: 310,
      y: 110,
      status: isIsolated ? "secure" : isCritical ? "compromised" : "active",
    },
    {
      id: "workstation",
      label: "Pivot Workstation",
      ip: "192.168.10.15",
      type: "workstation",
      x: 440,
      y: 55,
      status: isIsolated ? "isolated" : isCritical ? "compromised" : "secure",
    },
    {
      id: "target",
      label: "Target CII SCADA Asset",
      ip: targetIp,
      type: "scada",
      x: 440,
      y: 165,
      status: isIsolated ? "secure" : isCritical ? "targeted" : "secure",
    },
  ];

  return (
    <div className="flex flex-col gap-4 rounded-xl border p-5 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-3" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex items-center gap-2">
          <Radio size={16} className="text-[var(--color-accent)] animate-pulse" />
          <div>
            <h3 className="font-semibold text-xs tracking-wider uppercase text-[var(--color-text-primary)]">
              LIVE SUBNET LATERAL TRAVERSAL TOPOLOGY (WORLD MODEL ATTACK PATH)
            </h3>
            <div className="font-mono text-[10px] text-[var(--color-text-muted)]">
              Scenario: <span className="text-[var(--color-accent)]">{scenarioName}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-mono text-[10px] font-bold border ${
            isIsolated
              ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
              : isCritical
              ? "bg-rose-500/20 text-rose-300 border-rose-500/30"
              : "bg-cyan-500/20 text-cyan-300 border-cyan-500/30"
          }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${isIsolated ? "bg-emerald-400" : isCritical ? "bg-rose-400 animate-ping" : "bg-cyan-400"}`}></span>
            {isIsolated ? "ACTIVE MITIGATION: QUARANTINED" : isCritical ? "IMMINENT INFILTRATION DETECTED" : "NORMAL TELEMETRY DYNAMICS"}
          </span>
        </div>
      </div>

      {/* SVG Topology Canvas */}
      <div className="relative w-full h-56 rounded-lg border bg-[var(--color-base)] overflow-hidden" style={{ borderColor: "var(--color-border)" }}>
        <svg viewBox="0 0 540 220" className="w-full h-full">
          {/* Subtle Grid Background */}
          <defs>
            <pattern id="topo-grid" width="20" height="20" patternUnits="userSpaceOnUse">
              <path d="M 20 0 L 0 0 0 20" fill="none" stroke="color-mix(in srgb, var(--color-text-primary) 3%, transparent)" strokeWidth="1" />
            </pattern>
            {/* Animated Gradient Beam */}
            <linearGradient id="attackBeam" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="var(--color-critical)" stopOpacity="0.8" />
              <stop offset="100%" stopColor="var(--color-accent)" stopOpacity="0.8" />
            </linearGradient>
          </defs>
          <rect width="540" height="220" fill="url(#topo-grid)" />

          {/* Connection Lines (Network Links) */}
          {/* 1. Attacker to Perimeter */}
          <line
            x1="60"
            y1="110"
            x2="180"
            y2="110"
            stroke={isIsolated ? "var(--color-normal)" : isCritical ? "var(--color-critical)" : "var(--color-accent)"}
            strokeWidth={isCritical && !isIsolated ? "3" : "1.5"}
            strokeDasharray={isIsolated ? "4,4" : isCritical ? "none" : "3,3"}
          />

          {/* 2. Perimeter to Core Switch */}
          <line
            x1="180"
            y1="110"
            x2="310"
            y2="110"
            stroke={isIsolated ? "var(--color-normal)" : isCritical ? "var(--color-critical)" : "var(--color-accent)"}
            strokeWidth={isCritical && !isIsolated ? "3" : "1.5"}
          />

          {/* 3. Core Switch to Pivot Workstation */}
          <line
            x1="310"
            y1="110"
            x2="440"
            y2="55"
            stroke={isIsolated ? "var(--color-text-secondary)" : isCritical ? "var(--color-elevated)" : "var(--color-text-secondary)"}
            strokeWidth="1.5"
            strokeDasharray="2,2"
          />

          {/* 4. Core Switch to Target SCADA Asset */}
          <line
            x1="310"
            y1="110"
            x2="440"
            y2="165"
            stroke={isIsolated ? "var(--color-normal)" : isCritical ? "var(--color-critical)" : "var(--color-accent)"}
            strokeWidth={isCritical && !isIsolated ? "3" : "1.5"}
          />

          {/* Active Attack Propagation Pulse */}
          {isCritical && !isIsolated && (
            <>
              <circle cx="120" cy="110" r="3.5" fill="var(--color-critical)">
                <animate attributeName="cx" from="60" to="180" dur="1.2s" repeatCount="indefinite" />
              </circle>
              <circle cx="245" cy="110" r="3.5" fill="var(--color-critical)">
                <animate attributeName="cx" from="180" to="310" dur="1.2s" repeatCount="indefinite" />
              </circle>
              <circle cx="375" cy="137" r="3.5" fill="var(--color-critical)">
                <animate attributeName="cx" from="310" to="440" dur="1.2s" repeatCount="indefinite" />
                <animate attributeName="cy" from="110" to="165" dur="1.2s" repeatCount="indefinite" />
              </circle>
            </>
          )}

          {/* Render Nodes */}
          {nodes.map((node) => {
            const isSelected = selectedNode === node.id;
            let strokeColor = "var(--color-border)";
            let fillColor = "var(--color-panel)";

            if (node.type === "attacker") {
              strokeColor = isIsolated ? "var(--color-normal)" : "var(--color-critical)";
              fillColor = isIsolated ? "color-mix(in srgb, var(--color-normal) 15%, transparent)" : "color-mix(in srgb, var(--color-critical) 20%, transparent)";
            } else if (node.type === "scada") {
              strokeColor = isCritical && !isIsolated ? "var(--color-critical)" : "var(--color-accent)";
              fillColor = isCritical && !isIsolated ? "color-mix(in srgb, var(--color-critical) 20%, transparent)" : "color-mix(in srgb, var(--color-accent) 15%, transparent)";
            } else if (node.type === "perimeter") {
              strokeColor = "var(--color-accent-secondary)";
              fillColor = "color-mix(in srgb, var(--color-accent-secondary) 15%, transparent)";
            } else if (node.type === "switch") {
              strokeColor = "var(--color-mitre-recon)";
              fillColor = "color-mix(in srgb, var(--color-mitre-recon) 15%, transparent)";
            }

            return (
              <g
                key={node.id}
                onClick={() => setSelectedNode(node.id)}
                className="cursor-pointer transition-transform hover:scale-105"
              >
                {/* Outer Glow Halo if targeted or attacker */}
                {(node.type === "attacker" || (node.type === "scada" && isCritical)) && !isIsolated && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={isSelected ? 24 : 20}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth="1.5"
                    opacity="0.4"
                    className="animate-ping"
                  />
                )}

                {/* Main Node Circle */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={isSelected ? 18 : 15}
                  fill={fillColor}
                  stroke={strokeColor}
                  strokeWidth={isSelected ? 2.5 : 1.5}
                />

                {/* Node Icon Indicator */}
                {node.type === "attacker" && (
                  <text x={node.x} y={node.y + 4} textAnchor="middle" fontSize="10" fill={strokeColor} fontWeight="bold">
                    ⚔
                  </text>
                )}
                {node.type === "perimeter" && (
                  <text x={node.x} y={node.y + 4} textAnchor="middle" fontSize="10" fill={strokeColor} fontWeight="bold">
                    🛡
                  </text>
                )}
                {node.type === "switch" && (
                  <text x={node.x} y={node.y + 4} textAnchor="middle" fontSize="10" fill={strokeColor} fontWeight="bold">
                    ☵
                  </text>
                )}
                {node.type === "workstation" && (
                  <text x={node.x} y={node.y + 4} textAnchor="middle" fontSize="10" fill="var(--color-text-secondary)" fontWeight="bold">
                    💻
                  </text>
                )}
                {node.type === "scada" && (
                  <text x={node.x} y={node.y + 4} textAnchor="middle" fontSize="10" fill={strokeColor} fontWeight="bold">
                    ⚡
                  </text>
                )}

                {/* Node Labels */}
                <text
                  x={node.x}
                  y={node.y + 30}
                  textAnchor="middle"
                  fontSize="9"
                  fill="var(--color-text-primary)"
                  fontWeight="600"
                >
                  {node.label}
                </text>
                <text
                  x={node.x}
                  y={node.y + 42}
                  textAnchor="middle"
                  fontSize="8"
                  fill="var(--color-text-muted)"
                  fontFamily="monospace"
                >
                  {node.ip}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Legend Overlay */}
        <div className="absolute bottom-2 left-3 flex flex-wrap items-center gap-3 font-mono text-[9px] text-[var(--color-text-muted)] bg-black/60 px-2 py-1 rounded border border-white/5">
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-rose-500"></span> Adversary Flow
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-blue-500"></span> Perimeter Guard
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-cyan-400"></span> CII Target Asset
          </span>
          {isIsolated && (
            <span className="flex items-center gap-1 text-emerald-400 font-bold">
              <ShieldCheck size={10} /> Quarantined via {mitigationAction}
            </span>
          )}
        </div>
      </div>

      {/* Node Detail Callout */}
      {selectedNode && (
        <div className="rounded-lg border p-3 font-mono text-xs bg-[var(--color-panel-raised)] flex flex-wrap items-center justify-between gap-3" style={{ borderColor: "var(--color-border)" }}>
          <div className="flex items-center gap-2">
            <Server size={14} className="text-[var(--color-accent)]" />
            <span className="text-[var(--color-text-secondary)]">Inspecting Node:</span>
            <strong className="text-[var(--color-text-primary)]">
              {nodes.find((n) => n.id === selectedNode)?.label} ({nodes.find((n) => n.id === selectedNode)?.ip})
            </strong>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[var(--color-text-muted)] text-[11px]">Subnet Policy:</span>
            <span className="text-emerald-400 font-semibold">
              {isIsolated ? "ISOLATION RULE ENFORCED" : "DEEP PACKET INSPECTION ACTIVE"}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
