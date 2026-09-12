import { Zap, FileText, ShieldCheck } from "lucide-react";
import type { MitigationResponse } from "../data/api";

interface DefenseSandboxPanelProps {
  mitigationData: MitigationResponse | null;
  selectedAction: string;
  onSelectAction: (actionName: string) => void;
  onOpenDossier: () => void;
  scenarioName?: string;
  hostIp?: string;
  targetIp?: string;
  baselineRisk?: number;
}

interface ActionProfile {
  name: string;
  label: string;
  riskReduction: number;
  residualRisk: number;
  cost: number;
  trajectory: number[];
  commandPreview: string;
  explanation: string;
}

const ACTION_PROFILES: Record<string, ActionProfile> = {
  ISOLATE_HOST: {
    name: "ISOLATE_HOST",
    label: "Quarantine Host (VLAN Isolation)",
    riskReduction: 0.94,
    residualRisk: 0.03,
    cost: 0.40,
    trajectory: [0.88, 0.45, 0.12, 0.05, 0.03],
    commandPreview: "iptables -I FORWARD -s {HOST_IP} -j DROP && netsh advfirewall set allprofiles state on",
    explanation: "Sever all Layer 3 routing for adversary host. Completely halts lateral movement and C2 beaconing within 500ms."
  },
  BLOCK_PORT: {
    name: "BLOCK_PORT",
    label: "Block Targeted Port (ACL Severance)",
    riskReduction: 0.85,
    residualRisk: 0.09,
    cost: 0.20,
    trajectory: [0.88, 0.58, 0.28, 0.14, 0.09],
    commandPreview: "iptables -A INPUT -p tcp --dport {PORT} -j REJECT --reject-with tcp-reset",
    explanation: "Drops incoming packets on targeted destination port. Nullifies service exploitation while preserving other host traffic."
  },
  RATE_LIMIT: {
    name: "RATE_LIMIT",
    label: "Dynamic Token Bucket Rate Limiting",
    riskReduction: 0.68,
    residualRisk: 0.22,
    cost: 0.15,
    trajectory: [0.88, 0.72, 0.50, 0.32, 0.22],
    commandPreview: "tc qdisc add dev eth0 root tbf rate 256kbit latency 50ms burst 1540",
    explanation: "Clamps bandwidth and packet velocity. Effective for volumetric DDoS (Hulk/LOIC) and aggressive port-scanning."
  },
  RESET_CONNECTIONS: {
    name: "RESET_CONNECTIONS",
    label: "TCP RST Packet Injection",
    riskReduction: 0.74,
    residualRisk: 0.18,
    cost: 0.10,
    trajectory: [0.88, 0.62, 0.38, 0.24, 0.18],
    commandPreview: "tcpkill -i eth0 host {HOST_IP} and port {PORT}",
    explanation: "Injects synthetic TCP RST flags to tear down active 3-way handshakes and interrupt unauthorized data exfiltration."
  },
  MONITOR_ONLY: {
    name: "MONITOR_ONLY",
    label: "Passive Sovereign Observation",
    riskReduction: 0.00,
    residualRisk: 0.99,
    cost: 0.00,
    trajectory: [0.88, 0.92, 0.96, 0.98, 0.99],
    commandPreview: "# Zero active intervention - Threat telemetry stream only",
    explanation: "Passive monitoring. Warning: Unmitigated trajectory projects full system compromise (MITRE T1048 Exfiltration) within K=5."
  }
};

export function DefenseSandboxPanel({
  mitigationData,
  selectedAction,
  onSelectAction,
  onOpenDossier,
  hostIp = "172.16.0.1",
  targetIp = "192.168.10.50",
  baselineRisk = 0.94,
}: DefenseSandboxPanelProps) {
  const currentProfile = ACTION_PROFILES[selectedAction] || ACTION_PROFILES.RESET_CONNECTIONS;

  // Dynamically calculate unmitigated risk and policy residual risk based on actual scenario probability
  const unmitigatedRisk = baselineRisk > 0 ? baselineRisk : 0.94;
  const isBenign = unmitigatedRisk < 0.15;
  const dynamicDropPct = isBenign
    ? 0
    : selectedAction === "MONITOR_ONLY"
    ? 0
    : Math.round(currentProfile.riskReduction * 100);

  const dynamicResidual = isBenign
    ? unmitigatedRisk
    : selectedAction === "MONITOR_ONLY"
    ? Math.min(0.999, +(unmitigatedRisk * 1.05).toFixed(3))
    : Math.max(0.012, +(unmitigatedRisk * (1 - currentProfile.riskReduction)).toFixed(3));

  // Dynamic curves:
  // Unmitigated curve: escalates or stays steady
  const unmitPoints = [
    unmitigatedRisk,
    Math.min(0.999, +(unmitigatedRisk + (isBenign ? 0.005 : 0.03)).toFixed(3)),
    Math.min(0.999, +(unmitigatedRisk + (isBenign ? 0.008 : 0.05)).toFixed(3)),
    Math.min(0.999, +(unmitigatedRisk + (isBenign ? 0.010 : 0.07)).toFixed(3)),
    Math.min(0.999, +(unmitigatedRisk + (isBenign ? 0.012 : 0.09)).toFixed(3)),
  ];

  // Mitigated curve: drops steeply towards dynamicResidual
  const mitPoints = [
    unmitigatedRisk,
    Math.max(dynamicResidual, +(unmitigatedRisk * 0.55).toFixed(3)),
    Math.max(dynamicResidual, +(unmitigatedRisk * 0.28).toFixed(3)),
    Math.max(dynamicResidual, +(unmitigatedRisk * 0.14).toFixed(3)),
    dynamicResidual,
  ];

  return (
    <div className="flex flex-col gap-5 rounded-xl border p-5 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-3" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex items-center gap-2">
          <Zap size={18} className="text-[var(--color-accent)] animate-pulse" />
          <h3 className="font-semibold text-sm tracking-wide text-[var(--color-text-primary)]">
            INTERACTIVE "WHAT-IF" DEFENSE POLICY SANDBOX (LATENT COUNTERFACTUAL SIMULATION)
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onOpenDossier}
            className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold text-white transition-all hover:scale-105 shadow-md"
            style={{ backgroundColor: "var(--color-accent)" }}
          >
            <FileText size={14} />
            <span>Generate Sovereign Incident Dossier</span>
          </button>
        </div>
      </div>

      {/* Main Sandbox Grid */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Left 7 Cols: Interactive Action Selector */}
        <div className="flex flex-col gap-3 lg:col-span-7">
          <div className="flex items-center justify-between font-mono text-xs text-[var(--color-text-secondary)]">
            <span>CHOOSE DEFENSIVE INTERVENTION:</span>
            <span className="text-[var(--color-accent)]">Live Trajectory Simulation</span>
          </div>

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {Object.values(ACTION_PROFILES).map((prof) => {
              const isSelected = prof.name === selectedAction;
              const isOptimal = prof.name === (mitigationData?.safety_shield_recommendation || "ISOLATE_HOST");

              return (
                <button
                  key={prof.name}
                  onClick={() => onSelectAction(prof.name)}
                  className={`flex flex-col text-left rounded-lg p-3 border transition-all duration-200 ${
                    isSelected
                      ? "ring-2 ring-[var(--color-accent)] shadow-lg"
                      : "hover:border-[var(--color-accent)]"
                  }`}
                  style={{
                    backgroundColor: isSelected ? "color-mix(in srgb, var(--color-accent) 12%, transparent)" : "color-mix(in srgb, var(--color-base) 50%, transparent)",
                    borderColor: isSelected ? "var(--color-accent)" : "var(--color-border)",
                  }}
                >
                  <div className="flex items-center justify-between w-full mb-1">
                    <span className="font-bold text-xs text-[var(--color-text-primary)]">
                      {prof.label.split(" (")[0]}
                    </span>
                    {isOptimal && !isBenign && (
                      <span className="rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        RECOMMENDED
                      </span>
                    )}
                    {prof.name === "MONITOR_ONLY" && (
                      <span className="rounded px-1.5 py-0.5 text-[10px] font-mono font-medium bg-rose-500/20 text-rose-400 border border-rose-500/30">
                        NO DEFENSE
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-[var(--color-text-secondary)] line-clamp-2 mb-2 leading-relaxed">
                    {prof.explanation}
                  </p>
                  <div className="mt-auto flex items-center justify-between font-mono text-[10px] pt-1.5 border-t border-white/5">
                    <span className="text-[var(--color-text-muted)]">
                      Cost: {(prof.cost * 100).toFixed(0)}%
                    </span>
                    <span className={prof.riskReduction > 0.6 ? "text-emerald-400 font-bold" : prof.riskReduction > 0 ? "text-amber-400 font-bold" : "text-rose-400 font-bold"}>
                      {prof.riskReduction > 0 && !isBenign ? `-${Math.round(prof.riskReduction * 100)}% Risk` : isBenign ? "Nominal Safe" : "+0% (Adversary Wins)"}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Generated Autonomous Firewall Rule Preview */}
          <div className="mt-2 rounded-lg border p-3 font-mono text-xs bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
            <div className="flex items-center justify-between text-[10px] text-[var(--color-text-muted)] mb-1">
              <span>AUTONOMOUS FIREWALL RULE SYNTHESIZER:</span>
              <span className="text-emerald-400">READY FOR 1-CLICK DISPATCH</span>
            </div>
            <code className="block text-[var(--color-accent)] font-semibold truncate">
              {currentProfile.commandPreview.replace("{HOST_IP}", hostIp).replace("{TARGET_IP}", targetIp).replace("{PORT}", "8080/22")}
            </code>
          </div>
        </div>

        {/* Right 5 Cols: Real-Time Dual Trajectory Simulation Graph */}
        <div className="flex flex-col rounded-lg p-4 border lg:col-span-5 bg-[var(--color-panel-raised)]" style={{ borderColor: "var(--color-border)" }}>
          <div className="flex items-center justify-between font-mono text-xs text-[var(--color-text-secondary)] mb-2">
            <div className="flex items-center gap-1.5">
              <ShieldCheck size={14} className="text-emerald-400" />
              <span>COUNTERFACTUAL HORIZON</span>
            </div>
            <span className="text-[10px] uppercase text-emerald-400 font-bold font-mono">
              {dynamicDropPct > 0 ? `-${dynamicDropPct}% DROP` : isBenign ? "BASELINE STABLE" : "NO MITIGATION"}
            </span>
          </div>

          {/* SVG Dual-Curve Graph: Red (Do Nothing) vs Cyan/Green (After Mitigation) */}
          <div className="relative h-44 w-full rounded-lg border p-3 bg-[var(--color-base)] flex flex-col justify-between" style={{ borderColor: "var(--color-border)" }}>
            <div className="flex items-center justify-between text-[10px] font-mono">
              <span className="text-rose-400 flex items-center gap-1">
                <span className="inline-block w-2.5 h-0.5 bg-rose-500"></span> Unmitigated ({(unmitPoints[4] * 100).toFixed(1)}%)
              </span>
              <span className="text-emerald-400 flex items-center gap-1">
                <span className="inline-block w-2.5 h-0.5 bg-emerald-400"></span> {selectedAction.replace("_", " ")} ({(mitPoints[4] * 100).toFixed(1)}%)
              </span>
            </div>

            {/* SVG Plot */}
            <svg viewBox="0 0 300 100" className="w-full h-28 overflow-visible">
              {/* Grid Lines */}
              <line x1="0" y1="20" x2="300" y2="20" stroke="color-mix(in srgb, var(--color-text-primary) 6%, transparent)" strokeDasharray="3,3" />
              <line x1="0" y1="50" x2="300" y2="50" stroke="color-mix(in srgb, var(--color-text-primary) 6%, transparent)" strokeDasharray="3,3" />
              <line x1="0" y1="80" x2="300" y2="80" stroke="color-mix(in srgb, var(--color-text-primary) 6%, transparent)" strokeDasharray="3,3" />

              {/* Dynamic Red Unmitigated Line */}
              {(() => {
                const pts = unmitPoints
                  .map((val, idx) => {
                    const x = 10 + idx * 70;
                    const y = Math.max(5, Math.min(95, 95 - val * 85));
                    return `${x},${y}`;
                  })
                  .join(" ");
                const finalY = Math.max(5, Math.min(95, 95 - unmitPoints[4] * 85));
                return (
                  <>
                    <polyline
                      fill="none"
                      stroke="var(--color-critical)"
                      strokeWidth="2.5"
                      strokeDasharray="4,4"
                      points={pts}
                    />
                    <circle cx="290" cy={finalY} r="3.5" fill="var(--color-critical)" />
                  </>
                );
              })()}

              {/* Dynamic Green/Cyan Mitigated Line: Plummets based on selected action! */}
              {(() => {
                const pts = mitPoints
                  .map((val, idx) => {
                    const x = 10 + idx * 70;
                    const y = Math.max(5, Math.min(95, 95 - val * 85));
                    return `${x},${y}`;
                  })
                  .join(" ");

                const finalY = Math.max(5, Math.min(95, 95 - mitPoints[4] * 85));
                return (
                  <>
                    <polyline
                      fill="none"
                      stroke="var(--color-normal)"
                      strokeWidth="3"
                      points={pts}
                      className="transition-all duration-500 ease-out"
                    />
                    <circle cx="290" cy={finalY} r="4" fill="var(--color-normal)" className="animate-pulse" />
                  </>
                );
              })()}
            </svg>

            {/* Horizon Labels */}
            <div className="flex items-center justify-between text-[9px] font-mono text-[var(--color-text-muted)] border-t border-white/5 pt-1">
              <span>T (Now)</span>
              <span>T+1 (+10s)</span>
              <span>T+2 (+20s)</span>
              <span>T+3 (+30s)</span>
              <span>T+5 (+50s)</span>
            </div>
          </div>

          {/* Outcome Comparison Summary */}
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="rounded border p-2 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
              <div className="text-[10px] text-rose-400">UNMITIGATED RISK</div>
              <div className="mt-0.5 text-base font-bold text-rose-400">
                {(unmitigatedRisk * 100).toFixed(1)}% Risk
              </div>
              <div className="text-[10px] text-[var(--color-text-muted)]">
                {isBenign ? "Normal Stationary Flow" : "Projects Critical Impact"}
              </div>
            </div>
            <div className="rounded border p-2 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
              <div className="text-[10px] text-emerald-400">AFTER POLICY</div>
              <div className="mt-0.5 text-base font-bold text-emerald-400">
                {(dynamicResidual * 100).toFixed(1)}% Risk
              </div>
              <div className="text-[10px] text-emerald-400/80">
                {isBenign ? "Baseline Verified" : "Intervention Active"}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
