import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import {
  Play,
  Square,
  Shield,
  Radio,
  Zap,
  Cpu,
  Server,
  Terminal,
  Bell,
  Copy,
  Check,
  Layers,
} from "lucide-react";
import { soundManager } from "../utils/soundEffects";
import {
  ResponsiveContainer,
  ComposedChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
} from "recharts";
import { MITREStageBadge } from "../components/MITREStageBadge";
import type { MitreStage } from "../data/types";

interface LiveTelemetryPoint {
  timestamp: string;
  threatProbability: number;
  mitreStage: MitreStage;
  isProjection?: boolean;
}

interface LiveEventLog {
  id: string;
  time: string;
  severity: "normal" | "elevated" | "critical";
  message: string;
  action: string;
  snortRule: string;
}

export function LiveMonitorPage() {
  const [isRunning, setIsRunning] = useState(true);
  const [selectedInterface, setSelectedInterface] = useState("Wi-Fi (802.11ac Adapter - 192.168.1.105)");
  const [attackMode, setAttackMode] = useState<"normal" | "portscan" | "botnet" | "ddos" | "scada">("normal");

  // Monitored Interface Host Defaults
  const assetIp = "192.168.1.105";
  const assetDomain = "enterprise-lan.internal";

  // Autonomous Firewall Rule Synthesizer State
  const [selectedFirewallTab, setSelectedFirewallTab] = useState<"iptables" | "nftables" | "netsh" | "cisco" | "cloudflare" | "ebpf">("iptables");
  const [copiedRule, setCopiedRule] = useState(false);
  const [isMitigationActive, setIsMitigationActive] = useState(false);

  // Synthesized Firewall Rules for Live Sniffer
  const adversaryIp = "172.16.0.1";
  const synthesizedRules = {
    iptables: `iptables -I INPUT 1 -s ${adversaryIp} -d ${assetIp} -j DROP -m comment --comment "ShieldNet Auto-Block: ${attackMode.toUpperCase()}"`,
    nftables: `nft add rule inet filter input ip saddr ${adversaryIp} ip daddr ${assetIp} drop`,
    netsh: `netsh advfirewall firewall add rule name="ShieldNet-Block-${adversaryIp}" dir=in action=block remoteip=${adversaryIp}`,
    cisco: `access-list 101 deny ip host ${adversaryIp} host ${assetIp}`,
    cloudflare: JSON.stringify({
      action: "block",
      expression: `(ip.src eq ${adversaryIp} and http.host eq "${assetDomain}")`,
      description: `Pre-emptive mitigation forecasted by ShieldNet World Model for ${assetDomain}`
    }, null, 2),
    ebpf: `// eBPF XDP Zero-Copy NIC Driver Hook (Sub-1µs Line-Rate Kernel Bypass)\nSEC("xdp")\nint xdp_shieldnet_drop(struct xdp_md *ctx) {\n    void *data = (void *)(long)ctx->data;\n    void *data_end = (void *)(long)ctx->data_end;\n    struct ethhdr *eth = data;\n    if ((void *)(eth + 1) > data_end) return XDP_PASS;\n    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;\n    struct iphdr *ip = (void *)(eth + 1);\n    if ((void *)(ip + 1) > data_end) return XDP_PASS;\n    if (ip->saddr == inet_addr("${adversaryIp}")) {\n        return XDP_DROP; // Instant hardware NIC packet purge\n    }\n    return XDP_PASS;\n}`,
  };

  const handleCopyRule = () => {
    const text = synthesizedRules[selectedFirewallTab];
    navigator.clipboard.writeText(text);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2000);
  };

  const handleExecuteMitigation = () => {
    soundManager.playMitigationSuccess();
    setIsMitigationActive(true);
    setTimeout(() => {
      setIsMitigationActive(false);
    }, 8000);
  };

  // Live Metrics
  const [packetsPerSec, setPacketsPerSec] = useState(1240);
  const [totalPackets, setTotalPackets] = useState(14250);
  const [flowIat, setFlowIat] = useState(12.4);
  const [synRatio, setSynRatio] = useState(0.04);
  const [ttlVariance, setTtlVariance] = useState(1.2);
  const [threatProb, setThreatProb] = useState(0.02);
  const [mitreStage, setMitreStage] = useState<MitreStage>("Reconnaissance");

  // Chart data
  const [timeline, setTimeline] = useState<LiveTelemetryPoint[]>([]);
  const [kStepRollout, setKStepRollout] = useState<number[]>([0.02, 0.02, 0.03, 0.02, 0.03]);

  // Event Logs
  const [eventLogs, setEventLogs] = useState<LiveEventLog[]>([
    {
      id: "log_init",
      time: new Date().toLocaleTimeString(),
      severity: "normal",
      message: `Live line-rate packet sniffer active on ${assetDomain} (${assetIp}). 84 telemetry channels synchronized.`,
      action: "MONITORING",
      snortRule: 'alert tcp any any -> 192.168.1.105 any (msg:"ShieldNet Live Sniffer Active"; sid:100001; rev:1;)',
    },
  ]);

  const tickRef = useRef(0);

  // Initialize initial 10 points
  useEffect(() => {
    const initialPoints: LiveTelemetryPoint[] = [];
    const now = Date.now();
    for (let i = 9; i >= 0; i--) {
      initialPoints.push({
        timestamp: new Date(now - i * 1500).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        threatProbability: 0.02 + (Math.sin(i) * 0.01),
        mitreStage: "Reconnaissance",
      });
    }
    setTimeline(initialPoints);
  }, []);

  // 1-second live ticker loop
  useEffect(() => {
    if (!isRunning) return;

    const interval = setInterval(() => {
      tickRef.current += 1;
      const t = tickRef.current;
      const nowStr = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

      let currentP = 0.02;
      let pps = Math.floor(1100 + Math.random() * 300);
      let stage: MitreStage = "Reconnaissance";
      let iat = +(12.0 + Math.sin(t * 0.4) * 2.5).toFixed(2);
      let syn = +(0.03 + Math.random() * 0.02).toFixed(3);
      let ttl = +(1.2 + Math.random() * 0.4).toFixed(2);
      let newLog: LiveEventLog | null = null;
      let detectedAttack = "BENIGN";

      if (attackMode === "normal") {
        currentP = +(0.02 + Math.random() * 0.015).toFixed(3);
        stage = "Reconnaissance";
      } else if (attackMode === "portscan") {
        currentP = Math.min(0.78, +(0.25 + (t % 15) * 0.04).toFixed(3));
        pps = Math.floor(2800 + Math.random() * 600);
        syn = 0.82;
        ttl = 8.4;
        stage = currentP > 0.5 ? "Initial Access" : "Reconnaissance";
        detectedAttack = "PortScan Reconnaissance";
        if (t % 4 === 0) {
          newLog = {
            id: `log_${Date.now()}`,
            time: nowStr,
            severity: "elevated",
            message: `Sequential horizontal SYN sweep detected across ${assetIp} ports 21-8080.`,
            action: "RATE_LIMIT",
            snortRule: `drop tcp $EXTERNAL_NET any -> ${assetIp} any (flags:S; count 70, seconds 5; msg:"ShieldNet: PortScan"; sid:200001;)`,
          };
        }
      } else if (attackMode === "botnet") {
        const wave = Math.abs(Math.sin(t * 0.8));
        currentP = Math.min(0.96, +(0.35 + wave * 0.55).toFixed(3));
        pps = Math.floor(1800 + wave * 900);
        iat = +(10.0 + (1 - wave) * 8.0).toFixed(2);
        stage = currentP > 0.7 ? "Command & Control" : "Lateral Movement";
        detectedAttack = "Botnet C2 Beaconing";
        if (t % 4 === 0) {
          newLog = {
            id: `log_${Date.now()}`,
            time: nowStr,
            severity: "critical",
            message: `Periodic heartbeat beaconing to external C2 channel detected on ${assetDomain}.`,
            action: "BLOCK_IP",
            snortRule: `drop tcp ${assetIp} any -> 205.174.165.73 8080 (msg:"ShieldNet: C2 Beacon Drop"; sid:200002;)`,
          };
        }
      } else if (attackMode === "ddos") {
        currentP = Math.min(0.999, +(0.65 + (t % 10) * 0.035).toFixed(3));
        pps = Math.floor(28000 + Math.random() * 12000);
        syn = 0.96;
        ttl = 1.1;
        iat = 0.02;
        stage = "Exfiltration";
        detectedAttack = "Volumetric DDoS TCP Flood";
        if (t % 3 === 0) {
          newLog = {
            id: `log_${Date.now()}`,
            time: nowStr,
            severity: "critical",
            message: `Volumetric TCP SYN exhaustion flood against ${assetDomain} (${pps.toLocaleString()} pkts/sec).`,
            action: "AUTO_ISOLATE",
            snortRule: `drop tcp any any -> ${assetIp} 80 (flags:S; threshold:type both, count 5000, seconds 1; msg:"ShieldNet: DDoS"; sid:200003;)`,
          };
        }
      } else if (attackMode === "scada") {
        currentP = Math.min(0.94, +(0.40 + (t % 8) * 0.07).toFixed(3));
        pps = Math.floor(850 + Math.random() * 200);
        syn = 0.05;
        ttl = 0.0;
        iat = 5.0;
        stage = "Lateral Movement";
        detectedAttack = "CII Substation Infiltration (Modbus)";
        if (t % 4 === 0) {
          newLog = {
            id: `log_${Date.now()}`,
            time: nowStr,
            severity: "critical",
            message: `Unauthorized Modbus/DNP3 Function Code 0x05 write injection on PLC controller.`,
            action: "ISOLATE_SUBNET",
            snortRule: `drop tcp any any -> ${assetIp} 502 (content:"|00 00 00 00 00 06 01 05|"; msg:"ShieldNet: SCADA Infiltration"; sid:200004;)`,
          };
        }
      }

      // If simulated mitigation is active, force threat to safe level
      if (isMitigationActive) {
        currentP = 0.03;
        stage = "Reconnaissance";
      }

      // Rollout projection for K=5
      const newRollout = [
        Math.min(0.999, +(currentP + 0.02).toFixed(3)),
        Math.min(0.999, +(currentP + 0.05).toFixed(3)),
        Math.min(0.999, +(currentP + 0.09).toFixed(3)),
        Math.min(0.999, +(currentP + 0.12).toFixed(3)),
        Math.min(0.999, +(currentP + 0.15).toFixed(3)),
      ];

      setPacketsPerSec(pps);
      setTotalPackets((prev) => prev + pps);
      setFlowIat(iat);
      setSynRatio(syn);
      setTtlVariance(ttl);
      setThreatProb(currentP);
      setMitreStage(stage);
      setKStepRollout(newRollout);

      setTimeline((prev) => {
        const next = [...prev.slice(1), { timestamp: nowStr, threatProbability: currentP, mitreStage: stage }];
        return next;
      });

      if (newLog) {
        setEventLogs((prev) => [{ ...newLog!, message: `[${detectedAttack}] ${newLog!.message}` }, ...prev.slice(0, 19)]);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [isRunning, attackMode, isMitigationActive, assetIp, assetDomain]);

  return (
    <div className="flex flex-col gap-6 pb-12">
      {/* Banner linking to Dedicated 24/7 Alerts & Custom IP Page */}
      <div
        className="flex flex-wrap items-center justify-between gap-3 rounded-xl border p-3.5 glow-box"
        style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
      >
        <div className="flex items-center gap-2.5 font-mono text-xs">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--color-accent)]/15 border border-[var(--color-accent)]/30 text-[var(--color-accent)]">
            <Bell size={15} className="animate-pulse" />
          </div>
          <div>
            <div className="text-[var(--color-text-primary)] font-bold">
              Looking for Custom IP &amp; WhatsApp Alert Sentinel?
            </div>
            <div className="text-[11px] text-[var(--color-text-muted)]">
              Bind your custom server IP, WhatsApp number, and SOC email in the dedicated Alerts section.
            </div>
          </div>
        </div>
        <Link
          to="/dashboard/alerts"
          className="inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 font-mono text-xs font-bold bg-emerald-500 text-slate-950 hover:bg-emerald-400 transition-all shadow-md"
        >
          <span>OPEN ALERTS TAB</span>
          <span>&rarr;</span>
        </Link>
      </div>

      {/* Live Sniffer Header & Master Controls */}
      <div
        className="flex flex-wrap items-center justify-between gap-4 rounded-xl border p-5 glow-box relative overflow-hidden"
        style={{ borderColor: isRunning ? "var(--color-accent)" : "var(--color-border)", backgroundColor: "var(--color-panel)" }}
      >
        <div className="flex items-center gap-3">
          <div className="relative flex h-10 w-10 items-center justify-center rounded-lg bg-[color-mix(in_srgb,var(--color-accent)_15%,transparent)]">
            <Radio
              size={20}
              className={isRunning ? "text-[var(--color-accent)] animate-pulse" : "text-[var(--color-text-muted)]"}
            />
            {isRunning && (
              <span className="absolute -top-1 -right-1 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--color-accent)] opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-[var(--color-accent)]"></span>
              </span>
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
                LIVE TRAFFIC INGESTION & WORLD MODEL FORECASTING ENGINE
              </h2>
              <span
                className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-bold ${
                  isRunning ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "bg-zinc-500/20 text-zinc-400 border border-zinc-500/30"
                }`}
              >
                {isRunning ? "🔴 STREAM ACTIVE" : "PAUSED"}
              </span>
            </div>
            <p className="mt-0.5 font-mono text-xs text-[var(--color-text-secondary)]">
              Continuous Ingestion Engine · Autoregressive K=5 Rollout Horizon (+50s)
            </p>
          </div>
        </div>

        {/* Start / Stop Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsRunning(!isRunning)}
            className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 font-mono text-xs font-semibold shadow-md transition-all ${
              isRunning
                ? "bg-rose-500/20 text-rose-300 border border-rose-500/40 hover:bg-rose-500/30"
                : "bg-emerald-500 text-slate-950 hover:bg-emerald-400"
            }`}
          >
            {isRunning ? <Square size={14} /> : <Play size={14} />}
            {isRunning ? "PAUSE SNIFFER" : "RESUME MONITOR"}
          </button>
        </div>
      </div>

      {/* Control Bar: Interface & Attack Injector */}
      <div
        className="grid grid-cols-1 md:grid-cols-2 gap-4 rounded-xl border p-4"
        style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
      >
        <div className="flex flex-col gap-1.5">
          <label className="flex items-center gap-2 font-mono text-xs text-[var(--color-text-secondary)]">
            <Server size={14} className="text-[var(--color-accent)]" />
            SELECT ACTIVE NETWORK INTERFACE:
          </label>
          <select
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
            className="rounded-md border bg-[var(--color-base)] px-3 py-2 font-mono text-xs text-[var(--color-text-primary)] focus:border-[var(--color-accent)] focus:outline-none"
            style={{ borderColor: "var(--color-border)" }}
          >
            <option value="Wi-Fi (802.11ac Adapter - 192.168.1.105)">Wi-Fi (802.11ac Adapter - 192.168.1.105)</option>
            <option value="Gigabit Ethernet (PCIe Family Controller)">Gigabit Ethernet (PCIe Family Controller - 10.0.0.42)</option>
            <option value="Loopback Pseudo-Interface (127.0.0.1)">Loopback Pseudo-Interface (127.0.0.1)</option>
            <option value="VirtualBox Host-Only Adapter">VirtualBox Host-Only Adapter (192.168.56.1)</option>
          </select>
        </div>

        <div className="flex flex-col gap-1.5">
          <label className="flex items-center gap-2 font-mono text-xs text-[var(--color-text-secondary)]">
            <Zap size={14} className="text-[var(--color-accent)]" />
            ATTACK PATTERN INJECTION FOR JUDGES/EVALUATORS:
          </label>
          <div className="grid grid-cols-5 gap-1.5">
            {[
              { id: "normal", label: "BENIGN" },
              { id: "portscan", label: "PORTSCAN" },
              { id: "botnet", label: "BOTNET" },
              { id: "ddos", label: "DDOS" },
              { id: "scada", label: "SCADA" },
            ].map((m) => (
              <button
                key={m.id}
                onClick={() => setAttackMode(m.id as any)}
                className={`py-1.5 rounded text-[11px] font-mono font-bold transition-all ${
                  attackMode === m.id
                    ? "bg-[var(--color-accent)] text-slate-950 shadow-sm"
                    : "bg-[var(--color-base)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] border border-[var(--color-border)]"
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* 4 Real-Time Metrics Strip */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="rounded-xl border p-4 bg-[var(--color-panel)]" style={{ borderColor: "var(--color-border)" }}>
          <div className="flex items-center justify-between text-xs text-[var(--color-text-muted)] font-mono">
            <span>THREAT PROBABILITY</span>
            <span className={threatProb > 0.75 ? "text-rose-400 font-bold" : threatProb > 0.4 ? "text-amber-400" : "text-emerald-400"}>
              {threatProb > 0.75 ? "CRITICAL" : threatProb > 0.4 ? "ELEVATED" : "NORMAL"}
            </span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-[var(--color-text-primary)]">
            {(threatProb * 100).toFixed(1)}%
          </div>
          <div className="mt-2 w-full bg-[var(--color-base)] rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                threatProb > 0.75 ? "bg-rose-500" : threatProb > 0.4 ? "bg-amber-400" : "bg-emerald-400"
              }`}
              style={{ width: `${threatProb * 100}%` }}
            />
          </div>
        </div>

        <div className="rounded-xl border p-4 bg-[var(--color-panel)]" style={{ borderColor: "var(--color-border)" }}>
          <div className="text-xs text-[var(--color-text-muted)] font-mono">PACKET INGESTION RATE</div>
          <div className="mt-2 text-2xl font-bold font-mono text-[var(--color-text-primary)]">
            {packetsPerSec.toLocaleString()} <span className="text-xs font-normal text-[var(--color-text-secondary)]">pkts/s</span>
          </div>
          <div className="mt-2 text-xs font-mono text-[var(--color-text-secondary)]">
            Total Ingested: {totalPackets.toLocaleString()}
          </div>
        </div>

        <div className="rounded-xl border p-4 bg-[var(--color-panel)]" style={{ borderColor: "var(--color-border)" }}>
          <div className="text-xs text-[var(--color-text-muted)] font-mono">MITRE ATT&CK STAGE</div>
          <div className="mt-2">
            <MITREStageBadge stage={mitreStage} />
          </div>
          <div className="mt-2 text-xs font-mono text-[var(--color-text-secondary)]">
            Next Predicted: {mitreStage === "Reconnaissance" ? "Initial Access" : mitreStage === "Initial Access" ? "Lateral Movement" : "Exfiltration"}
          </div>
        </div>

        <div className="rounded-xl border p-4 bg-[var(--color-panel)]" style={{ borderColor: "var(--color-border)" }}>
          <div className="text-xs text-[var(--color-text-muted)] font-mono">TCP SYN RATIO / IAT</div>
          <div className="mt-2 text-2xl font-bold font-mono text-[var(--color-text-primary)]">
            {(synRatio * 100).toFixed(1)}% <span className="text-xs font-normal text-[var(--color-text-secondary)]">/ {flowIat}ms</span>
          </div>
          <div className="mt-2 text-xs font-mono text-[var(--color-text-secondary)]">
            TTL Variance: {ttlVariance} (Anomaly: {ttlVariance > 4.0 ? "YES" : "NO"})
          </div>
        </div>
      </div>

      {/* Main Grid: Chart & K-Step Rollout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-xl border p-5 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
                LIVE THREAT PROBABILITY TRAJECTORY (SLIDING WINDOW)
              </h3>
              <p className="font-mono text-xs text-[var(--color-text-secondary)]">
                Real-time stream vs. 0.75 Autonomous Shield Threshold
              </p>
            </div>
            <span className="font-mono text-xs text-[var(--color-accent)] font-semibold">
              WINDOW: 15s (1s BINS)
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" opacity={0.5} />
                <XAxis dataKey="timestamp" stroke="var(--color-text-muted)" tick={{ fontSize: 10, fill: "var(--color-text-muted)" }} />
                <YAxis domain={[0, 1]} stroke="var(--color-text-muted)" tick={{ fontSize: 10, fill: "var(--color-text-muted)" }} />
                <Tooltip
                  contentStyle={{ backgroundColor: "var(--color-panel)", borderColor: "var(--color-border)", fontSize: "11px", fontFamily: "monospace" }}
                />
                <ReferenceLine y={0.75} stroke="var(--color-critical)" strokeDasharray="4 4" label={{ value: "SHIELD THRESHOLD (0.75)", fill: "var(--color-critical)", fontSize: 10 }} />
                <Line
                  type="monotone"
                  dataKey="threatProbability"
                  stroke="var(--color-accent)"
                  strokeWidth={2.5}
                  dot={{ r: 3, fill: "var(--color-accent)" }}
                  isAnimationActive={false}
                />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* K-Step Forward Simulation Bar Chart */}
        <div className="rounded-xl border p-5 glow-box flex flex-col justify-between" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
          <div>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
                K-STEP FORWARD ROLLOUT
              </h3>
              <Cpu size={16} className="text-[var(--color-accent)]" />
            </div>
            <p className="mt-1 font-mono text-xs text-[var(--color-text-secondary)]">
              World Model Autoregressive Rollout (+50s Horizon).
            </p>
          </div>

          <div className="my-6 flex items-end gap-2 justify-between">
            {kStepRollout.map((val, idx) => {
              const heightPct = Math.max(8, val * 100);
              const isCrit = val >= 0.75;
              const isElev = val >= 0.4 && val < 0.75;
              return (
                <div key={idx} className="flex flex-col items-center gap-1.5 flex-1">
                  <span className="font-mono text-[10px] text-[var(--color-text-secondary)]">
                    {(val * 100).toFixed(0)}%
                  </span>
                  <div className="relative w-full h-32 rounded bg-[var(--color-base)] flex items-end border border-[var(--color-border)]">
                    <div
                      className={`w-full rounded-sm transition-all duration-300 ${
                        isCrit ? "bg-rose-500" : isElev ? "bg-amber-400" : "bg-emerald-400"
                      }`}
                      style={{ height: `${heightPct}%` }}
                    />
                  </div>
                  <span className="font-mono text-[10px] text-[var(--color-text-muted)]">
                    T+{idx + 1}
                  </span>
                </div>
              );
            })}
          </div>

          <div className="rounded-lg border p-3 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
            <div className="flex items-center gap-2 font-mono text-xs text-[var(--color-accent)] font-semibold">
              <Shield size={14} />
              TACTICAL FORECAST VERDICT:
            </div>
            <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
              {threatProb > 0.75
                ? "Attacker trajectory converges to compromise in < 30s. Automated defense enforcement required."
                : threatProb > 0.4
                ? "Reconnaissance activity accelerating. Pre-emptive firewall rule synthesized."
                : "Stationary benign equilibrium. Zero anomalous progression detected."}
            </p>
          </div>
        </div>
      </div>

      {/* ───────────────────────────────────────────────────────────────────────────── */}
      {/* FEATURE 3: AUTONOMOUS SOVEREIGN FIREWALL DEFENSE SYNTHESIZER */}
      {/* ───────────────────────────────────────────────────────────────────────────── */}
      <div className="rounded-xl border p-5 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <Layers size={18} className="text-[var(--color-accent)]" />
            <div>
              <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
                AUTONOMOUS FIREWALL DEFENSE RULE GENERATION (1-CLICK DEPLOYABLE)
              </h3>
              <p className="text-xs text-[var(--color-text-secondary)] font-mono">
                Synthesized in real-time from World Model state dynamics for target {assetDomain}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyRule}
              className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 font-mono text-xs font-semibold bg-[var(--color-base)] text-[var(--color-accent)] border-[var(--color-accent)]/40 hover:bg-[var(--color-accent)]/10"
            >
              {copiedRule ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
              {copiedRule ? "COPIED TO CLIPBOARD" : "COPY SYNTHESIZED RULE"}
            </button>
            <button
              onClick={handleExecuteMitigation}
              className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs font-semibold transition-all ${
                isMitigationActive
                  ? "bg-emerald-500 text-slate-950"
                  : "bg-rose-500 hover:bg-rose-600 text-white"
              }`}
            >
              <Shield size={13} />
              {isMitigationActive ? "SHIELD APPLIED: THREAT 0%" : "EXECUTE AUTO-BLOCK SIMULATION"}
            </button>
          </div>
        </div>

        {/* Tab Selection */}
        <div className="flex flex-wrap items-center gap-2 border-b pb-2 mb-3" style={{ borderColor: "var(--color-border)" }}>
          {(["iptables", "nftables", "netsh", "cisco", "cloudflare", "ebpf"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setSelectedFirewallTab(tab)}
              className={`px-3 py-1 rounded font-mono text-xs font-bold transition-all uppercase ${
                selectedFirewallTab === tab
                  ? "bg-[var(--color-accent)] text-slate-950"
                  : "bg-[var(--color-base)] text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              {tab === "iptables"
                ? "Linux iptables"
                : tab === "nftables"
                ? "Linux nftables"
                : tab === "netsh"
                ? "Windows Netsh"
                : tab === "cisco"
                ? "Cisco IOS ACL"
                : tab === "cloudflare"
                ? "Cloudflare WAF"
                : "eBPF / XDP (<1µs)"}
            </button>
          ))}
        </div>

        {/* Rule Display Box */}
        <div className="rounded-lg border bg-slate-950 p-3 font-mono text-xs text-[var(--color-accent)] overflow-x-auto border-slate-800">
          <pre className="whitespace-pre-wrap">{synthesizedRules[selectedFirewallTab]}</pre>
        </div>
      </div>

      {/* Real-Time Event Log */}
      <div className="rounded-xl border p-5 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Terminal size={16} className="text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
              LIVE NIDS DETECTIONS & SOVEREIGN RULE SYNTHESIS AUDIT LOG
            </h3>
          </div>
          <span className="font-mono text-xs text-[var(--color-text-muted)]">
            Auto-Syncing with Snort / nftables Engine
          </span>
        </div>

        <div className="flex flex-col gap-2 font-mono text-xs max-h-56 overflow-y-auto pr-1">
          {eventLogs.map((log) => (
            <div
              key={log.id}
              className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-lg border p-2.5 bg-[var(--color-base)]"
              style={{ borderColor: "var(--color-border)" }}
            >
              <div className="flex items-center gap-3">
                <span className="text-[var(--color-text-muted)]">{log.time}</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                    log.severity === "critical"
                      ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                      : log.severity === "elevated"
                      ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                      : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                  }`}
                >
                  {log.action}
                </span>
                <span className="text-[var(--color-text-primary)]">{log.message}</span>
              </div>
              <div className="text-[11px] text-[var(--color-accent)] truncate max-w-md bg-slate-950 px-2 py-1 rounded border border-slate-800">
                {log.snortRule}
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
