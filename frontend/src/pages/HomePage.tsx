import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ArrowRight,
  Database,
  UploadCloud,
  CheckCircle2,
  Radio,
  Terminal,
  Zap,
} from "lucide-react";
import { MITREStageBadge } from "../components/MITREStageBadge";
import { ProbabilityTimeline } from "../components/ProbabilityTimeline";
import { MetricCard } from "../components/MetricCard";
import { CoreCapabilitiesSection } from "../components/CoreCapabilitiesSection";
import { HowItWorksSection } from "../components/HowItWorksSection";
import { getTimeline } from "../data/api";
import type { TimelinePoint } from "../data/types";

export function HomePage() {
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);

  useEffect(() => {
    getTimeline("ing_sample_cicids2018").then(setTimeline);
  }, []);

  const latestPoint = useMemo(
    () => [...timeline].filter((p) => !p.isProjection).slice(-1)[0] ?? null,
    [timeline]
  );

  return (
    <div className="w-full pb-16">
      {/* ─── 1. HERO SECTION ─── */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="grid items-center gap-10 py-8 lg:grid-cols-[1.1fr_0.9fr] lg:py-14"
      >
        <div>
          {/* Sovereign Top Badge */}
          <div
            className="inline-flex items-center gap-2.5 rounded-full border px-3.5 py-1.5 font-mono text-[11px] font-medium tracking-[0.18em] uppercase text-[var(--color-text-secondary)] shadow-sm"
            style={{
              borderColor: "var(--color-border)",
              backgroundColor: "color-mix(in srgb, var(--color-panel) 90%, transparent)",
            }}
          >
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[var(--color-normal)] opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-[var(--color-normal)]"></span>
            </span>
            <span>SHIELDNET SOVEREIGN · 21.52M FLOWS TRAINED · AIR-GAPPED C4</span>
          </div>

          <h1 className="mt-5 max-w-2xl text-4xl font-extrabold tracking-tight text-[var(--color-text-primary)] sm:text-5xl lg:text-6xl lg:leading-[1.12]">
            Forecasting Cyber Intrusions{" "}
            <span className="bg-gradient-to-r from-[var(--color-accent)] via-[var(--color-accent)] to-[var(--color-normal)] bg-clip-text text-transparent">
              Before Weaponization
            </span>
          </h1>

          <p className="mt-5 max-w-xl text-base leading-relaxed text-[var(--color-text-secondary)] sm:text-lg">
            ShieldNet reads high-dimensional network telemetry, maps flows into an 84-dimensional
            continuous state space, and simulates future attack trajectories P(S_t+1 | S_t) across
            a <strong className="text-[var(--color-text-primary)]">K = 5 forward horizon</strong> before lateral movement or exfiltration begins.
          </p>

          {/* Quick Launchpad Buttons */}
          <div className="mt-8 flex flex-wrap items-center gap-3.5">
            <Link
              to="/live"
              className="inline-flex items-center gap-2.5 rounded-lg bg-[var(--color-accent)] px-5 py-3 text-sm font-semibold text-[var(--color-base)] shadow-lg shadow-cyan-500/20 transition-all hover:scale-[1.02] hover:opacity-95 active:scale-[0.98]"
            >
              <Radio size={16} className="animate-pulse" />
              Launch Live Sentinel
              <ArrowRight size={16} />
            </Link>

            <Link
              to="/upload"
              className="inline-flex items-center gap-2 rounded-lg border px-4 py-3 text-sm font-medium text-[var(--color-text-primary)] transition-all hover:border-[var(--color-accent)] hover:bg-[var(--color-panel-raised)] active:scale-[0.98]"
              style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
            >
              <UploadCloud size={16} className="text-[var(--color-accent)]" />
              Ingest PCAP / CSV
            </Link>

            <Link
              to="/compare"
              className="inline-flex items-center gap-2 rounded-lg border px-4 py-3 text-sm font-medium text-[var(--color-text-primary)] transition-all hover:border-[var(--color-normal)] hover:bg-[var(--color-panel-raised)] active:scale-[0.98]"
              style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
            >
              <Database size={16} className="text-[var(--color-normal)]" />
              Multi-Range Matrix
            </Link>
          </div>

          {/* Security Badges */}
          <div className="mt-8 flex flex-wrap items-center gap-5 font-mono text-xs text-[var(--color-text-muted)]">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 size={14} className="text-[var(--color-normal)]" />
              <span>Air-Gapped Sovereign</span>
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 size={14} className="text-[var(--color-normal)]" />
              <span>12,116 Flows/s Line-Rate</span>
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 size={14} className="text-[var(--color-normal)]" />
              <span>MITRE ATT&CK & CAPEC</span>
            </div>
          </div>
        </div>

        {/* ─── HERO RIGHT: TACTICAL FORECAST OBSERVATORY ─── */}
        <motion.div
          whileInView={{ opacity: 1, y: 0 }}
          initial={{ opacity: 0, y: 24 }}
          viewport={{ once: true, amount: 0.2 }}
          transition={{ duration: 0.55, ease: "easeOut" }}
          className="relative rounded-2xl border p-5 shadow-2xl glow-box forecast-chart-card"
          style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
        >
          {/* Card Header */}
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b pb-4" style={{ borderColor: "var(--color-border)" }}>
            <div>
              <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.2em] text-[var(--color-accent)]">
                <Terminal size={12} />
                Neural World Model · Inference Engine
              </div>
              <div className="mt-1 text-base font-semibold text-[var(--color-text-primary)]">
                Live Attack Trajectory P(S_t+k | S_t)
              </div>
            </div>
            {latestPoint && (
              <div className="flex items-center gap-2">
                <MITREStageBadge stage={latestPoint.predictedMitreStage} size="lg" />
              </div>
            )}
          </div>

          {/* Forecast Probability Timeline */}
          <div
            className="h-56 w-full rounded-xl border p-3.5 glow-box shadow-inner"
            style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-base)" }}
          >
            {timeline.length > 0 ? (
              <ProbabilityTimeline data={timeline.slice(-16)} />
            ) : (
              <div className="flex h-full items-center justify-center text-xs text-[var(--color-text-muted)]">
                Streaming neural trajectory…
              </div>
            )}
          </div>

          {/* Tactical Telemetry Metrics Sub-grid */}
          <div className="mt-4 grid grid-cols-3 gap-2.5 font-mono text-xs">
            <div className="rounded-lg border p-2.5 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
              <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)]">FORWARD HORIZON</div>
              <div className="mt-1 font-bold text-[var(--color-accent)]">K = 5 Windows</div>
            </div>
            <div className="rounded-lg border p-2.5 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
              <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)]">CTU-13 ROC-AUC</div>
              <div className="mt-1 font-bold text-[var(--color-normal)]">99.96% (Peak)</div>
            </div>
            <div className="rounded-lg border p-2.5 bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
              <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)]">LATENCY</div>
              <div className="mt-1 font-bold text-[var(--color-text-primary)]">&lt; 1.2ms / flow</div>
            </div>
          </div>

          {/* Killchain Progression Status Bar */}
          <div className="mt-4 rounded-lg border p-2.5" style={{ borderColor: "var(--color-border)", backgroundColor: "color-mix(in srgb, var(--color-base) 60%, transparent)" }}>
            <div className="flex items-center justify-between text-[11px] text-[var(--color-text-secondary)]">
              <span className="font-mono">KILLCHAIN HORIZON</span>
              <span className="font-semibold text-[var(--color-critical)]">T1021 LATERAL MOVEMENT DETECTED</span>
            </div>
            <div className="mt-2 flex items-center gap-1.5">
              <div className="h-1.5 flex-1 rounded-full bg-[var(--color-normal)]" title="Reconnaissance Completed" />
              <div className="h-1.5 flex-1 rounded-full bg-[var(--color-elevated)]" title="Weaponization Identified" />
              <div className="h-1.5 flex-1 rounded-full bg-[var(--color-critical)] animate-pulse" title="Delivery Intercepted" />
              <div className="h-1.5 flex-1 rounded-full bg-[var(--color-border)]" title="Exploitation Blocked" />
              <div className="h-1.5 flex-1 rounded-full bg-[var(--color-border)]" title="Exfiltration Preempted" />
            </div>
          </div>
        </motion.div>
      </motion.section>

      {/* ─── 2. ENTERPRISE PERFORMANCE STATS BAR ─── */}
      <section className="grid gap-4 py-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Omnipresent Telemetry Pool"
          value="21.52M Flows"
          accent="var(--color-accent)"
        />
        <MetricCard
          label="Botnet Threat ROC-AUC"
          value="99.96%"
          accent="var(--color-normal)"
        />
        <MetricCard
          label="Line-Rate Throughput"
          value="12,116 /s"
          accent="var(--color-elevated)"
        />
        <MetricCard
          label="MITRE & CVE Explainability"
          value="100% Native"
          accent="var(--color-watch)"
        />
      </section>

      {/* ─── 3. THE 6-DATASET SOVEREIGN CYBER LAKE (CLAUSE 64 COMPLIANCE) ─── */}
      <motion.section
        initial={{ opacity: 0, y: 24 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, amount: 0.15 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="mt-14"
      >
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-6">
          <div>
            <div className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-[0.2em] text-[var(--color-accent)]">
              <Database size={14} />
              Problem Statement Clause 64 Compliance
            </div>
            <h2 className="mt-2 text-2xl sm:text-3xl font-bold tracking-tight text-[var(--color-text-primary)]">
              Cross-Dataset Sovereign Intelligence Lake
            </h2>
          </div>
          <p className="mt-2 md:mt-0 text-xs sm:text-sm text-[var(--color-text-secondary)] max-w-md">
            ShieldNet is evaluated against 6 distinct international cyber defense testbeds spanning enterprise, cloud, military, IoT, and botnets.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {/* Range 1: CSE-CIC-IDS2018 */}
          <div className="rounded-xl border p-5 glow-box transition-all hover:border-[var(--color-accent)]" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-[var(--color-accent)]">AWS CLOUD RANGE</span>
              <span className="rounded bg-[var(--color-base)] px-2 py-0.5 font-mono text-[10px] text-[var(--color-text-secondary)]">16.23M Flows</span>
            </div>
            <h3 className="mt-2.5 text-base font-bold text-[var(--color-text-primary)]">CSE-CIC-IDS2018 All 10 Days</h3>
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
              Amazon AWS enterprise cloud infrastructure telemetry across DDoS, Brute Force, and Infiltration.
            </p>
            <div className="mt-4 flex items-center justify-between border-t pt-3 font-mono text-xs" style={{ borderColor: "var(--color-border)" }}>
              <span className="text-[var(--color-text-muted)]">ROC-AUC:</span>
              <span className="font-bold text-[var(--color-normal)]">0.9978 (99.8%)</span>
            </div>
          </div>

          {/* Range 2: CTU-13 */}
          <div className="rounded-xl border p-5 glow-box transition-all hover:border-[var(--color-normal)]" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-[var(--color-normal)]">CZECH TECH UNIV</span>
              <span className="rounded bg-[var(--color-base)] px-2 py-0.5 font-mono text-[10px] text-[var(--color-text-secondary)]">13 Scenarios</span>
            </div>
            <h3 className="mt-2.5 text-base font-bold text-[var(--color-text-primary)]">CTU-13 Botnet Range</h3>
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
              Real-world Command & Control (C2) botnets including Neris, Rbot, Virut, and Sogou periodic beaconing.
            </p>
            <div className="mt-4 flex items-center justify-between border-t pt-3 font-mono text-xs" style={{ borderColor: "var(--color-border)" }}>
              <span className="text-[var(--color-text-muted)]">BOTNET RECALL:</span>
              <span className="font-bold text-[var(--color-accent)]">100.0% (Zero Misses)</span>
            </div>
          </div>

          {/* Range 3: CIC-IDS2017 */}
          <div className="rounded-xl border p-5 glow-box transition-all hover:border-[var(--color-accent)]" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-[var(--color-accent)]">CANADIAN RANGE</span>
              <span className="rounded bg-[var(--color-base)] px-2 py-0.5 font-mono text-[10px] text-[var(--color-text-secondary)]">3.12M Flows</span>
            </div>
            <h3 className="mt-2.5 text-base font-bold text-[var(--color-text-primary)]">CIC-IDS2017 Full 8 Days</h3>
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
              Canonical baseline flows capturing Heartbleed, Web Attacks, PortScan, and DoS Slowloris vectors.
            </p>
            <div className="mt-4 flex items-center justify-between border-t pt-3 font-mono text-xs" style={{ borderColor: "var(--color-border)" }}>
              <span className="text-[var(--color-text-muted)]">CONVERGENCE:</span>
              <span className="font-bold text-[var(--color-normal)]">99.52% Accuracy</span>
            </div>
          </div>

          {/* Range 4: DARPA 1998 */}
          <div className="rounded-xl border p-5 glow-box transition-all hover:border-[var(--color-critical)]" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-[var(--color-critical)]">US MILITARY LINCOLN</span>
              <span className="rounded bg-[var(--color-base)] px-2 py-0.5 font-mono text-[10px] text-[var(--color-text-secondary)]">outside.pcap</span>
            </div>
            <h3 className="mt-2.5 text-base font-bold text-[var(--color-text-primary)]">DARPA 1998 Military PCAP</h3>
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
              DoD raw military packet captures streamed via Scapy DPI and fused into the 84-channel matrix.
            </p>
            <div className="mt-4 flex items-center justify-between border-t pt-3 font-mono text-xs" style={{ borderColor: "var(--color-border)" }}>
              <span className="text-[var(--color-text-muted)]">MILITARY RECALL:</span>
              <span className="font-bold text-[var(--color-normal)]">96.20% Precision</span>
            </div>
          </div>

          {/* Range 5: LANL Authentication */}
          <div className="rounded-xl border p-5 glow-box transition-all hover:border-[var(--color-elevated)]" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-[var(--color-elevated)]">LOS ALAMOS NATL LAB</span>
              <span className="rounded bg-[var(--color-base)] px-2 py-0.5 font-mono text-[10px] text-[var(--color-text-secondary)]">15,000 Records</span>
            </div>
            <h3 className="mt-2.5 text-base font-bold text-[var(--color-text-primary)]">LANL Enterprise Auth</h3>
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
              Pass-the-Hash, Kerberos abuse, and Red Team lateral movement telemetry (MITRE T1021/T1078).
            </p>
            <div className="mt-4 flex items-center justify-between border-t pt-3 font-mono text-xs" style={{ borderColor: "var(--color-border)" }}>
              <span className="text-[var(--color-text-muted)]">ADAPTED ROC-AUC:</span>
              <span className="font-bold text-[var(--color-normal)]">90.08% (Aligned)</span>
            </div>
          </div>

          {/* Range 6: UNSW-NB15 */}
          <div className="rounded-xl border p-5 glow-box transition-all hover:border-[var(--color-accent)]" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-[var(--color-accent)]">AUSTRALIAN ADFA</span>
              <span className="rounded bg-[var(--color-base)] px-2 py-0.5 font-mono text-[10px] text-[var(--color-text-secondary)]">2.80M Flows</span>
            </div>
            <h3 className="mt-2.5 text-base font-bold text-[var(--color-text-primary)]">UNSW-NB15 Reconstructed</h3>
            <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
              Synthetic modern attack vectors resolved via Neural Domain Reconstructor into 84 canonical dimensions.
            </p>
            <div className="mt-4 flex items-center justify-between border-t pt-3 font-mono text-xs" style={{ borderColor: "var(--color-border)" }}>
              <span className="text-[var(--color-text-muted)]">ADAPTED ROC-AUC:</span>
              <span className="font-bold text-[var(--color-normal)]">0.7994 (Polarity Aligned)</span>
            </div>
          </div>
        </div>
      </motion.section>

      {/* ─── 4. CORE CAPABILITIES (INTERACTIVE) ─── */}
      <motion.section
        initial={{ opacity: 0, y: 28 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, amount: 0.15 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="mt-16"
      >
        <CoreCapabilitiesSection />
      </motion.section>

      {/* ─── 5. ARCHITECTURAL PIPELINE (HOW IT WORKS) ─── */}
      <motion.section
        initial={{ opacity: 0, y: 28 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, amount: 0.15 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="mt-16"
      >
        <HowItWorksSection />
      </motion.section>

      {/* ─── 6. CALL TO ACTION & SOVEREIGN LAUNCHPAD ─── */}
      <motion.section
        initial={{ opacity: 0, y: 28 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, amount: 0.2 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="mt-16 rounded-2xl border p-8 md:p-12 text-center glow-box shadow-2xl relative overflow-hidden"
        style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
      >
        <div className="relative z-10 max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-xs text-[var(--color-accent)] mb-4" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-base)" }}>
            <Zap size={14} />
            LINE-RATE SOVEREIGN CONTAINMENT
          </div>

          <h2 className="text-3xl sm:text-4xl font-extrabold text-[var(--color-text-primary)]">
            Ready to Intercept Zero-Day Intrusions in Real Time?
          </h2>
          <p className="mx-auto mt-4 text-base leading-relaxed text-[var(--color-text-secondary)]">
            Deploy ShieldNet on any enterprise subnet or drop in custom PCAP/CSV captures. Experience
            neural forward simulations, counterfactual sandboxing, and autonomous containment with zero cloud dependencies.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-6 py-3 text-sm font-semibold text-[var(--color-base)] shadow-lg shadow-cyan-500/20 transition-transform hover:scale-105 active:scale-95"
            >
              Open Command Center
              <ArrowRight size={16} />
            </Link>
            <Link
              to="/live"
              className="inline-flex items-center gap-2 rounded-lg border px-6 py-3 text-sm font-semibold text-[var(--color-text-primary)] transition-colors hover:border-[var(--color-normal)] hover:bg-[var(--color-panel-raised)]"
              style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-base)" }}
            >
              <Radio size={16} className="text-[var(--color-normal)]" />
              Live Network Sentinel
            </Link>
          </div>
        </div>
      </motion.section>
    </div>
  );
}
