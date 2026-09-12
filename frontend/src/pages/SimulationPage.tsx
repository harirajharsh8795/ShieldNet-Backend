import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { RotateCcw, Activity, FileText, Sparkles, Volume2, VolumeX } from "lucide-react";
import { ProbabilityTimeline } from "../components/ProbabilityTimeline";
import { KStepProjection } from "../components/KStepProjection";
import { FlaggedFlowsList } from "../components/FlaggedFlowsList";
import { MITREStageBadge } from "../components/MITREStageBadge";
import { ExplainabilityPanel } from "../components/ExplainabilityPanel";
import { ExportButton } from "../components/ExportButton";
import { TelemetryHeader } from "../components/TelemetryHeader";
import { ActiveIngestionBanner } from "../components/ActiveIngestionBanner";
import { MitreLifecycleTimeline } from "../components/MitreLifecycleTimeline";
import { DefenseSandboxPanel } from "../components/DefenseSandboxPanel";
import { IncidentDossierModal } from "../components/IncidentDossierModal";
import { ShapExplanationCard } from "../components/ShapExplanationCard";
import { NetworkTopologyVisualizer } from "../components/NetworkTopologyVisualizer";
import { ExecutiveMemoModal } from "../components/ExecutiveMemoModal";
import { OODDomainGuardCard } from "../components/OODDomainGuardCard";
import { soundManager } from "../utils/soundEffects";
import {
  getTimeline,
  getFlaggedFlows,
  getSampleSessions,
  evaluateMitigationActions,
  getMitreReasoning,
  type ScenarioSession,
  type MitigationResponse,
  type MitreReasoningResponse,
} from "../data/api";
import { useAppStore } from "../store/useAppStore";
import type { FlaggedFlow, Severity, TimelinePoint } from "../data/types";

export function SimulationPage() {
  const [searchParams] = useSearchParams();
  const querySession = searchParams.get("session");

  const activeIngestion = useAppStore((s) => s.activeIngestion);
  const setActiveIngestion = useAppStore((s) => s.setActiveIngestion);

  const [sessions, setSessions] = useState<ScenarioSession[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string>("sess_bot_c2");
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [flows, setFlows] = useState<FlaggedFlow[]>([]);
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [selectedPoint, setSelectedPoint] = useState<TimelinePoint | null>(null);
  const [replayKey, setReplayKey] = useState(0);
  const [loading, setLoading] = useState(true);

  // Counterfactual Mitigation & Symbolic MITRE state
  const [mitigationData, setMitigationData] = useState<MitigationResponse | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>("RESET_CONNECTIONS");
  const [mitreReasoning, setMitreReasoning] = useState<MitreReasoningResponse | null>(null);
  const [isDossierOpen, setIsDossierOpen] = useState(false);
  const [isMemoOpen, setIsMemoOpen] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const [displayMode, setDisplayMode] = useState<"timeline" | "topology">("timeline");

  useEffect(() => {
    getSampleSessions().then((sList) => {
      setSessions(sList);
      const targetId = querySession || activeIngestion?.matchedScenarioId || activeIngestion?.id || sList[0]?.id || "sess_bot_c2";
      const matched = sList.find(s => s.id === targetId || s.name.toLowerCase().includes((targetId || "").toLowerCase())) || sList[0];
      if (matched) {
        setSelectedSessionId(matched.id);
        setActiveIngestion({
          id: matched.id,
          sourceType: "csv",
          filename: matched.name,
          datasetName: "cic-ids-2018",
          uploadedAt: new Date().toISOString(),
          status: "ready",
          matchedScenarioId: matched.id,
        });
      }
    });
  }, [querySession]);

  useEffect(() => {
    const sessId = activeIngestion?.matchedScenarioId || activeIngestion?.id || selectedSessionId;
    setLoading(true);

    const currentSess = sessions.find((s) => s.id === sessId || s.name === sessId) || sessions[0];

    Promise.all([
      getTimeline(sessId),
      getFlaggedFlows(),
      evaluateMitigationActions(sessId),
      getMitreReasoning({
        predicted_class: currentSess?.ground_truth_label || "SSH-Patator",
        confidence: currentSess && currentSess.threat_trajectory ? currentSess.threat_trajectory.slice(-1)[0] : 0.98,
        host_ip: currentSess?.host_ip || "172.16.0.1",
        target_ip: currentSess?.target_ip || "192.168.10.50",
      }),
    ]).then(([tl, fl, mit, reason]) => {
      setTimeline(tl);
      setFlows(fl);
      setMitigationData(mit);
      setSelectedAction(mit.safety_shield_recommendation || "RESET_CONNECTIONS");
      setMitreReasoning(reason);
      setLoading(false);
    });
  }, [activeIngestion?.id, activeIngestion?.matchedScenarioId, selectedSessionId, replayKey, sessions]);

  function handleSessionChange(id: string) {
    setSelectedSessionId(id);
    const found = sessions.find((s) => s.id === id);
    if (found) {
      setActiveIngestion({
        id: found.id,
        sourceType: "csv",
        filename: found.name,
        datasetName: "cic-ids-2018",
        uploadedAt: new Date().toISOString(),
        status: "ready",
        matchedScenarioId: found.id,
      });
    }
  }

  const targetSessionId = activeIngestion?.matchedScenarioId || activeIngestion?.id || selectedSessionId;
  const currentSession = sessions.find((s) => s.id === targetSessionId) || sessions[0];
  const latestObserved = [...timeline].filter((p) => !p.isProjection).slice(-1)[0];
  const projectedPoints = timeline.filter((p) => p.isProjection);
  const isCritical =
    (latestObserved?.infiltrationProbability ?? 0) >= 0.8 ||
    projectedPoints.some((p) => p.infiltrationProbability >= 0.8);

  return (
    <div className="flex flex-col gap-6">
      {/* Sovereign Telemetry Header */}
      <TelemetryHeader />

      {/* Active Ingested File Banner */}
      <ActiveIngestionBanner
        ingestion={activeIngestion}
        scenarioName={currentSession?.name}
        hostIp={currentSession?.host_ip}
        targetIp={currentSession?.target_ip}
      />

      {/* Top Header & Scenario Selector */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border p-4 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
        <div className="flex min-w-0 max-w-full flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 font-mono text-xs text-[var(--color-text-secondary)]">
            <Activity size={14} className="text-[var(--color-accent)]" />
            <span>SCENARIO PRESET:</span>
          </div>
          <select
            value={activeIngestion?.id || selectedSessionId}
            onChange={(e) => handleSessionChange(e.target.value)}
            className="rounded-md border bg-[var(--color-base)] px-3 py-1.5 font-mono text-xs text-[var(--color-text-primary)] transition-colors focus:border-[var(--color-accent)] focus:outline-none"
            style={{ 
              borderColor: "var(--color-border)"
            }}
          >
            {activeIngestion && (
              <option value={activeIngestion.id}>
                📁 [INGESTED FILE] {activeIngestion.filename} ({activeIngestion.sourceType.toUpperCase()})
              </option>
            )}
            {sessions.map((sess) => (
              <option key={sess.id} value={sess.id}>
                [{sess.severity.toUpperCase()}] {sess.name} ({sess.host_ip})
              </option>
            ))}
          </select>
          {latestObserved && <MITREStageBadge stage={latestObserved.predictedMitreStage} size="lg" />}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Display Mode Switcher */}
          <div className="flex rounded-lg border p-0.5 bg-[var(--color-base)] font-mono text-xs" style={{ borderColor: "var(--color-border)" }}>
            <button
              onClick={() => setDisplayMode("timeline")}
              className={`px-2.5 py-1 rounded-md transition-colors ${displayMode === "timeline" ? "bg-[var(--color-accent)] text-slate-950 font-bold" : "text-[var(--color-text-secondary)]"}`}
            >
              Timeline (K=5)
            </button>
            <button
              onClick={() => setDisplayMode("topology")}
              className={`px-2.5 py-1 rounded-md transition-colors ${displayMode === "topology" ? "bg-[var(--color-accent)] text-slate-950 font-bold" : "text-[var(--color-text-secondary)]"}`}
            >
              Subnet Topology
            </button>
          </div>

          {/* Sound Alert Toggle */}
          <button
            onClick={() => setIsMuted(soundManager.toggleMute())}
            className="inline-flex items-center gap-1.5 rounded-lg border px-2 py-1.5 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            style={{ borderColor: "var(--color-border)" }}
            title={isMuted ? "Unmute Tactical Sound Alerts" : "Mute Tactical Sound Alerts"}
          >
            {isMuted ? <VolumeX size={14} className="text-rose-400" /> : <Volume2 size={14} className="text-emerald-400" />}
          </button>


          <button
            onClick={() => setIsMemoOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold text-emerald-300 border border-emerald-500/40 bg-emerald-500/15 transition-all shadow-md hover:scale-105"
            title="Generate NCIIPC / CERT-In Executive Threat Intelligence Memo"
          >
            <FileText size={13} />
            <span>Executive Memo</span>
          </button>

          <button
            onClick={() => setIsDossierOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold text-white transition-all shadow-md hover:scale-105"
            style={{ backgroundColor: "var(--color-accent)" }}
          >
            <FileText size={13} />
            <span>Sovereign Dossier</span>
          </button>

          <button
            onClick={() => setReplayKey((k) => k + 1)}
            className="inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-medium text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-panel-raised)]"
            style={{ borderColor: "var(--color-border)" }}
          >
            <RotateCcw size={13} />
            Replay
          </button>
          <ExportButton ingestionId={activeIngestion?.id || selectedSessionId} />
        </div>
      </div>

      {/* Host Meta Banner */}
      {currentSession && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 rounded-xl border p-3.5 font-mono text-xs text-[var(--color-text-secondary)]" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel-raised)" }}>
          <div>
            <span className="text-[var(--color-text-muted)]">ACTIVE FILE: </span>
            <span className="text-emerald-400 font-bold truncate">{activeIngestion?.filename || currentSession.name}</span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">ADVERSARY HOST: </span>
            <span className="text-[var(--color-accent)]">{currentSession.host_ip}</span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">TARGET CII ASSET: </span>
            <span className="text-[var(--color-text-primary)]">{currentSession.target_ip}</span>
          </div>
          <div>
            <span className="text-[var(--color-text-muted)]">GROUND TRUTH: </span>
            <span className="text-[var(--color-elevated)]">{currentSession.ground_truth_label}</span>
          </div>
        </div>
      )}

      {/* Symbolic MITRE ATT&CK Lifecycle Timeline */}
      <MitreLifecycleTimeline
        reasoning={mitreReasoning}
        currentStage={currentSession?.mitre_stage || 2}
      />

      {/* Out-of-Distribution (OOD) Domain Guard Visualizer */}
      <OODDomainGuardCard sessionId={targetSessionId} />

      {/* Main Grid: Forecast Timeline & Side Panels */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_340px]">
        <div className="flex flex-col gap-6">
          {/* Main Forecast View: Timeline (K=5) or Subnet Lateral Traversal Topology */}
          {displayMode === "topology" ? (
            <NetworkTopologyVisualizer
              attackerIp={currentSession?.host_ip}
              targetIp={currentSession?.target_ip}
              scenarioName={currentSession?.name}
              threatProbability={currentSession?.threat_trajectory?.slice(-1)[0] ?? 0.88}
              mitigationAction={selectedAction}
            />
          ) : (
            <>
              {/* Timeline Chart */}
              <div
                className="relative h-84 rounded-xl border p-4"
                style={{
                  borderColor: isCritical ? "var(--color-critical)" : "var(--color-border)",
                  backgroundColor: "var(--color-panel)",
                  boxShadow: isCritical ? "0 0 18px -8px var(--color-critical)" : "none",
                }}
              >
                <div className="mb-2 flex items-center justify-between">
                  <span className="font-mono text-xs tracking-wider text-[var(--color-text-secondary)]">
                    THREAT INFILTRATION PROBABILITY P(Attack) &amp; K-STEP FORWARD ROLLOUT
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => document.getElementById("shap-explanation-section")?.scrollIntoView({ behavior: "smooth" })}
                      className="flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-[10px] font-semibold text-[var(--color-accent)] border-[var(--color-accent)]/40 hover:bg-[var(--color-accent)]/15 transition-all shadow-sm"
                      title="Jump to SHAP Feature Attribution Breakdown"
                    >
                      <Sparkles size={12} className="animate-pulse text-[var(--color-accent)]" />
                      <span>Inspect SHAP Attribution ↓</span>
                    </button>
                    <span className="font-mono text-xs text-[var(--color-accent)]">
                      {isCritical ? "CRITICAL RISK ELEVATION" : "NORMAL DYNAMICS"}
                    </span>
                  </div>
                </div>

                {loading ? (
                  <div className="flex h-64 items-center justify-center text-xs text-[var(--color-text-muted)]">
                    Loading live state-space trajectory...
                  </div>
                ) : (
                  <ProbabilityTimeline
                    data={timeline}
                    onPointClick={setSelectedPoint}
                    selectedPredictionId={selectedPoint?.predictionId}
                  />
                )}
              </div>

              {/* K-Step Horizon Projection */}
              {!loading && projectedPoints.length > 0 && (
                <KStepProjection
                  projectedPoints={projectedPoints}
                  onSelect={setSelectedPoint}
                  selectedPredictionId={selectedPoint?.predictionId}
                />
              )}
            </>
          )}

          {/* Dynamic Scenario-Specific SHAP Feature Attribution (Immediately explains the graph!) */}
          <ShapExplanationCard
            sessionId={currentSession?.id}
            filename={activeIngestion?.filename}
            currentProbability={currentSession?.threat_trajectory?.slice(-1)[0] ?? 0.88}
            onOpenDetailedDrawer={() => {
              if (timeline.length > 0) {
                setSelectedPoint(timeline[timeline.length - 1]);
              }
            }}
          />

          {/* Interactive What-If Counterfactual Sandbox Panel */}
          <DefenseSandboxPanel
            mitigationData={mitigationData}
            selectedAction={selectedAction}
            onSelectAction={setSelectedAction}
            onOpenDossier={() => setIsDossierOpen(true)}
            scenarioName={currentSession?.name}
            hostIp={currentSession?.host_ip}
            targetIp={currentSession?.target_ip}
            baselineRisk={currentSession?.threat_trajectory ? currentSession.threat_trajectory.slice(-1)[0] : (latestObserved?.infiltrationProbability ?? 0.88)}
          />
        </div>

        {/* Right Column: Flagged Flows */}
        <div className="flex flex-col gap-6">
          <div className="rounded-xl border p-4 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
            <FlaggedFlowsList
              flows={flows}
              filter={severityFilter}
              onFilterChange={setSeverityFilter}
            />
          </div>
        </div>
      </div>

      {/* Slide-in Explainability Drawer */}
      <ExplainabilityPanel point={selectedPoint} onClose={() => setSelectedPoint(null)} />

      {/* 1-Click Sovereign Incident Dossier Modal */}
      <IncidentDossierModal
        isOpen={isDossierOpen}
        onClose={() => setIsDossierOpen(false)}
        scenarioName={currentSession?.name || "SSH / FTP Brute Force"}
        hostIp={currentSession?.host_ip || "172.16.0.1"}
        targetIp={currentSession?.target_ip || "192.168.10.50"}
        predictedClass={currentSession?.ground_truth_label || "SSH-Patator"}
        confidence={currentSession?.threat_trajectory ? currentSession.threat_trajectory.slice(-1)[0] : 0.98}
      />

      {/* 1-Click NCIIPC / CERT-In Executive Threat Intelligence Memo Modal */}
      <ExecutiveMemoModal
        isOpen={isMemoOpen}
        onClose={() => setIsMemoOpen(false)}
        scenarioName={currentSession?.name || "Ares Botnet / Infiltration"}
        hostIp={currentSession?.host_ip || "172.16.0.1"}
        targetIp={currentSession?.target_ip || "192.168.10.50"}
        predictedClass={currentSession?.ground_truth_label || "Botnet C2"}
        confidence={currentSession?.threat_trajectory ? currentSession.threat_trajectory.slice(-1)[0] : 0.94}
      />
    </div>
  );
}
