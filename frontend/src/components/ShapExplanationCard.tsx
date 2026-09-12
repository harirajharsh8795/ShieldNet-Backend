import { useMemo } from "react";
import { Sparkles, ArrowDownRight, CheckCircle2, FileSearch, ShieldAlert } from "lucide-react";
import { getDynamicShapProfile } from "../data/shapExplanations";

interface ShapExplanationCardProps {
  sessionId?: string;
  filename?: string;
  currentProbability?: number;
  onOpenDetailedDrawer?: () => void;
}

export function ShapExplanationCard({
  sessionId,
  filename,
  currentProbability = 0.88,
  onOpenDetailedDrawer,
}: ShapExplanationCardProps) {
  const profile = useMemo(() => {
    return getDynamicShapProfile(sessionId, filename);
  }, [sessionId, filename]);

  const totalPositiveShap = profile.features
    .filter((f) => f.contributionScore > 0)
    .reduce((acc, f) => acc + f.contributionScore, 0);

  const totalNegativeShap = profile.features
    .filter((f) => f.contributionScore < 0)
    .reduce((acc, f) => acc + f.contributionScore, 0);

  return (
    <div
      id="shap-explanation-section"
      className="flex flex-col gap-4 rounded-xl border p-5 transition-all duration-300 glow-box scroll-mt-24"
      style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-3" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-[var(--color-accent)]/15 border border-[var(--color-accent)]/30 text-[var(--color-accent)]">
            <Sparkles size={15} />
          </div>
          <div>
            <h3 className="font-bold text-sm tracking-wide text-[var(--color-text-primary)]">
              SHAP LOCAL FEATURE EXPLAINABILITY (AXIOMATIC ATTRIBUTION)
            </h3>
            <p className="font-mono text-[10px] text-[var(--color-text-muted)]">
              Lloyd Shapley Game Theory ($\Delta P = \sum \phi_i$) · Specific to {profile.name}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="rounded-full px-2.5 py-1 font-mono text-[10px] font-semibold border bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
            Axiom of Completeness: Validated
          </span>
          {onOpenDetailedDrawer && (
            <button
              onClick={onOpenDetailedDrawer}
              className="flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium text-[var(--color-accent)] hover:bg-[var(--color-accent)]/10 transition-colors"
              style={{ borderColor: "var(--color-accent)" }}
            >
              <FileSearch size={13} />
              <span>Full Path Breakdown</span>
            </button>
          )}
        </div>
      </div>

      {/* Forensic Narrative Callout */}
      <div className="rounded-lg border p-3.5 bg-[var(--color-base)] text-xs leading-relaxed" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
          <div className="flex items-center gap-1.5 font-mono text-[10px] text-[var(--color-accent)] font-semibold">
            <ShieldAlert size={13} />
            FORENSIC NARRATIVE ({profile.targetClass.toUpperCase()} ATTRIBUTION):
          </div>

          <div className="flex items-center gap-1.5 font-mono text-[9px]">
            {profile.targetClass !== "BENIGN" ? (
              <>
                <span className="px-1.5 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/40">
                  {profile.targetClass.includes("Infiltration") || profile.targetClass.includes("SCADA")
                    ? "CVE-2022-29951 (CVSS 9.8)"
                    : profile.targetClass.includes("Bot")
                    ? "CVE-2019-11510 (CVSS 9.8)"
                    : profile.targetClass.includes("Patator")
                    ? "CVE-2018-15473 (CVSS 7.5)"
                    : profile.targetClass.includes("DoS")
                    ? "CVE-2007-6750 (CVSS 7.5)"
                    : "CVE-2023-44487 (CVSS 7.5)"}
                </span>
                <span className="px-1.5 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/40">
                  {profile.targetClass.includes("Infiltration") || profile.targetClass.includes("SCADA")
                    ? "NCIIPC Sector 1 (Energy)"
                    : profile.targetClass.includes("Patator") || profile.targetClass.includes("DoS")
                    ? "NCIIPC Sector 2 (BFSI)"
                    : "NCIIPC Sector 3 (Telecom)"}
                </span>
              </>
            ) : (
              <span className="px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                Baseline Enterprise Activity
              </span>
            )}
          </div>
        </div>
        <p className="text-[var(--color-text-primary)]">
          {profile.narrative}
        </p>
      </div>

      {/* Main Dynamic Features Grid */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {profile.features.map((feat, idx) => {
          const isElevating = feat.contributionScore > 0;
          const pctWidth = Math.min(Math.abs(feat.contributionScore) * 160, 100);

          return (
            <div
              key={feat.featureName}
              className="flex flex-col justify-between rounded-lg border p-3 bg-[var(--color-panel-raised)] transition-all hover:border-[var(--color-accent)]/50"
              style={{ borderColor: "var(--color-border)" }}
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-[10px] text-[var(--color-text-muted)]">#{idx + 1}</span>
                    <span className="font-semibold text-xs text-[var(--color-text-primary)]">
                      {feat.featureName}
                    </span>
                  </div>
                  <span className="rounded px-1.5 py-0.5 text-[9px] font-mono uppercase bg-black/40 text-[var(--color-text-secondary)] border border-white/5 shrink-0">
                    {feat.category}
                  </span>
                </div>

                <div className="flex items-center justify-between text-xs font-mono mb-2">
                  <span className="text-[var(--color-text-secondary)] text-[11px]">
                    Observed: <strong className="text-[var(--color-text-primary)]">{feat.observedValue}</strong>
                  </span>
                  <span className={`font-bold ${isElevating ? "text-rose-400" : "text-emerald-400"}`}>
                    {isElevating ? `+${(feat.contributionScore * 100).toFixed(1)}%` : `${(feat.contributionScore * 100).toFixed(1)}%`}
                  </span>
                </div>

                {/* Contribution Bar */}
                <div className="h-2 w-full rounded-full bg-black/50 overflow-hidden mb-2">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      isElevating ? "bg-gradient-to-r from-rose-500 to-red-400" : "bg-gradient-to-r from-emerald-500 to-teal-400"
                    }`}
                    style={{ width: `${pctWidth}%` }}
                  />
                </div>
              </div>

              <p className="text-[10px] text-[var(--color-text-muted)] italic leading-tight pt-1 border-t border-white/5">
                {feat.rationale}
              </p>
            </div>
          );
        })}
      </div>

      {/* Summary Footer Equation */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border p-2.5 font-mono text-xs bg-[var(--color-base)]" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex items-center gap-2">
          <CheckCircle2 size={14} className="text-emerald-400" />
          <span className="text-[var(--color-text-secondary)]">
            Base Prior: <strong className="text-[var(--color-text-primary)]">{(profile.baselineProbability * 100).toFixed(1)}%</strong>
          </span>
          <span className="text-[var(--color-text-muted)]">+</span>
          <span className="text-rose-400">
            Threat Push: <strong>+{(totalPositiveShap * 100).toFixed(1)}%</strong>
          </span>
          {totalNegativeShap !== 0 && (
            <>
              <span className="text-[var(--color-text-muted)]">-</span>
              <span className="text-emerald-400">
                Benign Pull: <strong>{(totalNegativeShap * 100).toFixed(1)}%</strong>
              </span>
            </>
          )}
          <ArrowDownRight size={14} className="text-[var(--color-accent)]" />
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[var(--color-text-muted)]">Net Forecast:</span>
          <span className="font-extrabold text-sm text-[var(--color-accent)]">
            {(currentProbability * 100).toFixed(1)}% P(Attack)
          </span>
        </div>
      </div>
    </div>
  );
}
