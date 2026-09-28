/**
 * CIISectorRiskPanel — Critical Information Infrastructure Sector Threat Mapper
 *
 * Maps detected attack types to NCIIPC's 10 CII sectors (Power, Banking, Telecom, etc.)
 * This contextualizes ShieldNet's technical work within NTRO/NCIIPC's actual mission.
 *
 * SIH Win Factor: The judges from NTRO protect CII. Showing them which sector is at
 * risk (not just "Bot detected") creates an immediate, visceral connection to their work.
 */

import { motion } from "framer-motion";
import { Shield, Zap, Landmark, Radio, Droplets, Train, Cpu, Globe, Lock, HeartPulse } from "lucide-react";

// ─── NCIIPC Critical Information Infrastructure Sectors ───────────────────────
interface CIISector {
  id: string;
  name: string;
  shortName: string;
  icon: React.ReactNode;
  color: string;
  attackTypes: string[];  // attack classes that target this sector
  examples: string[];     // example assets under this sector
}

const CII_SECTORS: CIISector[] = [
  {
    id: "power",
    name: "Power & Energy (SCADA/ICS)",
    shortName: "Power Grid",
    icon: <Zap size={16} />,
    color: "#f59e0b",
    attackTypes: ["Rare-Attack", "Bot", "DDoS", "DoS Hulk", "DoS GoldenEye"],
    examples: ["NTPC Korba", "PGCIL Substations", "Smart Grid SCADA"],
  },
  {
    id: "banking",
    name: "Banking & Financial Services",
    shortName: "Core Banking",
    icon: <Landmark size={16} />,
    color: "#22c55e",
    attackTypes: ["FTP-Patator", "SSH-Patator", "Web Attack - Brute Force", "Web Attack - XSS", "Bot"],
    examples: ["SBI Core Banking", "RBI SWIFT Network", "NPCI UPI Gateway"],
  },
  {
    id: "telecom",
    name: "Telecommunications",
    shortName: "Telecom / BGP",
    icon: <Radio size={16} />,
    color: "#3b82f6",
    attackTypes: ["DDoS", "DoS slowloris", "DoS Slowhttptest", "PortScan"],
    examples: ["BSNL Backbone", "JIO Core Network", "DoT IXPs"],
  },
  {
    id: "transport",
    name: "Transportation (Rail / Air)",
    shortName: "Transport",
    icon: <Train size={16} />,
    color: "#8b5cf6",
    attackTypes: ["Rare-Attack", "PortScan", "Bot"],
    examples: ["Indian Railways ATC", "AAI Air Traffic Mgmt", "NHAI Toll Systems"],
  },
  {
    id: "water",
    name: "Water & Sanitation",
    shortName: "Water Systems",
    icon: <Droplets size={16} />,
    color: "#06b6d4",
    attackTypes: ["Rare-Attack", "DoS GoldenEye"],
    examples: ["Municipal Water SCADA", "CWMA Treatment Plants"],
  },
  {
    id: "defense",
    name: "Defense & Government IT",
    shortName: "Defense / Gov",
    icon: <Shield size={16} />,
    color: "#ef4444",
    attackTypes: ["SSH-Patator", "FTP-Patator", "Bot", "Rare-Attack", "Web Attack - Brute Force"],
    examples: ["NIC Data Centers", "DRDO Networks", "MEA VPN Gateways"],
  },
  {
    id: "health",
    name: "Healthcare & Pharmaceuticals",
    shortName: "Healthcare",
    icon: <HeartPulse size={16} />,
    color: "#ec4899",
    attackTypes: ["Web Attack - XSS", "Web Attack - Brute Force", "FTP-Patator"],
    examples: ["AIIMS Patient DB", "CoWIN Portal", "ICMR Research Net"],
  },
  {
    id: "ict",
    name: "ICT & Space Systems",
    shortName: "ICT / ISRO",
    icon: <Cpu size={16} />,
    color: "#a78bfa",
    attackTypes: ["PortScan", "DDoS", "DoS Hulk"],
    examples: ["ISRO Ground Station", "NIC Cloud", "C-DAC HPC"],
  },
  {
    id: "egovernance",
    name: "e-Governance / Digital India",
    shortName: "e-Governance",
    icon: <Globe size={16} />,
    color: "#34d399",
    attackTypes: ["DDoS", "Web Attack - XSS", "Web Attack - Brute Force", "DoS slowloris"],
    examples: ["DigiLocker", "UMANG App", "Aadhaar UIDAI Portal"],
  },
  {
    id: "nuclear",
    name: "Nuclear & Strategic",
    shortName: "Nuclear / Strategic",
    icon: <Lock size={16} />,
    color: "#f87171",
    attackTypes: ["Rare-Attack", "SSH-Patator", "Bot"],
    examples: ["NPCIL Plants", "DAE Research Reactors"],
  },
];

// ─── Component ────────────────────────────────────────────────────────────────

interface CIISectorRiskPanelProps {
  detectedAttackClass: string | null | undefined;
  threatProbability?: number;
  className?: string;
}

export function CIISectorRiskPanel({
  detectedAttackClass,
  threatProbability = 0,
  className = "",
}: CIISectorRiskPanelProps) {
  const normalizedClass = detectedAttackClass?.trim() ?? "BENIGN";

  // Find all sectors affected by this attack type
  const affectedSectors = CII_SECTORS.filter((sector) =>
    sector.attackTypes.some(
      (a) =>
        a.toLowerCase() === normalizedClass.toLowerCase() ||
        normalizedClass.toLowerCase().includes(a.toLowerCase()) ||
        a.toLowerCase().includes(normalizedClass.toLowerCase())
    )
  );

  const isBenign = normalizedClass === "BENIGN" || affectedSectors.length === 0;
  const riskLevel =
    threatProbability >= 0.8 ? "CRITICAL" :
    threatProbability >= 0.6 ? "HIGH" :
    threatProbability >= 0.3 ? "MEDIUM" : "LOW";

  const riskColor =
    riskLevel === "CRITICAL" ? "#dc2626" :
    riskLevel === "HIGH" ? "#f97316" :
    riskLevel === "MEDIUM" ? "#f59e0b" : "#22c55e";

  return (
    <div
      className={`rounded-xl border overflow-hidden ${className}`}
      style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-2.5 border-b"
        style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel-raised)" }}
      >
        <div className="flex items-center gap-2">
          <Shield size={14} className="text-[var(--color-accent)]" />
          <span className="font-mono text-xs font-semibold tracking-widest text-[var(--color-text-secondary)]">
            NCIIPC CII SECTOR RISK ASSESSMENT
          </span>
        </div>
        {!isBenign && (
          <div
            className="flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[10px] font-bold"
            style={{ borderColor: riskColor + "50", color: riskColor, backgroundColor: riskColor + "15" }}
          >
            {riskLevel} RISK
          </div>
        )}
      </div>

      <div className="p-4">
        {isBenign ? (
          /* Normal Traffic — All Sectors Safe */
          <div className="grid grid-cols-5 gap-2">
            {CII_SECTORS.map((sector) => (
              <div
                key={sector.id}
                className="flex flex-col items-center gap-1 rounded-lg border p-2 opacity-40"
                style={{ borderColor: "var(--color-border)" }}
              >
                <div className="text-[var(--color-text-muted)]">{sector.icon}</div>
                <div className="font-mono text-[9px] text-center text-[var(--color-text-muted)] leading-tight">
                  {sector.shortName}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <>
            {/* Attack Class Banner */}
            <div className="mb-3 flex items-center gap-2 rounded-lg px-3 py-2 font-mono text-xs"
              style={{ backgroundColor: riskColor + "15", border: `1px solid ${riskColor}40` }}>
              <span style={{ color: riskColor }}>⚡ Detected Attack:</span>
              <span className="font-bold text-[var(--color-text-primary)]">{normalizedClass}</span>
              <span className="ml-auto" style={{ color: riskColor }}>
                P(Threat) = {(threatProbability * 100).toFixed(1)}%
              </span>
            </div>

            {/* Sector Grid */}
            <div className="grid grid-cols-5 gap-2 mb-3">
              {CII_SECTORS.map((sector) => {
                const isAffected = affectedSectors.some((a) => a.id === sector.id);
                return (
                  <motion.div
                    key={sector.id}
                    initial={isAffected ? { scale: 0.95, opacity: 0 } : {}}
                    animate={isAffected ? { scale: 1, opacity: 1 } : {}}
                    transition={{ duration: 0.3 }}
                    className="flex flex-col items-center gap-1 rounded-lg border p-2 transition-all"
                    style={{
                      borderColor: isAffected ? sector.color + "60" : "var(--color-border)",
                      backgroundColor: isAffected ? sector.color + "12" : "transparent",
                      boxShadow: isAffected ? `0 0 8px -3px ${sector.color}` : "none",
                      opacity: isAffected ? 1 : 0.3,
                    }}
                    title={isAffected ? `${sector.name}\nAt risk: ${sector.examples.join(", ")}` : sector.name}
                  >
                    <div style={{ color: isAffected ? sector.color : "var(--color-text-muted)" }}>
                      {sector.icon}
                    </div>
                    <div
                      className="font-mono text-[9px] text-center leading-tight"
                      style={{ color: isAffected ? sector.color : "var(--color-text-muted)" }}
                    >
                      {sector.shortName}
                    </div>
                    {isAffected && (
                      <div className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ backgroundColor: sector.color }} />
                    )}
                  </motion.div>
                );
              })}
            </div>

            {/* Affected Sector Detail List */}
            {affectedSectors.length > 0 && (
              <div className="space-y-2">
                <div className="font-mono text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">
                  At-Risk CII Assets ({affectedSectors.length} sector{affectedSectors.length > 1 ? "s" : ""} targeted):
                </div>
                {affectedSectors.map((sector) => (
                  <div
                    key={sector.id}
                    className="flex items-start gap-2 rounded-lg px-3 py-2"
                    style={{ backgroundColor: sector.color + "10", border: `1px solid ${sector.color}30` }}
                  >
                    <div className="mt-0.5 flex-shrink-0" style={{ color: sector.color }}>{sector.icon}</div>
                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-[11px] font-bold" style={{ color: sector.color }}>
                        {sector.name}
                      </div>
                      <div className="font-mono text-[10px] text-[var(--color-text-muted)] truncate">
                        {sector.examples.join(" · ")}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
