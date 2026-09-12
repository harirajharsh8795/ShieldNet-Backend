import { motion, AnimatePresence } from "framer-motion";
import { Radar, LogIn, Shuffle, Radio, Upload } from "lucide-react";
import type { MitreStage } from "../data/types";

const STAGE_CONFIG: Record<
  MitreStage,
  { color: string; icon: typeof Radar; label: string }
> = {
  Reconnaissance: { color: "var(--color-mitre-recon)", icon: Radar, label: "Reconnaissance" },
  "Initial Access": { color: "var(--color-mitre-initial)", icon: LogIn, label: "Initial Access" },
  "Lateral Movement": { color: "var(--color-mitre-lateral)", icon: Shuffle, label: "Lateral Movement" },
  "Command & Control": { color: "var(--color-mitre-c2)", icon: Radio, label: "Command & Control" },
  Exfiltration: { color: "var(--color-mitre-exfil)", icon: Upload, label: "Exfiltration" },
};

interface MITREStageBadgeProps {
  stage: MitreStage;
  size?: "sm" | "lg";
}

export function MITREStageBadge({ stage, size = "sm" }: MITREStageBadgeProps) {
  const config = STAGE_CONFIG[stage];
  const Icon = config.icon;
  const isLarge = size === "lg";

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={stage}
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -4 }}
        transition={{ duration: 0.35, ease: "easeOut" }}
        className={`inline-flex items-center gap-2 rounded-md border font-mono ${
          isLarge ? "px-4 py-2 text-sm" : "px-2.5 py-1 text-xs"
        }`}
        style={{
          borderColor: config.color,
          backgroundColor: `color-mix(in srgb, ${config.color} 14%, transparent)`,
          color: config.color,
        }}
      >
        <motion.span
          key={`${stage}-icon`}
          animate={{ backgroundColor: config.color }}
          transition={{ duration: 0.4 }}
          className="flex items-center justify-center rounded-full"
          style={{ width: isLarge ? 22 : 16, height: isLarge ? 22 : 16 }}
        >
          <Icon size={isLarge ? 14 : 10} color="var(--color-base)" strokeWidth={2.5} />
        </motion.span>
        <span className="uppercase tracking-wide">{config.label}</span>
      </motion.div>
    </AnimatePresence>
  );
}

export const MITRE_STAGE_ORDER: MitreStage[] = [
  "Reconnaissance",
  "Initial Access",
  "Lateral Movement",
  "Command & Control",
  "Exfiltration",
];

export function getMitreStageColor(stage: MitreStage): string {
  return STAGE_CONFIG[stage].color;
}
