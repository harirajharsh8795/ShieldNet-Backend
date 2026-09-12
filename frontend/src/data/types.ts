// Types mirror the backend schema (Section 8, ShieldNet spec) exactly so a real
// API can be swapped in behind src/data/api.ts with zero changes to components.

export type SourceType = "csv" | "pcap";
export type DatasetName = "cic-ids-2018" | "ctu-13" | "custom";
export type IngestionStatus =
  | "uploading"
  | "validating"
  | "extracting_features"
  | "sequencing"
  | "ready"
  | "failed";

export interface Ingestion {
  id: string;
  sourceType: SourceType;
  filename: string;
  datasetName: DatasetName;
  uploadedAt: string; // ISO timestamp
  status: IngestionStatus;
  fileSize?: string;
  flowCount?: number;
  extractedFeatures?: number;
  matchedScenarioId?: string;
}

export interface TimeWindow {
  id: string;
  ingestionId: string;
  windowStart: string; // ISO timestamp
  windowEnd: string; // ISO timestamp
}

export type MitreStage =
  | "Reconnaissance"
  | "Initial Access"
  | "Lateral Movement"
  | "Command & Control"
  | "Exfiltration";

export interface Prediction {
  id: string;
  windowId: string;
  infiltrationProbability: number; // 0..1
  predictedMitreStage: MitreStage;
  kStepOffset: number; // 0 = observed/current, >0 = forward-simulated step
  modelVersion: string;
}

export interface Explanation {
  id: string;
  predictionId: string;
  featureName: string;
  contributionScore: number; // signed SHAP-style contribution
  rank: number;
}

export type Severity = "normal" | "watch" | "elevated" | "critical";

export interface FlaggedFlow {
  id: string;
  windowId: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: "TCP" | "UDP" | "ICMP";
  severity: Severity;
}

export type ModelType = "lstm" | "transformer" | "gnn" | "baseline_lr";

export interface ModelRun {
  id: string;
  modelType: ModelType;
  trainedAt: string; // ISO timestamp
  f1Score: number;
  precision: number;
  recall: number;
  falsePositiveRate: number;
  datasetUsed: DatasetName;
}

// Chart-ready timeline point combining a prediction with its window timestamp.
export interface TimelinePoint {
  timestamp: string; // ISO timestamp
  kStepOffset: number;
  infiltrationProbability: number;
  predictedMitreStage: MitreStage;
  predictionId: string;
  isProjection: boolean; // true for k_step_offset > 0 (forward-simulated / "ghosted")
}

