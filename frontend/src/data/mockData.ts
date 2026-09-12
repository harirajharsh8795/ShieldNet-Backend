// Realistic sample data for the "CIC-IDS-2018 demo" sample dataset path.
// This is the ONLY file allowed to fabricate data — everything else reads
// through src/data/api.ts. Nothing here is real network traffic.

import type {
  Ingestion,
  TimeWindow,
  Prediction,
  Explanation,
  FlaggedFlow,
  ModelRun,
  TimelinePoint,
  MitreStage,
  Severity,
} from "./types";

const SAMPLE_INGESTION_ID = "ing_sample_cicids2018";

export const mockIngestion: Ingestion = {
  id: SAMPLE_INGESTION_ID,
  sourceType: "csv",
  filename: "cicids2018_sample_capture.csv",
  datasetName: "cic-ids-2018",
  uploadedAt: "2026-08-20T09:12:00Z",
  status: "ready",
};

// 30 historical windows (observed, kStepOffset = 0) + 10 forward-simulated
// windows (kStepOffset 1..10), rising toward Lateral Movement — matches the
// spec's "believable rising trajectory" requirement.
const WINDOW_SECONDS = 10;
const BASE_TIME = new Date("2026-08-20T09:00:00Z").getTime();
const TOTAL_OBSERVED = 30;
const K_STEPS = 10;

function stageForProbability(p: number): MitreStage {
  if (p < 0.15) return "Reconnaissance";
  if (p < 0.35) return "Initial Access";
  if (p < 0.6) return "Lateral Movement";
  if (p < 0.8) return "Command & Control";
  return "Exfiltration";
}

export const mockTimeWindows: TimeWindow[] = [];
export const mockPredictions: Prediction[] = [];
export const mockTimeline: TimelinePoint[] = [];

{
  // Observed portion: gentle noisy climb from ~0.05 to ~0.42
  let prob = 0.05;
  for (let i = 0; i < TOTAL_OBSERVED; i++) {
    const windowStart = new Date(BASE_TIME + i * WINDOW_SECONDS * 1000);
    const windowEnd = new Date(windowStart.getTime() + WINDOW_SECONDS * 1000);
    const windowId = `win_${i.toString().padStart(3, "0")}`;
    const predictionId = `pred_${i.toString().padStart(3, "0")}`;

    // Climb with noise, small dips allowed but overall upward drift
    const drift = 0.013 + Math.sin(i / 4) * 0.004;
    prob = Math.min(0.42, Math.max(0.02, prob + drift + (Math.random() - 0.5) * 0.01));

    mockTimeWindows.push({ id: windowId, ingestionId: SAMPLE_INGESTION_ID, windowStart: windowStart.toISOString(), windowEnd: windowEnd.toISOString() });

    const stage = stageForProbability(prob);
    mockPredictions.push({
      id: predictionId,
      windowId,
      infiltrationProbability: Number(prob.toFixed(3)),
      predictedMitreStage: stage,
      kStepOffset: 0,
      modelVersion: "lstm-v1.3.0",
    });

    mockTimeline.push({
      timestamp: windowStart.toISOString(),
      kStepOffset: 0,
      infiltrationProbability: Number(prob.toFixed(3)),
      predictedMitreStage: stage,
      predictionId,
      isProjection: false,
    });
  }

  // Forward-simulated (K-step rollout) portion: continues climbing toward
  // Lateral Movement / early C2, confidence-decay is rendered client-side by
  // KStepProjection based on kStepOffset, not encoded in the data itself.
  let lastTime = BASE_TIME + TOTAL_OBSERVED * WINDOW_SECONDS * 1000;
  for (let k = 1; k <= K_STEPS; k++) {
    const windowStart = new Date(lastTime + k * WINDOW_SECONDS * 1000);
    const windowId = `win_proj_${k}`;
    const predictionId = `pred_proj_${k}`;

    prob = Math.min(0.93, prob + 0.028 + (Math.random() - 0.5) * 0.006);
    const stage = stageForProbability(prob);

    mockPredictions.push({
      id: predictionId,
      windowId,
      infiltrationProbability: Number(prob.toFixed(3)),
      predictedMitreStage: stage,
      kStepOffset: k,
      modelVersion: "lstm-v1.3.0",
    });

    mockTimeline.push({
      timestamp: windowStart.toISOString(),
      kStepOffset: k,
      infiltrationProbability: Number(prob.toFixed(3)),
      predictedMitreStage: stage,
      predictionId,
      isProjection: true,
    });
  }
}

// The prediction the Explainability panel opens against by default —
// the most recent observed (non-projected) point.
export const mockDefaultPredictionId =
  mockPredictions.filter((p) => p.kStepOffset === 0).slice(-1)[0].id;

const FEATURE_POOL: string[] = [
  "SYN packet rate",
  "Unusual destination port sequence",
  "Inter-arrival time variance",
  "TTL variance",
  "Backward/forward flow byte ratio",
  "Retransmission count",
  "TCP window size delta",
  "Flow duration (short-lived bursts)",
  "Fragmented packet flag rate",
  "Destination IP fan-out",
];

function explanationsFor(predictionId: string, seed: number): Explanation[] {
  const shuffled = [...FEATURE_POOL].sort((a, b) => {
    const ha = (a.length * 31 + seed) % 97;
    const hb = (b.length * 31 + seed) % 97;
    return ha - hb;
  });
  const top5 = shuffled.slice(0, 5);
  const scores = [0.34, 0.24, 0.18, 0.13, 0.08].map(
    (base, i) => base + (((seed + i) % 7) - 3) * 0.01
  );
  return top5.map((featureName, i) => ({
    id: `exp_${predictionId}_${i}`,
    predictionId,
    featureName,
    contributionScore: Number(scores[i].toFixed(3)),
    rank: i + 1,
  }));
}

export const mockExplanations: Record<string, Explanation[]> = Object.fromEntries(
  mockPredictions.map((p, idx) => [p.id, explanationsFor(p.id, idx)])
);

const PROTOCOLS: FlaggedFlow["protocol"][] = ["TCP", "UDP", "ICMP"];

function randomIp(prefix: string): string {
  return `${prefix}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`;
}

const COMMON_PORTS = [22, 23, 80, 443, 445, 3389, 8080, 3306, 53, 21];

export const mockFlaggedFlows: FlaggedFlow[] = Array.from({ length: 18 }, (_, i) => {
  const windowIdx = Math.min(TOTAL_OBSERVED - 1, Math.floor(i * (TOTAL_OBSERVED / 18)));
  const severity =
    i > 14 ? "critical" : i > 10 ? "elevated" : i > 5 ? "watch" : ("normal" as Severity);
  return {
    id: `flow_${i.toString().padStart(3, "0")}`,
    windowId: `win_${windowIdx.toString().padStart(3, "0")}`,
    srcIp: randomIp("10.42"),
    dstIp: randomIp("172.16"),
    srcPort: 1024 + Math.floor(Math.random() * 40000),
    dstPort: COMMON_PORTS[i % COMMON_PORTS.length],
    protocol: PROTOCOLS[i % PROTOCOLS.length],
    severity,
  };
});

export const mockModelRuns: ModelRun[] = [
  {
    id: "run_lstm_v1",
    modelType: "lstm",
    trainedAt: "2026-08-18T14:30:00Z",
    f1Score: 0.912,
    precision: 0.897,
    recall: 0.928,
    falsePositiveRate: 0.041,
    datasetUsed: "cic-ids-2018",
  },
  {
    id: "run_baseline_lr",
    modelType: "baseline_lr",
    trainedAt: "2026-08-17T11:05:00Z",
    f1Score: 0.783,
    precision: 0.771,
    recall: 0.796,
    falsePositiveRate: 0.089,
    datasetUsed: "cic-ids-2018",
  },
];
