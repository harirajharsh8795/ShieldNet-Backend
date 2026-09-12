import type { Explanation } from "./types";

export interface ScenarioShapProfile {
  scenarioId: string;
  name: string;
  targetClass: string;
  narrative: string;
  baselineProbability: number;
  forecastProbability: number;
  features: Array<{
    featureName: string;
    category: "Timing" | "Payload" | "TCP Flags" | "Volume" | "Entropy" | "Protocol";
    observedValue: string;
    contributionScore: number; // Positive = pushes to attack, Negative = pushes to benign
    impact: "elevates_threat" | "reduces_threat";
    rationale: string;
  }>;
}

export const SCENARIO_SHAP_PROFILES: Record<string, ScenarioShapProfile> = {
  // 1. Botnet Ares C2 Heartbeat (CTU-13 / CIC-IDS2017)
  sess_bot_c2: {
    scenarioId: "sess_bot_c2",
    name: "Botnet Ares C2 Periodic Heartbeat",
    targetClass: "Bot",
    narrative: "Extremely low timing jitter (Flow IAT Std = 0.042s) combined with uniform reverse-shell payload sizes (284.5 B) matches Ares/Mirai C2 beaconing signatures.",
    baselineProbability: 0.04,
    forecastProbability: 0.94,
    features: [
      {
        featureName: "Flow IAT Std (Periodic Heartbeat Jitter)",
        category: "Timing",
        observedValue: "0.042 s",
        contributionScore: 0.428,
        impact: "elevates_threat",
        rationale: "Clock-work periodic beaconing eliminates human browsing behavior.",
      },
      {
        featureName: "Bwd Packet Length Mean",
        category: "Payload",
        observedValue: "284.5 Bytes",
        contributionScore: 0.315,
        impact: "elevates_threat",
        rationale: "Fixed-size reverse-shell telemetry matches automated Ares bot agent.",
      },
      {
        featureName: "SYN / ACK Asymmetry Ratio",
        category: "TCP Flags",
        observedValue: "1.00",
        contributionScore: 0.162,
        impact: "elevates_threat",
        rationale: "Single persistent outbound connection without typical web renegotiations.",
      },
      {
        featureName: "Destination Port Entropy",
        category: "Entropy",
        observedValue: "0.12 (Pinned to 8080)",
        contributionScore: -0.085,
        impact: "reduces_threat",
        rationale: "Traffic confined to single port, slightly dampens multi-port sweep suspicion.",
      },
    ],
  },

  // 2. SSH / FTP Patator Brute Force
  sess_ssh_patator: {
    scenarioId: "sess_ssh_patator",
    name: "SSH-Patator Automated Credential Brute Force",
    targetClass: "SSH-Patator",
    narrative: "Surge in high-frequency connection attempts targeting port 22 with uniform micro-durations (0.012s) and elevated FIN/RST flags.",
    baselineProbability: 0.03,
    forecastProbability: 0.96,
    features: [
      {
        featureName: "Flow Count to Port 22 (Velocity)",
        category: "Volume",
        observedValue: "68 flows / 10s",
        contributionScore: 0.465,
        impact: "elevates_threat",
        rationale: "Massive authentication attempt velocity exceeding human interaction limits.",
      },
      {
        featureName: "Flow Duration Std (Micro-bursts)",
        category: "Timing",
        observedValue: "0.012 s",
        contributionScore: 0.290,
        impact: "elevates_threat",
        rationale: "Identical short session duration indicates automated script teardown on bad password.",
      },
      {
        featureName: "FIN / RST Flag Aggregation",
        category: "TCP Flags",
        observedValue: "68 resets",
        contributionScore: 0.185,
        impact: "elevates_threat",
        rationale: "Continuous abnormal termination after single-handshake password spray.",
      },
      {
        featureName: "Payload Entropy (ASCII Credentials)",
        category: "Entropy",
        observedValue: "0.82",
        contributionScore: -0.062,
        impact: "reduces_threat",
        rationale: "Standard plaintext dictionary authentication prevents shellcode signature triggers.",
      },
    ],
  },

  // 3. Volumetric DoS Hulk / LOIC Flood
  sess_dos_hulk: {
    scenarioId: "sess_dos_hulk",
    name: "Volumetric DDoS Hulk HTTP Flood",
    targetClass: "DoS Hulk",
    narrative: "Surging network byte velocity (>4.8 MB/s) with extreme forward packet bursts exhausting web server socket pools.",
    baselineProbability: 0.05,
    forecastProbability: 0.99,
    features: [
      {
        featureName: "Flow Bytes / s Rate",
        category: "Volume",
        observedValue: "4.82 MB/s",
        contributionScore: 0.495,
        impact: "elevates_threat",
        rationale: "Unprecedented bandwidth surge overwhelming server network buffers.",
      },
      {
        featureName: "Fwd Packets / s (Surge Flood)",
        category: "Volume",
        observedValue: "3,820 pkts/s",
        contributionScore: 0.360,
        impact: "elevates_threat",
        rationale: "Continuous request stream with zero client processing delays.",
      },
      {
        featureName: "PSH Flag Count",
        category: "TCP Flags",
        observedValue: "980 pkts",
        contributionScore: 0.140,
        impact: "elevates_threat",
        rationale: "Aggressive push flags forcing immediate TCP stack queue processing.",
      },
      {
        featureName: "Flow IAT Mean (Sub-millisecond)",
        category: "Timing",
        observedValue: "0.0002 s",
        contributionScore: 0.095,
        impact: "elevates_threat",
        rationale: "Micro-second inter-arrival times confirm automated bot flood.",
      },
    ],
  },

  // 4. CII SCADA / Modbus Infiltration
  "session-scada-grid-exfiltration": {
    scenarioId: "session-scada-grid-exfiltration",
    name: "Critical Infrastructure Modbus SCADA Infiltration",
    targetClass: "Infiltration",
    narrative: "Unauthorized coil register write bursts targeting industrial PLCs over Port 502 with anomalous subnet lateral traversal.",
    baselineProbability: 0.08,
    forecastProbability: 0.95,
    features: [
      {
        featureName: "Modbus Function Code 0x05 / 0x0F Write Bursts",
        category: "Protocol",
        observedValue: "142 writes / 10s",
        contributionScore: 0.440,
        impact: "elevates_threat",
        rationale: "Direct actuator manipulation without corresponding HMI operator confirmation.",
      },
      {
        featureName: "Internal Subnet Fan-Out Degree",
        category: "Entropy",
        observedValue: "8 Substation PLCs",
        contributionScore: 0.320,
        impact: "elevates_threat",
        rationale: "Adversary actively pivoting across OT VLAN boundaries.",
      },
      {
        featureName: "Payload Length Variance",
        category: "Payload",
        observedValue: "48.2 Bytes (Fixed)",
        contributionScore: 0.175,
        impact: "elevates_threat",
        rationale: "Deterministic ICS control frame signature.",
      },
      {
        featureName: "TCP Window Size Stability",
        category: "TCP Flags",
        observedValue: "64240 B",
        contributionScore: -0.055,
        impact: "reduces_threat",
        rationale: "Clean socket window sizing avoids generic network degradation flags.",
      },
    ],
  },

  // 5. PortScan Reconnaissance
  sess_portscan_recon: {
    scenarioId: "sess_portscan_recon",
    name: "Horizontal Multi-Port SYN Reconnaissance",
    targetClass: "PortScan",
    narrative: "High destination port entropy (2.84) across ports 21, 22, 80, 443 with 0 ACK handshakes confirms active network mapping.",
    baselineProbability: 0.02,
    forecastProbability: 0.88,
    features: [
      {
        featureName: "Destination Port Entropy",
        category: "Entropy",
        observedValue: "2.84",
        contributionScore: 0.445,
        impact: "elevates_threat",
        rationale: "Rapid sequential port hopping across multiple services.",
      },
      {
        featureName: "SYN Without ACK Response Rate",
        category: "TCP Flags",
        observedValue: "42 pkts/s",
        contributionScore: 0.340,
        impact: "elevates_threat",
        rationale: "Half-open scanning without completing TCP 3-way handshakes.",
      },
      {
        featureName: "Flow Duration (Micro-Probes)",
        category: "Timing",
        observedValue: "0.002 s",
        contributionScore: 0.150,
        impact: "elevates_threat",
        rationale: "Zero-data probe packets terminated immediately.",
      },
      {
        featureName: "Average Packet Length (Small Headers)",
        category: "Payload",
        observedValue: "44 Bytes",
        contributionScore: -0.070,
        impact: "reduces_threat",
        rationale: "Minimal packet footprint slightly suppresses volumetric alert thresholds.",
      },
    ],
  },

  // 6. Normal Enterprise Workstation Baseline
  sess_benign_normal: {
    scenarioId: "sess_benign_normal",
    name: "Normal Enterprise Workstation Baseline",
    targetClass: "BENIGN",
    narrative: "Standard corporate HTTPS TLS 1.3 handshakes, balanced packet transfers, normal human timing jitter, and zero anomalous TCP flags.",
    baselineProbability: 0.02,
    forecastProbability: 0.02,
    features: [
      {
        featureName: "Balanced SYN / ACK Handshake Ratio",
        category: "TCP Flags",
        observedValue: "1.01",
        contributionScore: -0.410,
        impact: "reduces_threat",
        rationale: "Clean 3-way handshakes completed for all network connections.",
      },
      {
        featureName: "Standard HTTPS TLS 1.3 Port 443",
        category: "Protocol",
        observedValue: "TLS 1.3 Handshake",
        contributionScore: -0.315,
        impact: "reduces_threat",
        rationale: "Authorized business traffic to trusted cloud CDNs.",
      },
      {
        featureName: "Flow Inter-Arrival Time Jitter",
        category: "Timing",
        observedValue: "0.420 s",
        contributionScore: -0.240,
        impact: "reduces_threat",
        rationale: "Natural human web browsing intervals with expected variation.",
      },
      {
        featureName: "Zero TCP Reset Anomalies",
        category: "TCP Flags",
        observedValue: "0.0 resets",
        contributionScore: -0.125,
        impact: "reduces_threat",
        rationale: "No dropped packets, firewall rejections, or abnormal terminations.",
      },
    ],
  },
};

/**
 * Resolves dynamic SHAP profile for any session ID or uploaded file name.
 */
export function getDynamicShapProfile(sessionId?: string, filename?: string): ScenarioShapProfile {
  if (sessionId && SCENARIO_SHAP_PROFILES[sessionId]) {
    return SCENARIO_SHAP_PROFILES[sessionId];
  }

  const clean = ((sessionId || "") + " " + (filename || "")).toLowerCase();
  if (clean.includes("ddos") || clean.includes("hulk") || clean.includes("flood") || clean.includes("dos")) {
    return SCENARIO_SHAP_PROFILES.sess_dos_hulk;
  }
  if (clean.includes("bot") || clean.includes("ares") || clean.includes("ctu") || clean.includes("c2")) {
    return SCENARIO_SHAP_PROFILES.sess_bot_c2;
  }
  if (clean.includes("patator") || clean.includes("ssh") || clean.includes("ftp") || clean.includes("brute")) {
    return SCENARIO_SHAP_PROFILES.sess_ssh_patator;
  }
  if (clean.includes("scada") || clean.includes("grid") || clean.includes("infil") || clean.includes("modbus") || clean.includes("cii")) {
    return SCENARIO_SHAP_PROFILES["session-scada-grid-exfiltration"];
  }
  if (clean.includes("benign") || clean.includes("normal") || clean.includes("baseline")) {
    return SCENARIO_SHAP_PROFILES.sess_benign_normal;
  }
  if (clean.includes("portscan") || clean.includes("recon") || clean.includes("probe")) {
    return SCENARIO_SHAP_PROFILES.sess_portscan_recon;
  }

  return SCENARIO_SHAP_PROFILES.sess_bot_c2;
}

/**
 * Converts profile features into standard Explanation[] array for SHAPBarChart.
 */
export function profileToExplanations(profile: ScenarioShapProfile, predictionId: string): Explanation[] {
  return profile.features.map((f, idx) => ({
    id: `exp_${profile.scenarioId}_${idx}`,
    predictionId,
    featureName: f.featureName,
    contributionScore: f.contributionScore,
    rank: idx + 1,
  }));
}
