"""
ShieldNet Symbolic MITRE ATT&CK & CAPEC Knowledge-Graph Explainability Engine.

Implements a hand-authored, rule-based symbolic reasoning layer (Zero Opacity)
that links Axiomatic Feature Attributions (Integrated Gradients) to the
MITRE ATT&CK framework and CAPEC attack patterns.
"""

from typing import Dict, List, Any, Optional
import numpy as np

# Ground-truth MITRE ATT&CK & CAPEC Knowledge Graph
MITRE_KG_NODES = {
    # Tactics / Stages
    "TA0043": {
        "id": "TA0043",
        "name": "Reconnaissance",
        "stage": 1,
        "description": "Adversary is attempting to gather information to plan future operations.",
        "url": "https://attack.mitre.org/tactics/TA0043/"
    },
    "TA0001": {
        "id": "TA0001",
        "name": "Initial Access",
        "stage": 2,
        "description": "Adversary is attempting to gain entry into the network or host.",
        "url": "https://attack.mitre.org/tactics/TA0001/"
    },
    "TA0008": {
        "id": "TA0008",
        "name": "Lateral Movement",
        "stage": 3,
        "description": "Adversary is attempting to move through the environment to reach critical targets.",
        "url": "https://attack.mitre.org/tactics/TA0008/"
    },
    "TA0011": {
        "id": "TA0011",
        "name": "Command and Control",
        "stage": 4,
        "description": "Adversary is communicating with compromised systems to control them.",
        "url": "https://attack.mitre.org/tactics/TA0011/"
    },
    "TA0040": {
        "id": "TA0040",
        "name": "Impact",
        "stage": 5,
        "description": "Adversary is attempting to manipulate, interrupt, or destroy systems and data.",
        "url": "https://attack.mitre.org/tactics/TA0040/"
    },
    # Techniques
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "TA0043",
        "capec_id": "CAPEC-300",
        "capec_name": "Port Scanning",
        "precursors": ["tcp_window_min", "Flow IAT Mean", "SYN Flag Count"],
        "mitigation": "M1037: Filter Network Traffic"
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "TA0001",
        "capec_id": "CAPEC-112",
        "capec_name": "Brute Force Authentication",
        "precursors": ["Total Fwd Packets", "retransmission_count", "Flow Duration"],
        "mitigation": "M1036: Account Lockout & Rate Limiting"
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "TA0001",
        "capec_id": "CAPEC-63",
        "capec_name": "Cross-Site Scripting (XSS)",
        "precursors": ["Fwd Packet Length Mean", "Packet Length Variance"],
        "mitigation": "M1050: Exploit Protection & WAF"
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "TA0011",
        "capec_id": "CAPEC-588",
        "capec_name": "Periodic Command-and-Control Beaconing",
        "precursors": ["Flow IAT Std", "Bwd Packets/s", "Fwd IAT Mean"],
        "mitigation": "M1031: Network Intrusion Prevention"
    },
    "T1498": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "TA0040",
        "capec_id": "CAPEC-486",
        "capec_name": "HTTP / TCP Exhaustion Flood",
        "precursors": ["Flow Packets/s", "Flow Bytes/s", "Subflow Fwd Bytes"],
        "mitigation": "M1037: Ingress Rate-Limiting & Scrubbing"
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services / SCADA Infiltration",
        "tactic": "TA0008",
        "capec_id": "CAPEC-594",
        "capec_name": "SCADA/ICS Command Injection",
        "precursors": ["Destination Port", "Packet Length Std", "Flow Duration"],
        "mitigation": "M1030: Network Segmentation & Air-Gapping"
    }
}

CLASS_TO_TECHNIQUE = {
    "PortScan": "T1046",
    "FTP-Patator": "T1110",
    "SSH-Patator": "T1110",
    "Web Attack - Brute Force": "T1110",
    "Web Attack - XSS": "T1190",
    "Bot": "T1071",
    "DDoS": "T1498",
    "DoS GoldenEye": "T1498",
    "DoS Hulk": "T1498",
    "DoS Slowhttptest": "T1498",
    "DoS slowloris": "T1498",
    "Rare-Attack": "T1021",
    "Infiltration": "T1021",
    "Heartbleed": "T1190"
}

KILL_CHAIN_TRANSITIONS = {
    1: {"next_stage": 2, "progression_name": "Reconnaissance -> Initial Access", "risk_acceleration": "High"},
    2: {"next_stage": 3, "progression_name": "Initial Access -> Lateral Movement", "risk_acceleration": "Critical"},
    3: {"next_stage": 4, "progression_name": "Lateral Movement -> Command & Control", "risk_acceleration": "Critical"},
    4: {"next_stage": 5, "progression_name": "Command & Control -> Impact / Exfiltration", "risk_acceleration": "Severe"},
    5: {"next_stage": 5, "progression_name": "System Compromise / Service Disruption", "risk_acceleration": "Maximum"}
}


class SymbolicMitreReasoner:
    """
    Symbolic MITRE ATT&CK & CAPEC Knowledge-Graph Reasoning Engine.
    Converts raw statistical neural attributions into actionable, audit-ready forensic attack paths.
    """

    def __init__(self):
        self.nodes = MITRE_KG_NODES
        self.class_map = CLASS_TO_TECHNIQUE
        self.transitions = KILL_CHAIN_TRANSITIONS

    def explain_attack_progression(self,
                                   predicted_class: str,
                                   confidence: float,
                                   top_features: List[Dict[str, Any]],
                                   host_ip: str = "192.168.10.50",
                                   target_ip: str = "10.0.100.1",
                                   k_steps_ahead: int = 3) -> Dict[str, Any]:
        """
        Synthesizes a post-hoc symbolic explanation by combining:
        1. Numerical Integrated Gradients attributions
        2. Symbolic MITRE technique and CAPEC mappings
        3. Lifecycle transition dynamics
        """
        if predicted_class == "BENIGN":
            return {
                "status": "NORMAL",
                "narrative": f"Host {host_ip} is exhibiting stationary baseline telemetry consistent with normal enterprise network operations.",
                "mitre_technique": None,
                "mitre_tactic": "Normal Operations",
                "capec": None,
                "lifecycle_trajectory": "Stationary",
                "prescribed_mitigation": "Continue passive telemetry monitoring."
            }

        tech_id = self.class_map.get(predicted_class, "T1046")
        tech_info = self.nodes.get(tech_id, self.nodes["T1046"])
        tactic_id = tech_info["tactic"]
        tactic_info = self.nodes.get(tactic_id, self.nodes["TA0001"])
        stage_num = tactic_info["stage"]

        transition = self.transitions.get(stage_num, self.transitions[5])

        # Extract top driving precursor
        top_driver_name = top_features[0]["feature_name"] if top_features else "Flow IAT"
        top_driver_attr = top_features[0]["attribution_score"] if top_features else 0.0

        # Construct authoritative SOC forensic narrative
        narrative = (
            f"Host {host_ip} initiated activity targeting {target_ip} with precursor anomaly in '{top_driver_name}' "
            f"(Attribution: {top_driver_attr:+.3f}). The Neural World Model forecasts {tactic_info['name']} "
            f"via MITRE {tech_id} ({tech_info['name']}) with {confidence*100:.1f}% confidence. "
            f"Observed telemetry is consistent with {tech_info['capec_id']} ({tech_info['capec_name']}). "
            f"Forward dynamics project a progression from {transition['progression_name']} over the next +{k_steps_ahead*10}s."
        )

        return {
            "status": "THREAT_FORECAST",
            "host_ip": host_ip,
            "target_ip": target_ip,
            "predicted_class": predicted_class,
            "confidence": confidence,
            "mitre_stage_id": stage_num,
            "mitre_stage_name": tactic_info["name"],
            "mitre_tactic_id": tactic_id,
            "mitre_technique_id": tech_id,
            "mitre_technique_name": tech_info["name"],
            "mitre_url": f"https://attack.mitre.org/techniques/{tech_id}/",
            "capec_id": tech_info["capec_id"],
            "capec_name": tech_info["capec_name"],
            "lifecycle_transition": transition["progression_name"],
            "risk_acceleration": transition["risk_acceleration"],
            "top_driving_feature": top_driver_name,
            "attribution_magnitude": float(top_driver_attr),
            "prescribed_mitigation": tech_info["mitigation"],
            "forensic_narrative": narrative
        }
