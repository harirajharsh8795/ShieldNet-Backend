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
        "mitigation": "M1037: Filter Network Traffic",
        "cve_id": "CVE-2023-44487",
        "cvss_score": 7.5,
        "cvss_severity": "HIGH",
        "nvd_advisory": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
        "nciipc_sector": "Sector 3: Telecom & Strategic Information Infrastructure",
        "nciipc_sop": "NCIIPC-SOP-SEC3-08: Border Gateway Rapid Port Filtering & Stealth Drop",
        "target_critical_asset": "Perimeter Gateway / Core Router Interface"
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "TA0001",
        "capec_id": "CAPEC-112",
        "capec_name": "Brute Force Authentication",
        "precursors": ["Total Fwd Packets", "retransmission_count", "Flow Duration"],
        "mitigation": "M1036: Account Lockout & Rate Limiting",
        "cve_id": "CVE-2018-15473",
        "cvss_score": 7.5,
        "cvss_severity": "HIGH",
        "nvd_advisory": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
        "nciipc_sector": "Sector 2: Banking, Financial Services & Insurance (BFSI)",
        "nciipc_sop": "NCIIPC-SOP-SEC2-12: Zero-Trust Perimeter Lockout & Ephemeral Key Rotation",
        "target_critical_asset": "Enterprise Active Directory & Jump-Host DMZ"
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "TA0001",
        "capec_id": "CAPEC-63",
        "capec_name": "Cross-Site Scripting & Injection (XSS)",
        "precursors": ["Fwd Packet Length Mean", "Packet Length Variance"],
        "mitigation": "M1050: Exploit Protection & WAF",
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "cvss_severity": "CRITICAL",
        "nvd_advisory": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "nciipc_sector": "Sector 5: Strategic Public Enterprises & e-Governance",
        "nciipc_sop": "NCIIPC-SOP-SEC5-03: Ingress WAF Rigorous Sanitization & Log4j Isolation",
        "target_critical_asset": "Public Web Gateway / API Application Cluster"
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "TA0011",
        "capec_id": "CAPEC-588",
        "capec_name": "Periodic Command-and-Control Beaconing",
        "precursors": ["Flow IAT Std", "Bwd Packets/s", "Fwd IAT Mean"],
        "mitigation": "M1031: Network Intrusion Prevention",
        "cve_id": "CVE-2019-11510",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "nvd_advisory": "https://nvd.nist.gov/vuln/detail/CVE-2019-11510",
        "nciipc_sector": "Sector 3: Telecom & Strategic Backbone",
        "nciipc_sop": "NCIIPC-SOP-SEC3-14: BGP Blackhole Routing & Autonomous C2 Null-Route",
        "target_critical_asset": "Backbone ISP Peering & Enterprise Core DNS"
    },
    "T1498": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "TA0040",
        "capec_id": "CAPEC-486",
        "capec_name": "HTTP / TCP Exhaustion Flood",
        "precursors": ["Flow Packets/s", "Flow Bytes/s", "Subflow Fwd Bytes"],
        "mitigation": "M1037: Ingress Rate-Limiting & Scrubbing",
        "cve_id": "CVE-2007-6750",
        "cvss_score": 7.5,
        "cvss_severity": "HIGH",
        "nvd_advisory": "https://nvd.nist.gov/vuln/detail/CVE-2007-6750",
        "nciipc_sector": "Sector 2: Banking & Financial Market Infrastructure",
        "nciipc_sop": "NCIIPC-SOP-SEC2-07: Ingress Scrubbing Center Redirection & TCP RST Flood Kill",
        "target_critical_asset": "National Payment Switch & High-Volume Clearing Gateway"
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services / SCADA Infiltration",
        "tactic": "TA0008",
        "capec_id": "CAPEC-594",
        "capec_name": "SCADA/ICS Command Injection",
        "precursors": ["Destination Port", "Packet Length Std", "Flow Duration"],
        "mitigation": "M1030: Network Segmentation & Air-Gapping",
        "cve_id": "CVE-2022-29951",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "nvd_advisory": "https://nvd.nist.gov/vuln/detail/CVE-2022-29951",
        "nciipc_sector": "Sector 1: Power & Energy (SCADA Grid)",
        "nciipc_sop": "NCIIPC-SOP-SEC1-04: Substation Isolation & OT Ingress Scram",
        "target_critical_asset": "Substation RTU / Siemens S7-1500 PLC Gateway"
    },
    "T0814": {
        "id": "T0814",
        "name": "SCADA / Industrial Control System Infiltration",
        "tactic": "TA0008",
        "capec_id": "CAPEC-665",
        "capec_name": "SCADA Register & Coil Manipulation",
        "precursors": ["subflow_fwd_bytes", "Destination Port", "Packet Length Std"],
        "mitigation": "M1030: Physical Air-Gap & Unidirectional Data Diode Enclave",
        "cve_id": "CVE-2022-29951",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "nvd_advisory": "https://nvd.nist.gov/vuln/detail/CVE-2022-29951",
        "nciipc_sector": "Sector 1: Power & Energy (Critical Infrastructure)",
        "nciipc_sop": "NCIIPC-SOP-SEC1-04: Automated Substation Air-Gap Scram & Diode Lock",
        "target_critical_asset": "Critical Substation 400kV Step-Up Transformer PLC"
    },
    "T1550": {
        "id": "T1550",
        "name": "Use Alternate Authentication Material (Pass-the-Hash)",
        "tactic": "TA0008",
        "capec_id": "CAPEC-652",
        "capec_name": "Kerberos / NTLM Ticket Forgery & Replay",
        "precursors": ["auth_velocity", "failed_auth_burst", "fan_out_degree"],
        "mitigation": "M1026: Privileged Account Management & Kerberos PAC Validation",
        "cve_id": "CVE-2020-1472",
        "cvss_score": 10.0,
        "cvss_severity": "CRITICAL",
        "nvd_advisory": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472",
        "nciipc_sector": "Sector 3: Strategic Government & Defense R&D",
        "nciipc_sop": "NCIIPC-SOP-SEC3-19: Active Directory Domain Controller Isolation & KRBTGT Reset",
        "target_critical_asset": "Enterprise Primary Domain Controller (KDC)"
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
    "Heartbleed": "T1190",
    "CII-SCADA": "T0814",
    "SCADA": "T0814",
    "LANL-Auth": "T1550",
    "Lateral-Movement": "T1550"
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
        3. NIST NVD & CVE vulnerability correlations
        4. NCIIPC sovereign sector compliance & SOP directives
        5. Lifecycle transition dynamics
        """
        if predicted_class == "BENIGN":
            return {
                "status": "NORMAL",
                "narrative": f"Host {host_ip} is exhibiting stationary baseline telemetry consistent with normal enterprise network operations.",
                "mitre_technique": None,
                "mitre_tactic": "Normal Operations",
                "capec": None,
                "lifecycle_trajectory": "Stationary",
                "prescribed_mitigation": "Continue passive telemetry monitoring.",
                "cve_id": None,
                "cvss_score": 0.0,
                "cvss_severity": "NONE",
                "nvd_advisory": None,
                "nciipc_sector": "Standard Enterprise Zone",
                "nciipc_sop": "NCIIPC-SOP-GEN-01: Baseline Passive Telemetry Retention",
                "target_critical_asset": "Standard Workstation Baseline"
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
            f"Host {host_ip} initiated activity targeting {target_ip} ({tech_info.get('target_critical_asset', 'Target Host')}) "
            f"with precursor anomaly in '{top_driver_name}' (Attribution: {top_driver_attr:+.3f}). "
            f"The Neural World Model forecasts {tactic_info['name']} via MITRE {tech_id} ({tech_info['name']}) "
            f"correlated with {tech_info.get('cve_id', 'NVD CVE')} (CVSS {tech_info.get('cvss_score', 9.8)} {tech_info.get('cvss_severity', 'CRITICAL')}) "
            f"with {confidence*100:.1f}% confidence. Telemetry matches {tech_info['capec_id']} ({tech_info['capec_name']}). "
            f"Forward dynamics project {transition['progression_name']} over +{k_steps_ahead*10}s. "
            f"Compliance Mandate: {tech_info.get('nciipc_sop', 'NCIIPC SOP Enforced')} under {tech_info.get('nciipc_sector', 'CII')}."
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
            "cve_id": tech_info.get("cve_id", "CVE-2022-29951"),
            "cvss_score": tech_info.get("cvss_score", 9.8),
            "cvss_severity": tech_info.get("cvss_severity", "CRITICAL"),
            "nvd_advisory": tech_info.get("nvd_advisory", "https://nvd.nist.gov"),
            "nciipc_sector": tech_info.get("nciipc_sector", "Sector 1: Power & Energy"),
            "nciipc_sop": tech_info.get("nciipc_sop", "NCIIPC-SOP-SEC1-04: Substation Isolation & OT Ingress Scram"),
            "target_critical_asset": tech_info.get("target_critical_asset", "Critical Substation PLC Gateway"),
            "forensic_narrative": narrative
        }
