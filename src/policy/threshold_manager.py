"""
ShieldNet Section 3 Fix: Entropy-Adaptive Dynamic Thresholding (DAT).
Prevents adversary evasion attacks where attackers calibrate packet rates to fly just below
static thresholds (e.g. at 0.35 probability). Dynamically tightens operating decision boundaries
based on network transition Shannon Entropy H(t).
"""

from typing import Dict, List, Optional
import numpy as np

class DynamicAdaptiveThresholdManager:
    """
    Dynamically adjusts detection thresholds based on real-time network entropy.
    When background telemetry is calm and predictable, thresholds relax to eliminate false alarms.
    During anomalous bursts or multi-host scanning, thresholds tighten automatically to catch evasive APTs.
    """
    def __init__(self, base_thresholds: Optional[Dict[str, float]] = None, sensitivity_alpha: float = 0.25):
        # Default Nelder-Mead calibrated baseline thresholds
        self.base_thresholds = base_thresholds or {
            "BENIGN": 0.50,
            "Bot": 0.28,
            "DDoS": 0.35,
            "DoS GoldenEye": 0.30,
            "DoS Hulk": 0.40,
            "DoS Slowhttptest": 0.25,
            "DoS slowloris": 0.25,
            "FTP-Patator": 0.38,
            "PortScan": 0.32,
            "Rare-Attack": 0.20,
            "SSH-Patator": 0.38,
            "Web Attack - Brute Force": 0.35,
            "Web Attack - XSS": 0.30
        }
        self.sensitivity_alpha = sensitivity_alpha
        self.entropy_history: List[float] = []

    def compute_window_entropy(self, probabilities: np.ndarray) -> float:
        """Computes Shannon Entropy H(t) = -sum(p * log2(p)) over predicted class distribution."""
        probs = np.clip(probabilities, 1e-7, 1.0)
        entropy = -np.sum(probs * np.log2(probs))
        self.entropy_history.append(entropy)
        if len(self.entropy_history) > 100:
            self.entropy_history.pop(0)
        return float(entropy)

    def get_adaptive_thresholds(self, current_probabilities: np.ndarray) -> Dict[str, float]:
        """
        Calculates adapted threshold vector:
        tau_c(t) = tau_base * (1.0 - alpha * Delta_H)
        Tightens thresholds when network entropy spikes.
        """
        current_entropy = self.compute_window_entropy(current_probabilities)
        baseline_entropy = np.median(self.entropy_history) if len(self.entropy_history) >= 10 else current_entropy
        
        # Delta H: Positive when anomalous uncertainty spikes
        delta_h = np.clip((current_entropy - baseline_entropy) / (baseline_entropy + 1e-5), -0.5, 0.5)
        
        adapted = {}
        for c_name, base_tau in self.base_thresholds.items():
            if c_name == "BENIGN":
                adapted[c_name] = base_tau
            else:
                # Tighten threshold during elevated entropy
                adapted[c_name] = float(np.clip(base_tau * (1.0 - self.sensitivity_alpha * delta_h), 0.10, 0.70))
                
        return adapted
