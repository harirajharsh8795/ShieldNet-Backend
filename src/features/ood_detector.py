"""
ShieldNet Out-of-Distribution (OOD) and Feature Drift Detector.
SIH26153 NTRO PS-153 Mandated ML Credibility Upgrade.

Detects when incoming telemetry (from unseen network topologies, zero-day behaviors,
or cross-dataset schema discrepancies) drifts outside the enterprise baseline distribution.
Damps overconfident predictions with an automated confidence penalty, alerting SecOps
analysts with exact drifting feature dimensions.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import numpy as np
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CKPT_DIR = PROJECT_ROOT / "models" / "checkpoints"


class OODDetector:
    """
    Multivariate Statistical Drift & Out-of-Distribution Guard.
    Monitors streaming feature vectors against frozen baseline statistics.
    """
    def __init__(self, scaler_path: Optional[Union[str, Path]] = None,
                 drift_threshold: float = 4.5,
                 feature_names: Optional[List[str]] = None):
        if scaler_path is None:
            scaler_path = CKPT_DIR / "scaler.joblib"
        self.scaler_path = Path(scaler_path)
        self.drift_threshold = drift_threshold
        
        # Load Baseline Statistics
        if self.scaler_path.exists():
            scaler = joblib.load(self.scaler_path)
            self.mean = np.array(scaler.mean_[:84] if len(scaler.mean_) >= 84 else np.pad(scaler.mean_, (0, 84 - len(scaler.mean_))), dtype=np.float32)
            self.scale = np.array(scaler.scale_[:84] if len(scaler.scale_) >= 84 else np.pad(scaler.scale_, (0, 84 - len(scaler.scale_)), constant_values=1.0), dtype=np.float32)
            self.is_ready = True
        else:
            self.mean = np.zeros(84, dtype=np.float32)
            self.scale = np.ones(84, dtype=np.float32)
            self.is_ready = False

        # Load Feature Names for Explainable Drift
        if feature_names is not None:
            self.feature_names = feature_names
        else:
            self.feature_names = [f"feat_{i}" for i in range(84)]
            col_path = CKPT_DIR / "feature_columns.json"
            if col_path.exists():
                try:
                    import json
                    with open(col_path, "r") as f:
                        data = json.load(f)
                    if "features" in data:
                        self.feature_names = data["features"][:84]
                except Exception:
                    pass

    def evaluate_vector(self, x: np.ndarray) -> Dict[str, Any]:
        """
        Evaluates a single feature vector of dimension 84 (or sequence last step).
        Returns drift metrics, OOD classification, and confidence penalty.
        """
        arr = np.asarray(x, dtype=np.float32).flatten()
        n = min(len(arr), 84)
        
        mean_slice = self.mean[:n]
        scale_slice = self.scale[:n] + 1e-6
        
        # Standardized absolute Z-scores
        z_scores = np.abs((arr[:n] - mean_slice) / scale_slice)
        z_scores = np.nan_to_num(z_scores, nan=0.0, posinf=50.0, neginf=0.0)
        
        # Top drifting feature indices
        top_k_indices = np.argsort(z_scores)[-3:][::-1]
        top_drifts = []
        for idx in top_k_indices:
            feat_name = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
            top_drifts.append({
                "feature_index": int(idx),
                "feature_name": feat_name,
                "z_score": round(float(z_scores[idx]), 2),
                "raw_value": round(float(arr[idx]), 3),
                "baseline_mean": round(float(mean_slice[idx]), 3)
            })
            
        # Robust aggregate drift score: 70% max deviation + 30% top-3 average
        max_z = float(np.max(z_scores))
        top3_avg_z = float(np.mean([z_scores[i] for i in top_k_indices]))
        drift_score = round(0.7 * max_z + 0.3 * top3_avg_z, 2)
        
        is_ood = drift_score >= self.drift_threshold
        
        if is_ood:
            domain_status = "OUT_OF_DISTRIBUTION_WARNING"
            # Scales penalty between 0.15 and 0.45 proportionally to drift excess
            excess = max(0.0, drift_score - self.drift_threshold)
            confidence_penalty = round(min(0.45, 0.15 + (excess * 0.05)), 3)
            alert_message = (
                f"Feature distribution drift detected (Score: {drift_score} > {self.drift_threshold}). "
                f"Leading deviations in: {', '.join([d['feature_name'] for d in top_drifts])}."
            )
        else:
            domain_status = "IN_DISTRIBUTION"
            confidence_penalty = 0.0
            alert_message = "Feature distribution conforms to verified baseline telemetry."
            
        return {
            "is_ood": is_ood,
            "domain_status": domain_status,
            "drift_score": drift_score,
            "drift_threshold": self.drift_threshold,
            "confidence_penalty": confidence_penalty,
            "top_deviations": top_drifts,
            "alert_message": alert_message
        }

    def guard_probabilities(self, probabilities: Dict[str, float], ood_result: Dict[str, Any]) -> Dict[str, float]:
        """
        Applies calibrated confidence damping if telemetry is Out-of-Distribution.
        Dampens highest confidence class and distributes probability mass towards uncertainty.
        """
        if not ood_result.get("is_ood", False):
            return probabilities
            
        penalty = ood_result.get("confidence_penalty", 0.20)
        guarded = {}
        n_classes = len(probabilities)
        if n_classes == 0:
            return probabilities
            
        # Find max class
        sorted_probs = sorted(probabilities.items(), key=lambda x: x[1], reverse=True)
        top_cls, top_val = sorted_probs[0]
        
        damped_top_val = max(0.20, top_val * (1.0 - penalty))
        surplus = top_val - damped_top_val
        distributed_surplus = surplus / max(1, n_classes - 1)
        
        for cls_name, val in probabilities.items():
            if cls_name == top_cls:
                guarded[cls_name] = round(damped_top_val, 4)
            else:
                guarded[cls_name] = round(val + distributed_surplus, 4)
                
        return guarded


# Global singleton instance
_ood_detector_instance: Optional[OODDetector] = None

def get_ood_detector() -> OODDetector:
    global _ood_detector_instance
    if _ood_detector_instance is None:
        _ood_detector_instance = OODDetector()
    return _ood_detector_instance
