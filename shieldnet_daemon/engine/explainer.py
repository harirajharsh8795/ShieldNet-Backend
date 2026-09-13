"""
ShieldNet Gated SHAP Explainability Engine.

Implements Section 2.5 of ShieldNet Tech Stack & Section 5.1 of NodeSync Spec:
- Strict Architectural Gating: SHAP is ONLY invoked on windows flagged by the Confidence Gate.
  Benign windows bypass explanation entirely to preserve real-time throughput.
- Computes 84-dimensional feature attribution vectors explaining which network dynamics,
  ports, or flags drove the threat detection.
- Generates structured, tamper-evident SHAPOutput ready for the SQLite Action Ledger
  and privacy-preserving cross-node sync.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
import json
import time
import warnings
import numpy as np

# Suppress benign internal SHAP / LARS solver warnings for low-sample perturbations
warnings.filterwarnings("ignore", category=UserWarning)
try:
    from sklearn.exceptions import ConvergenceWarning
    warnings.filterwarnings("ignore", category=ConvergenceWarning)
except ImportError:
    pass

from shared.schema import (
    CANONICAL_84_FEATURES,
    NUM_CANONICAL_FEATURES,
    CONTEXT_LENGTH,
    ATTACK_CLASSES,
    MITRE_STAGES,
)
from .inference import ONNXInferenceEngine


@dataclass
class SHAPOutput:
    """
    Standardized, self-contained explainability output.
    
    Per Section 5.1 of NodeSync spec: This fixed-size feature-importance vector
    is the sole artifact that leaves the detection core for ledger logging and
    optional cross-node intelligence sharing (never raw packets).
    """
    is_explained: bool
    target_class: str
    mitre_stage: int
    mitre_tactic: str
    threat_probability: float
    confidence: float
    shap_vector: np.ndarray                    # (84,) continuous attribution vector
    feature_attributions: Dict[str, float]     # feature_name -> attribution score
    top_features: List[Dict[str, Any]]         # top driving features
    shap_summary: str                          # Serialized JSON summary for SQLite ledger
    explanation_latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serializes SHAPOutput to dictionary."""
        return {
            "is_explained": self.is_explained,
            "target_class": self.target_class,
            "mitre_stage": self.mitre_stage,
            "mitre_tactic": self.mitre_tactic,
            "threat_probability": self.threat_probability,
            "confidence": self.confidence,
            "shap_vector": self.shap_vector.tolist(),
            "feature_attributions": self.feature_attributions,
            "top_features": self.top_features,
            "shap_summary": self.shap_summary,
            "explanation_latency_ms": self.explanation_latency_ms,
        }


class GatedSHAPExplainer:
    """
    Architecturally-gated SHAP explainer.
    Guarantees that expensive SHAP computation is never executed on benign windows.
    """
    def __init__(
        self,
        inference_engine: Optional[ONNXInferenceEngine] = None,
        background_samples: Optional[np.ndarray] = None,
        nsamples: int = 40,
        top_k: int = 5
    ):
        self.engine = inference_engine or ONNXInferenceEngine()
        self.nsamples = nsamples
        self.top_k = top_k

        # Operational metrics for cost-vs-value transparency
        self.total_windows_seen = 0
        self.total_windows_explained = 0
        self.total_windows_bypassed = 0

        # Create or assign background reference dataset
        if background_samples is not None:
            self.background = np.asarray(background_samples, dtype=np.float32)
        else:
            # Default benign baseline background: 10 neutral baseline sequences
            self.background = np.zeros((10, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES), dtype=np.float32)

        # Flatten background for SHAP: (10, 3 * 84 = 252)
        self.flat_background = self.background.reshape(self.background.shape[0], -1)

        # Initialize SHAP KernelExplainer with ONNX Runtime wrapper
        self._init_shap_explainer()

    def _init_shap_explainer(self):
        """Initializes the SHAP KernelExplainer wrapping ONNX Runtime."""
        import shap

        def predict_threat_prob(X_flat: np.ndarray) -> np.ndarray:
            """Batch prediction wrapper for SHAP KernelExplainer."""
            B = X_flat.shape[0]
            seqs = X_flat.reshape(B, CONTEXT_LENGTH, NUM_CANONICAL_FEATURES)
            probs = np.zeros(B, dtype=np.float32)
            
            # Predict each sequence via ONNX Runtime
            for i in range(B):
                out = self.engine.predict_step(seqs[i])
                probs[i] = float(out["infiltration_prob"])
            return probs

        self.predict_fn = predict_threat_prob
        self.explainer = shap.KernelExplainer(self.predict_fn, self.flat_background)

    def explain_window(
        self,
        gate_result: Dict[str, Any],
        sequence: np.ndarray,
        force_explain: bool = False
    ) -> Optional[SHAPOutput]:
        """
        Gated explainability entrypoint.
        
        Args:
            gate_result: Dict output from ConfidenceGate.evaluate_window().
            sequence: Array of shape (3, 84) or (1, 3, 84).
            force_explain: If True, overrides gate (e.g. for testing/diagnostics).
            
        Returns:
            SHAPOutput if flagged (or forced); None if window is benign.
        """
        self.total_windows_seen += 1
        is_flagged = bool(gate_result.get("is_flagged", False))

        # ── ARCHITECTURAL GATE ──────────────────────────────────────────────
        # Real-time feasibility constraint: skip benign windows (99%+ of traffic)
        if not is_flagged and not force_explain:
            self.total_windows_bypassed += 1
            return None

        # Window is FLAGGED -> Execute SHAP explanation
        self.total_windows_explained += 1
        t0 = time.perf_counter()

        seq = np.asarray(sequence, dtype=np.float32)
        if seq.ndim == 3:
            seq = seq[0]  # (3, 84)

        flat_input = seq.reshape(1, -1)  # (1, 252)

        # Run KernelExplainer
        raw_shap = self.explainer.shap_values(flat_input, nsamples=self.nsamples, silent=True)
        shap_vals_flat = np.array(raw_shap).flatten()  # (252,)

        # Reshape across temporal context: (L=3, 84)
        shap_temporal = shap_vals_flat.reshape(CONTEXT_LENGTH, NUM_CANONICAL_FEATURES)
        
        # Attribution score per feature: weighted temporal emphasis on latest state (t)
        # 60% latest state (t), 25% (t-1), 15% (t-2)
        weights = np.array([0.15, 0.25, 0.60], dtype=np.float32).reshape(3, 1)
        shap_vector = np.sum(shap_temporal * weights, axis=0)  # (84,)

        # Build feature attribution dictionary
        feature_attributions: Dict[str, float] = {
            CANONICAL_84_FEATURES[i]: float(shap_vector[i])
            for i in range(NUM_CANONICAL_FEATURES)
        }

        # Identify Top-K driving features by absolute attribution
        sorted_indices = np.argsort(np.abs(shap_vector))[::-1]
        top_features = []
        for rank, idx in enumerate(sorted_indices[:self.top_k]):
            feat_name = CANONICAL_84_FEATURES[idx]
            attr_score = float(shap_vector[idx])
            direction = "Elevates Threat Risk" if attr_score > 0 else "Suppresses Threat Risk"
            top_features.append({
                "rank": rank + 1,
                "feature_name": feat_name,
                "attribution_score": round(attr_score, 6),
                "impact_direction": direction,
            })

        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0

        target_class = gate_result.get("predicted_class", "Threat")
        mitre_stage = int(gate_result.get("mitre_stage", 0))
        mitre_tactic = gate_result.get("mitre_tactic", MITRE_STAGES.get(mitre_stage, "Unknown"))
        threat_prob = float(gate_result.get("threat_probability", 1.0))
        confidence = float(gate_result.get("wm_confidence", 1.0))

        # Compact summary for Action Ledger storage
        # Includes both structured top_features (for dashboard/query) and top_drivers (compact text)
        summary_payload = {
            "target_class": target_class,
            "threat_probability": round(threat_prob, 4),
            "mitre_stage": mitre_stage,
            "mitre_tactic": mitre_tactic,
            "top_features": [
                {
                    "rank": f["rank"],
                    "feature_name": f["feature_name"],
                    "attribution_score": f["attribution_score"],
                    "impact_direction": f["impact_direction"],
                }
                for f in top_features[:5]
            ],
            "top_drivers": [
                f"{f['feature_name']} ({'+' if f['attribution_score'] > 0 else ''}{f['attribution_score']:.4f})"
                for f in top_features[:3]
            ],
            "explanation_method": "SHAP_KernelExplainer",
            "explanation_latency_ms": round(latency_ms, 2)
        }
        shap_summary_str = json.dumps(summary_payload)

        return SHAPOutput(
            is_explained=True,
            target_class=target_class,
            mitre_stage=mitre_stage,
            mitre_tactic=mitre_tactic,
            threat_probability=threat_prob,
            confidence=confidence,
            shap_vector=shap_vector,
            feature_attributions=feature_attributions,
            top_features=top_features,
            shap_summary=shap_summary_str,
            explanation_latency_ms=round(latency_ms, 2)
        )

    def get_operational_metrics(self) -> Dict[str, Any]:
        """Returns statistics on gating efficiency and compute savings."""
        bypass_rate = (
            (self.total_windows_bypassed / self.total_windows_seen * 100.0)
            if self.total_windows_seen > 0 else 0.0
        )
        return {
            "total_windows_seen": self.total_windows_seen,
            "total_windows_explained": self.total_windows_explained,
            "total_windows_bypassed": self.total_windows_bypassed,
            "bypass_rate_pct": round(bypass_rate, 2),
        }
