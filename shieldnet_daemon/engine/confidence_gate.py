"""
ShieldNet Gated Ensemble & Confidence Gate Engine.

Implements Section 2.4 and Section 3 of ShieldNet Tech Stack:
- Compares World Model confidence (C_wm = max(P_wm)) against threshold tau (default 0.80).
- Blends temporal GRU predictions with balanced Logistic Regression baseline score:
  - If C_wm >= tau: World Model dominant (high temporal certainty)
  - If C_wm < tau: Ensemble fallback blending: P_blended = 0.60 * P_wm + 0.40 * P_lr
- Determines the binary detection gate: 'is_flagged'
  A window is flagged when BOTH conditions hold:
    1. blended threat probability >= threat_threshold (default 0.80 — high-precision gate)
    2. the predicted class is non-benign (idx != 0)
  Flagged windows proceed to SHAP explainability (Module 4) and Action Ledger (Module 5);
  Benign windows bypass SHAP entirely to conserve CPU cycles for real-time operation.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
import time
import numpy as np
import joblib

from shared.schema import (
    ATTACK_CLASSES,
    MITRE_STAGES,
    NUM_CANONICAL_FEATURES,
)
from .inference import ONNXInferenceEngine


class ConfidenceGate:
    """
    Evaluates confidence-gated ensemble decisions between the World Model and
    the Logistic Regression baseline.
    """
    def __init__(
        self,
        logreg_path: Optional[Union[str, Path]] = None,
        confidence_tau: float = 0.80,
        wm_blend_weight: float = 0.60,
        threat_threshold: float = 0.80,
    ):
        self.confidence_tau = confidence_tau
        self.wm_blend_weight = wm_blend_weight
        self.threat_threshold = threat_threshold

        self.lr_coef: Optional[np.ndarray] = None
        self.lr_intercept: Optional[np.ndarray] = None
        self.is_loaded = False

        # Load Logistic Regression baseline parameters
        self._load_logreg_baseline(logreg_path)

    def _load_logreg_baseline(self, logreg_path: Optional[Union[str, Path]] = None):
        """Loads Logistic Regression weights from .npz (fast) or .joblib."""
        ckpt_dirs = [
            Path(__file__).resolve().parent.parent / "models" / "checkpoints",
            Path(__file__).resolve().parent.parent.parent / "models" / "checkpoints",
        ]
        if logreg_path:
            ckpt_dirs.insert(0, Path(logreg_path).parent)

        # 1. Try npz parameters first
        for c_dir in ckpt_dirs:
            npz_file = c_dir / "logreg_params.npz"
            if npz_file.exists():
                try:
                    data = np.load(npz_file)
                    self.lr_coef = np.array(data["coef"], dtype=np.float32)
                    self.lr_intercept = np.array(data["intercept"], dtype=np.float32)
                    self.is_loaded = True
                    return
                except Exception:
                    pass

        # 2. Try joblib file
        for c_dir in ckpt_dirs:
            joblib_file = c_dir / "ensemble_logreg.joblib"
            if joblib_file.exists():
                try:
                    lr_model = joblib.load(joblib_file)
                    self.lr_coef = np.array(lr_model.coef_, dtype=np.float32)
                    self.lr_intercept = np.array(lr_model.intercept_, dtype=np.float32)
                    self.is_loaded = True
                    return
                except Exception:
                    pass

        # Fallback identity baseline if not found
        self.lr_coef = np.zeros((len(ATTACK_CLASSES), NUM_CANONICAL_FEATURES), dtype=np.float32)
        self.lr_intercept = np.zeros(len(ATTACK_CLASSES), dtype=np.float32)
        self.is_loaded = False

    def predict_logreg_proba(self, state_vector: np.ndarray) -> np.ndarray:
        """
        Computes 13-class softmax probabilities for single or batch state vectors using
        the calibrated Logistic Regression baseline: logits = X @ W.T + b.
        
        Args:
            state_vector: Array of shape (84,) or (B, 84).
            
        Returns:
            Array of shape (13,) or (B, 13).
        """
        X = np.asarray(state_vector, dtype=np.float32)
        is_single = (X.ndim == 1)
        if is_single:
            X = np.expand_dims(X, axis=0)

        # Linear projection: (B, 84) @ (84, 13) + (13,) -> (B, 13)
        logits = np.dot(X, self.lr_coef.T) + self.lr_intercept

        # Stable Softmax
        exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
        probs = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)

        return probs[0] if is_single else probs

    def evaluate_window(
        self,
        wm_step_output: Dict[str, Any],
        current_state: np.ndarray,
        k_step_rollout: Optional[List[float]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates the confidence gate on a single window.
        
        Args:
            wm_step_output: Output from ONNXInferenceEngine.predict_step().
            current_state: Array of shape (84,) representing latest state S_t.
            k_step_rollout: Optional K=5 rollout threat probabilities.
            
        Returns:
            Dict containing final gated detection, blending action, probabilities,
            and binary 'is_flagged' decision for downstream SHAP / Ledger.
        """
        p_wm = np.asarray(wm_step_output["class_probs"], dtype=np.float32)
        p_lr = self.predict_logreg_proba(current_state)

        # World Model Confidence
        conf_wm = float(np.max(p_wm))
        conf_lr = float(np.max(p_lr))

        # Confidence Gate logic:
        # If World Model confidence >= tau: WM is dominant
        # If World Model confidence < tau: Blend with Logistic Regression baseline
        if conf_wm >= self.confidence_tau:
            gating_action = "world_model_dominant"
            p_blended = 0.85 * p_wm + 0.15 * p_lr
        else:
            gating_action = "ensemble_fallback"
            w = self.wm_blend_weight
            p_blended = w * p_wm + (1.0 - w) * p_lr

        # Normalize blended distribution
        p_blended = p_blended / np.sum(p_blended)

        pred_class_idx = int(np.argmax(p_blended))
        pred_class_label = ATTACK_CLASSES[pred_class_idx]

        # Threat probability: 1.0 - P(BENIGN)
        threat_prob = float(1.0 - p_blended[0])
        mitre_stage = int(wm_step_output.get("mitre_stage", 0))
        mitre_tactic = MITRE_STAGES.get(mitre_stage, "Normal Operations")

        # Binary flagging decision (high-precision gate):
        # Flag ONLY if threat probability >= threshold AND predicted class is non-benign.
        # Using AND (not OR) avoids false-positive alerts on uncertain-but-likely-benign windows.
        is_flagged = bool((threat_prob >= self.threat_threshold) and (pred_class_idx != 0))

        # Determine alert severity
        if not is_flagged:
            severity = "CLEAN"
        elif threat_prob >= 0.85 or mitre_stage >= 4:
            severity = "HIGH"
        elif threat_prob >= 0.50 or mitre_stage >= 2:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "is_flagged": is_flagged,
            "threat_probability": round(threat_prob, 4),
            "predicted_class": pred_class_label,
            "predicted_class_idx": pred_class_idx,
            "mitre_stage": mitre_stage,
            "mitre_tactic": mitre_tactic,
            "severity": severity,
            "gating_action": gating_action,
            "wm_confidence": round(conf_wm, 4),
            "lr_confidence": round(conf_lr, 4),
            "blended_probs": p_blended,
            "wm_probs": p_wm,
            "lr_probs": p_lr,
            "k_step_rollout": k_step_rollout or wm_step_output.get("k_step_rollout", []),
            "timestamp": time.time(),
        }
