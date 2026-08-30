"""
Explainability Layer for ShieldNet.

Provides feature attribution for every prediction using:
1. SHAP (DeepExplainer or KernelExplainer) — primary method
2. Gradient-based attribution (fallback when SHAP is slow)
3. Plain-language explanation generator

CONSTRAINT C2 ENFORCEMENT: Every prediction MUST have an explanation.
The main inference API raises ExplanationMissingError if a prediction
would be returned without an explanation object attached.
"""

import numpy as np
import torch
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class ExplanationMissingError(Exception):
    """Raised when a prediction is about to be returned without an explanation.
    
    CONSTRAINT C2: The PS explicitly states 'Black-box outputs without 
    interpretability are not acceptable.' This exception enforces that
    every prediction has an attached explanation.
    """
    pass


class Explanation:
    """Structured explanation object for a prediction."""
    
    def __init__(self, 
                 feature_attributions: Dict[str, float],
                 top_features: List[Dict],
                 plain_text: str,
                 method: str = 'shap',
                 confidence: float = 1.0):
        """
        Args:
            feature_attributions: Full dict of feature_name → attribution score.
            top_features: Top-K features with name, score, and direction.
            plain_text: Human-readable explanation string.
            method: Attribution method used ('shap', 'gradient', 'attention').
            confidence: Confidence in the explanation (0-1).
        """
        self.feature_attributions = feature_attributions
        self.top_features = top_features
        self.plain_text = plain_text
        self.method = method
        self.confidence = confidence
    
    def to_dict(self) -> Dict:
        """Serialize to dictionary."""
        return {
            'feature_attributions': self.feature_attributions,
            'top_features': self.top_features,
            'plain_text': self.plain_text,
            'method': self.method,
            'confidence': self.confidence,
        }
    
    def __repr__(self):
        return f"Explanation(method={self.method}, top_features={len(self.top_features)}, text='{self.plain_text[:80]}...')"


# ─── Feature Name → Human-Readable Description Map ──────────────────────────
FEATURE_DESCRIPTIONS = {
    'syn_ratio': 'SYN packet ratio',
    'rst_ratio': 'RST (reset) packet ratio',
    'fin_ratio': 'FIN packet ratio',
    'flow_bytes_per_sec': 'data transfer rate',
    'flow_packets_per_sec': 'packet rate',
    'port_scan_sequential_score': 'sequential port-scan pattern',
    'port_scan_random_score': 'random port-scan pattern',
    'ttl_variance': 'TTL value variance',
    'ttl_mean': 'average TTL value',
    'tcp_window_size_mean': 'TCP window size',
    'tcp_window_size_std': 'TCP window size variability',
    'payload_size_entropy': 'payload size randomness (entropy)',
    'payload_size_mean': 'average payload size',
    'retransmission_ratio': 'packet retransmission rate',
    'retransmission_count': 'number of retransmissions',
    'ip_fragment_flag_ratio': 'IP fragmentation rate',
    'flow_duration': 'flow duration',
    'total_fwd_packets': 'forward packet count',
    'total_bwd_packets': 'backward packet count',
    'total_fwd_bytes': 'forward data volume',
    'total_bwd_bytes': 'backward data volume',
    'fwd_iat_mean': 'forward inter-arrival time',
    'bwd_iat_mean': 'backward inter-arrival time',
    'flow_iat_mean': 'average inter-arrival time',
    'flow_iat_std': 'inter-arrival time variability',
    'down_up_ratio': 'download/upload ratio',
    'init_win_bytes_forward': 'initial TCP window (forward)',
    'init_win_bytes_backward': 'initial TCP window (backward)',
    'fwd_packets_per_sec': 'forward packet rate',
    'bwd_packets_per_sec': 'backward packet rate',
    'active_mean': 'active time',
    'idle_mean': 'idle time',
}


def compute_gradient_attribution(model, input_sequence: np.ndarray,
                                  feature_names: List[str],
                                  device: str = 'cpu') -> Dict[str, float]:
    """Compute gradient-based feature attribution.
    
    Uses input gradient magnitude as a proxy for feature importance.
    Fast and always available (no dependency on SHAP background data).
    
    Args:
        model: Trained WorldModel.
        input_sequence: Input state sequence (seq_len, n_features).
        feature_names: Names of features in the state vector.
        device: Torch device.
    
    Returns:
        Dict mapping feature_name → attribution score.
    """
    model.eval()
    model.to(device)
    
    x = torch.FloatTensor(input_sequence).unsqueeze(0).to(device)
    x.requires_grad_(True)
    
    outputs = model(x)
    
    # Gradient w.r.t. infiltration probability (most interpretable output)
    prob = outputs['infiltration_prob'].sum()
    prob.backward()
    
    # Average gradient magnitude across time steps
    grad = x.grad.abs().mean(dim=1).squeeze().detach().cpu().numpy()  # (n_features,)
    
    # Normalize to sum to 1
    grad_sum = grad.sum()
    if grad_sum > 0:
        grad = grad / grad_sum
    
    # Map to feature names — handle windowed features (_mean, _std, _max suffixes)
    attributions = {}
    for i, score in enumerate(grad):
        if i < len(feature_names):
            attributions[feature_names[i]] = float(score)
    
    return attributions


def compute_shap_attribution(model, input_sequence: np.ndarray,
                              background_data: np.ndarray,
                              feature_names: List[str],
                              device: str = 'cpu') -> Dict[str, float]:
    """Compute SHAP feature attribution.
    
    Uses KernelExplainer for model-agnostic SHAP values.
    More accurate than gradient attribution but slower.
    
    Args:
        model: Trained WorldModel.
        input_sequence: Input state sequence (seq_len, n_features).
        background_data: Background samples for SHAP (n_bg, seq_len, n_features).
        feature_names: Names of features.
        device: Torch device.
    
    Returns:
        Dict mapping feature_name → SHAP attribution score.
    """
    try:
        import shap
    except ImportError:
        print("  WARNING: SHAP not available, falling back to gradient attribution")
        return compute_gradient_attribution(model, input_sequence, feature_names, device)
    
    model.eval()
    model.to(device)
    
    def predict_fn(X):
        """Wrapper for SHAP: takes flattened input, returns infiltration probability."""
        # X shape: (n_samples, seq_len * n_features) — SHAP flattens inputs
        seq_len = input_sequence.shape[0]
        n_features = input_sequence.shape[1]
        
        results = []
        for row in X:
            x_reshaped = row.reshape(1, seq_len, n_features)
            x_tensor = torch.FloatTensor(x_reshaped).to(device)
            with torch.no_grad():
                output = model(x_tensor)
            results.append(output['infiltration_prob'].item())
        
        return np.array(results)
    
    # Flatten for SHAP
    flat_input = input_sequence.flatten().reshape(1, -1)
    flat_background = background_data.reshape(background_data.shape[0], -1)
    
    # Subsample background if too large
    max_bg = 50
    if len(flat_background) > max_bg:
        indices = np.random.choice(len(flat_background), max_bg, replace=False)
        flat_background = flat_background[indices]
    
    explainer = shap.KernelExplainer(predict_fn, flat_background)
    shap_values = explainer.shap_values(flat_input, nsamples=100)
    
    # Average SHAP values across time steps for each feature
    seq_len = input_sequence.shape[0]
    n_features = input_sequence.shape[1]
    
    shap_reshaped = shap_values.reshape(seq_len, n_features)
    feature_shap = np.abs(shap_reshaped).mean(axis=0)  # average across time
    
    # Normalize
    shap_sum = feature_shap.sum()
    if shap_sum > 0:
        feature_shap = feature_shap / shap_sum
    
    attributions = {}
    for i, score in enumerate(feature_shap):
        if i < len(feature_names):
            attributions[feature_names[i]] = float(score)
    
    return attributions


def generate_explanation(attributions: Dict[str, float],
                         prediction_result: Dict,
                         feature_names: List[str],
                         top_k: int = 5,
                         method: str = 'gradient') -> Explanation:
    """Generate a complete explanation object from attribution scores.
    
    Args:
        attributions: Dict of feature_name → attribution score.
        prediction_result: The prediction dict (with probability, stage, etc.)
        feature_names: Full list of feature names.
        top_k: Number of top features to highlight.
        method: Attribution method used.
    
    Returns:
        Explanation object.
    """
    # Get top-K features
    sorted_features = sorted(attributions.items(), key=lambda x: abs(x[1]), reverse=True)
    top_features = []
    
    for feat_name, score in sorted_features[:top_k]:
        # Get base feature name (strip _mean/_std/_max suffix for description lookup)
        base_name = feat_name
        for suffix in ['_mean', '_std', '_max']:
            if base_name.endswith(suffix):
                base_name = base_name[:-len(suffix)]
                break
        
        description = FEATURE_DESCRIPTIONS.get(base_name, base_name.replace('_', ' '))
        direction = 'elevated' if score > 0 else 'reduced'
        
        top_features.append({
            'name': feat_name,
            'score': abs(score),
            'direction': direction,
            'description': description,
        })
    
    # Generate plain-language explanation
    risk_level = prediction_result.get('risk_level', 'UNKNOWN')
    current_stage = prediction_result.get('current_stage', 'Unknown')
    current_prob = prediction_result.get('current_probability', 0)
    
    plain_text = _generate_plain_text(
        risk_level, current_stage, current_prob, top_features
    )
    
    return Explanation(
        feature_attributions=attributions,
        top_features=top_features,
        plain_text=plain_text,
        method=method,
        confidence=1.0,
    )


def _generate_plain_text(risk_level: str, stage: str, 
                          probability: float, top_features: List[Dict]) -> str:
    """Generate a human-readable explanation sentence.
    
    Uses template-based NLG (simple but reliable for a hackathon).
    """
    if risk_level in ('CRITICAL', 'HIGH'):
        severity_phrase = f"⚠️ **{risk_level} RISK** detected"
    elif risk_level == 'MEDIUM':
        severity_phrase = f"⚡ **{risk_level} RISK** — potential threat"
    else:
        severity_phrase = f"✅ **{risk_level} RISK** — likely benign"
    
    # Feature phrases
    feature_phrases = []
    for feat in top_features[:3]:
        desc = feat['description']
        direction = feat['direction']
        feature_phrases.append(f"{direction} {desc}")
    
    features_text = ", ".join(feature_phrases[:-1])
    if len(feature_phrases) > 1:
        features_text += f", and {feature_phrases[-1]}"
    elif feature_phrases:
        features_text = feature_phrases[0]
    else:
        features_text = "no strongly contributing features"
    
    explanation = (
        f"{severity_phrase} (probability: {probability:.1%}). "
        f"Predicted attack stage: **{stage}**. "
        f"Primary drivers: {features_text}."
    )
    
    return explanation


def enforce_explanation(prediction_result: Dict) -> Dict:
    """Enforce Constraint C2: every prediction must have an explanation.
    
    RAISES ExplanationMissingError if explanation is missing.
    
    Args:
        prediction_result: Inference result dict.
    
    Returns:
        The same dict (unchanged) if explanation is present.
    
    Raises:
        ExplanationMissingError: If explanation is None or empty.
    """
    explanation = prediction_result.get('explanation')
    
    if explanation is None:
        raise ExplanationMissingError(
            "CONSTRAINT C2 VIOLATION: Prediction returned without an explanation object. "
            "The problem statement explicitly requires: 'Black-box outputs without "
            "interpretability are not acceptable.' Every prediction must include "
            "feature attributions and a human-readable explanation."
        )
    
    if isinstance(explanation, dict):
        if not explanation.get('top_features') and not explanation.get('plain_text'):
            raise ExplanationMissingError(
                "CONSTRAINT C2 VIOLATION: Explanation object is empty — no top features "
                "or plain text explanation found."
            )
    elif isinstance(explanation, Explanation):
        if not explanation.top_features and not explanation.plain_text:
            raise ExplanationMissingError(
                "CONSTRAINT C2 VIOLATION: Explanation object has no content."
            )
    
    return prediction_result


def explain_prediction(model, input_sequence: np.ndarray,
                       prediction_result: Dict,
                       feature_names: List[str],
                       background_data: Optional[np.ndarray] = None,
                       method: str = 'gradient',
                       top_k: int = 5,
                       device: str = 'cpu') -> Dict:
    """Complete explanation pipeline: compute attribution + generate explanation.
    
    This is the main entry point called by the inference pipeline.
    
    Args:
        model: Trained WorldModel.
        input_sequence: Input state sequence.
        prediction_result: Prediction dict from run_inference().
        feature_names: Feature names.
        background_data: Optional background data for SHAP.
        method: 'gradient' or 'shap'.
        top_k: Number of top features.
        device: Torch device.
    
    Returns:
        Updated prediction_result with explanation attached.
    """
    # Compute attributions
    if method == 'shap' and background_data is not None:
        attributions = compute_shap_attribution(
            model, input_sequence, background_data, feature_names, device
        )
    else:
        attributions = compute_gradient_attribution(
            model, input_sequence, feature_names, device
        )
    
    # Generate explanation
    explanation = generate_explanation(
        attributions, prediction_result, feature_names, top_k, method
    )
    
    # Attach to prediction result
    prediction_result['explanation'] = explanation.to_dict()
    prediction_result['top_features'] = explanation.top_features
    
    # Enforce constraint C2
    enforce_explanation(prediction_result)
    
    return prediction_result
