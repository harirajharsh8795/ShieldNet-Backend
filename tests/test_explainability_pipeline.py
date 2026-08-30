"""
Unit tests for NetGuard Phase 5 Explainable & Trustworthy AI (XAI) Pipeline.

Verifies:
1. IntegratedGradientsExplainer initialization and attribution tensor shapes.
2. Completeness and non-trivial feature rankings.
3. Plain-English NLG security narrative generation.
4. Constraint C2 enforcement (prediction must contain explanation).
5. Temporal Attention Weights extraction and range validation [0, 1].
"""

import pytest
import numpy as np
import torch
from pathlib import Path
import json

from src.world_model.model import WorldModel
from src.explainability.feature_attribution import IntegratedGradientsExplainer
from src.explainability.explain import enforce_explanation, ExplanationMissingError

@pytest.fixture
def dummy_setup():
    input_size = 84
    hidden_size = 128
    classes = ["BENIGN", "Bot", "PortScan", "SSH-Patator", "Web Attack"]
    feature_names = [f"feat_{i}" for i in range(input_size)]
    
    model = WorldModel(
        input_size=input_size,
        hidden_size=hidden_size,
        num_layers=2,
        dropout=0.0,
        num_classes=len(classes),
        num_mitre_stages=6,
        use_attention=True,
    )
    model.eval()
    
    explainer = IntegratedGradientsExplainer(
        model=model,
        feature_names=feature_names,
        classes=classes,
        device="cpu",
        steps=10
    )
    
    return {
        "model": model,
        "explainer": explainer,
        "classes": classes,
        "feature_names": feature_names,
        "seq": np.random.randn(3, input_size).astype(np.float32),
    }

class TestExplainabilityPipeline:
    
    def test_attribution_structure(self, dummy_setup):
        explainer = dummy_setup["explainer"]
        seq = dummy_setup["seq"]
        
        res = explainer.attribute(seq)
        
        assert "predicted_class" in res
        assert "confidence_score" in res
        assert "top_features" in res
        assert "temporal_attention_weights" in res
        assert "plain_text_explanation" in res
        assert len(res["top_features"]) == 5
        assert len(res["temporal_attention_weights"]) == 3
        
    def test_attention_weights_sum_to_one(self, dummy_setup):
        explainer = dummy_setup["explainer"]
        seq = dummy_setup["seq"]
        
        res = explainer.attribute(seq)
        attn = np.array(res["temporal_attention_weights"])
        
        assert np.all(attn >= 0.0)
        assert np.isclose(np.sum(attn), 1.0, atol=1e-4)
        
    def test_top_features_ranking(self, dummy_setup):
        explainer = dummy_setup["explainer"]
        seq = dummy_setup["seq"]
        
        res = explainer.attribute(seq)
        top_f = res["top_features"]
        
        # Rankings must be strictly decreasing by absolute score
        abs_scores = [abs(f["attribution_score"]) for f in top_f]
        assert abs_scores == sorted(abs_scores, reverse=True)
        
    def test_plain_text_nlg_narrative(self, dummy_setup):
        explainer = dummy_setup["explainer"]
        seq = dummy_setup["seq"]
        
        res = explainer.attribute(seq)
        narrative = res["plain_text_explanation"]
        
        assert isinstance(narrative, str)
        assert len(narrative) > 20
        assert "%" in narrative  # Contains probability and attention percentages
        
    def test_constraint_c2_enforcement(self):
        # Empty or missing explanation must raise ExplanationMissingError
        with pytest.raises(ExplanationMissingError):
            enforce_explanation({"predicted_class": "PortScan"})
            
        with pytest.raises(ExplanationMissingError):
            enforce_explanation({"predicted_class": "PortScan", "explanation": {}})
            
        valid = enforce_explanation({
            "predicted_class": "PortScan",
            "explanation": {"top_features": [{"name": "syn_ratio", "score": 0.42}], "plain_text": "Warning"}
        })
        assert valid["predicted_class"] == "PortScan"
