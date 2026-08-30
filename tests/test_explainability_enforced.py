"""
Test: Constraint C2 — Explainability enforcement.

Verifies that every prediction returned by the system has a non-null 
explanation object. The inference API must raise ExplanationMissingError
if a prediction would be returned without an explanation.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.explainability.explain import (
    ExplanationMissingError, Explanation, enforce_explanation,
    generate_explanation, FEATURE_DESCRIPTIONS
)


class TestExplainabilityEnforcement:
    """Tests that Constraint C2 (mandatory explainability) is enforced."""
    
    def test_missing_explanation_raises_error(self):
        """Prediction without explanation must raise ExplanationMissingError."""
        prediction = {
            'current_probability': 0.85,
            'current_stage': 'Command & Control',
            'risk_level': 'CRITICAL',
            'explanation': None,  # Missing!
        }
        
        with pytest.raises(ExplanationMissingError) as exc_info:
            enforce_explanation(prediction)
        
        assert "CONSTRAINT C2" in str(exc_info.value)
    
    def test_empty_explanation_raises_error(self):
        """Empty explanation dict must also raise ExplanationMissingError."""
        prediction = {
            'current_probability': 0.5,
            'explanation': {
                'top_features': [],
                'plain_text': '',
            },
        }
        
        with pytest.raises(ExplanationMissingError):
            enforce_explanation(prediction)
    
    def test_valid_explanation_passes(self):
        """Valid explanation should pass enforcement check."""
        prediction = {
            'current_probability': 0.85,
            'current_stage': 'Command & Control',
            'risk_level': 'CRITICAL',
            'explanation': {
                'top_features': [
                    {'name': 'syn_ratio', 'score': 0.35, 'direction': 'elevated',
                     'description': 'SYN packet ratio'},
                ],
                'plain_text': 'High SYN ratio detected.',
                'method': 'gradient',
                'confidence': 1.0,
            },
        }
        
        result = enforce_explanation(prediction)
        assert result is prediction  # Should return unchanged
    
    def test_explanation_object_enforcement(self):
        """Explanation object instance should pass enforcement."""
        explanation = Explanation(
            feature_attributions={'syn_ratio': 0.35},
            top_features=[{'name': 'syn_ratio', 'score': 0.35, 'direction': 'elevated',
                          'description': 'SYN packet ratio'}],
            plain_text='Test explanation',
            method='gradient',
        )
        
        prediction = {
            'current_probability': 0.5,
            'explanation': explanation,
        }
        
        result = enforce_explanation(prediction)
        assert result is prediction
    
    def test_explanation_generation(self):
        """generate_explanation should produce valid explanations."""
        attributions = {
            'syn_ratio_mean': 0.25,
            'flow_bytes_per_sec_mean': 0.20,
            'rst_ratio_mean': 0.15,
            'ttl_variance_mean': 0.10,
            'port_scan_sequential_score_mean': 0.08,
            'total_fwd_packets_mean': 0.05,
        }
        
        prediction_result = {
            'risk_level': 'HIGH',
            'current_stage': 'Initial Access',
            'current_probability': 0.65,
        }
        
        feature_names = list(attributions.keys())
        explanation = generate_explanation(
            attributions, prediction_result, feature_names, top_k=3
        )
        
        assert len(explanation.top_features) == 3
        assert len(explanation.plain_text) > 0
        assert 'HIGH' in explanation.plain_text
        assert explanation.method == 'gradient'  # default
    
    def test_plain_text_is_human_readable(self):
        """Explanation text should be human-readable, not raw arrays."""
        attributions = {'syn_ratio_mean': 0.5, 'flow_bytes_per_sec_mean': 0.3}
        prediction_result = {
            'risk_level': 'CRITICAL',
            'current_stage': 'C2',
            'current_probability': 0.9,
        }
        
        explanation = generate_explanation(
            attributions, prediction_result, list(attributions.keys()), top_k=2
        )
        
        # Should contain words, not just numbers
        assert any(c.isalpha() for c in explanation.plain_text)
        # Should mention risk level
        assert 'CRITICAL' in explanation.plain_text


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
