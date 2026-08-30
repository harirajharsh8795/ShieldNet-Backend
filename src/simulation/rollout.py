"""
K-Step Forward Simulation Rollout Engine.

Given a current state sequence, feeds the model's own prediction back as input
for K steps, producing a probability-timeline array showing how attack 
likelihood evolves into the future.

Includes confidence decay — predictions further in the future are less certain.
"""

import torch
import numpy as np
from typing import Dict, List, Optional, Tuple
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.world_model.model import WorldModel
from src.simulation.mitre_mapping import predict_mitre_stage, MITRE_STAGE_NAMES


def k_step_rollout(model: WorldModel,
                   initial_sequence: np.ndarray,
                   k_steps: int = 10,
                   confidence_decay_factor: float = 0.85,
                   device: str = 'cpu') -> Dict:
    """Perform K-step forward simulation using the World Model.
    
    The model predicts the next state, then uses that prediction as input
    to predict the state after that, repeating K times. This is the core
    of the "world model" paradigm — the model generates its own future
    state trajectory.
    
    Args:
        model: Trained WorldModel.
        initial_sequence: Initial state sequence of shape (seq_len, n_features).
        k_steps: Number of forward simulation steps.
        confidence_decay_factor: Per-step confidence decay (0.85 = 15% decay per step).
        device: Torch device.
    
    Returns:
        Dict with:
            'probability_timeline': list of infiltration probabilities per step
            'predicted_stages': list of MITRE stage predictions per step
            'confidence_values': list of confidence values (decaying)
            'predicted_states': list of predicted state vectors
            'stage_names': list of human-readable stage names
    """
    model.eval()
    model.to(device)
    
    # Start with the initial sequence
    current_sequence = torch.FloatTensor(initial_sequence).unsqueeze(0).to(device)  # (1, seq_len, features)
    seq_len = current_sequence.shape[1]
    
    results = {
        'probability_timeline': [],
        'predicted_stages': [],
        'confidence_values': [],
        'predicted_states': [],
        'stage_names': [],
        'class_probabilities': [],
    }
    
    with torch.no_grad():
        for step in range(k_steps):
            # Forward pass
            outputs = model(current_sequence, return_hidden=True)
            
            # Extract predictions
            predicted_next_state = outputs['predicted_next_state']  # (1, features)
            class_logits = outputs['class_logits']  # (1, num_classes)
            infiltration_prob = outputs['infiltration_prob'].item()
            
            # Class probabilities
            class_probs = torch.softmax(class_logits, dim=-1).squeeze().cpu().numpy()
            predicted_class = int(class_logits.argmax(dim=-1).item())
            
            # Confidence decays with each step
            confidence = confidence_decay_factor ** step
            
            # MITRE stage mapping
            stage_name = predict_mitre_stage(
                class_probs=class_probs,
                predicted_state=predicted_next_state.squeeze().cpu().numpy(),
            )
            
            # Record
            results['probability_timeline'].append(float(infiltration_prob * confidence))
            results['predicted_stages'].append(predicted_class)
            results['confidence_values'].append(float(confidence))
            results['predicted_states'].append(predicted_next_state.squeeze().cpu().numpy().tolist())
            results['stage_names'].append(stage_name)
            results['class_probabilities'].append(class_probs.tolist())
            
            # Shift the sequence: drop oldest, append predicted state
            new_state = predicted_next_state.unsqueeze(1)  # (1, 1, features)
            current_sequence = torch.cat([current_sequence[:, 1:, :], new_state], dim=1)
    
    return results


def run_inference(model: WorldModel,
                  input_sequence: np.ndarray,
                  k_steps: int = 10,
                  confidence_decay_factor: float = 0.85,
                  device: str = 'cpu') -> Dict:
    """Complete inference pipeline: single-step prediction + K-step rollout.
    
    This is the main inference function called by the dashboard and evaluation.
    Returns prediction + explanation placeholder (filled by Phase 5).
    
    Args:
        model: Trained WorldModel.
        input_sequence: Input state sequence (seq_len, n_features).
        k_steps: Forward simulation steps.
        confidence_decay_factor: Confidence decay rate.
        device: Device string.
    
    Returns:
        Complete inference result dict.
    """
    # K-step rollout
    rollout = k_step_rollout(
        model, input_sequence, k_steps, 
        confidence_decay_factor, device
    )
    
    # Current-step prediction (step 0 of rollout)
    current_prob = rollout['probability_timeline'][0] if rollout['probability_timeline'] else 0.0
    current_stage = rollout['stage_names'][0] if rollout['stage_names'] else 'Benign'
    
    # Risk level
    if current_prob > 0.7:
        risk_level = 'CRITICAL'
    elif current_prob > 0.4:
        risk_level = 'HIGH'
    elif current_prob > 0.2:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    result = {
        'current_probability': current_prob,
        'current_stage': current_stage,
        'risk_level': risk_level,
        'probability_timeline': rollout['probability_timeline'],
        'predicted_stages': rollout['predicted_stages'],
        'stage_names': rollout['stage_names'],
        'confidence_values': rollout['confidence_values'],
        'class_probabilities': rollout['class_probabilities'],
        'k_steps': k_steps,
        # Explanation placeholder — will be populated by Phase 5 explainability
        'explanation': None,
        'top_features': None,
    }
    
    return result
