"""
NetGuard Counterfactual State-Space Trajectory Engine.

Simulates parallel 'what-if' future network trajectories under candidate mitigation actions
(NO_ACTION, RATE_LIMIT, RESET_CONNECTIONS, BLOCK_IP, ISOLATE_HOST) using the trained Dual-Engine Ensemble
(World Model GRU+Attention + Secondary Balanced Tabular Classifier).
"""

import numpy as np
import torch
from typing import Dict, List, Tuple, Optional, Any
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.world_model.model import WorldModel
from src.mitigation.actions import MitigationAction, ACTION_COST_MAP, apply_action_to_state_vector

class CounterfactualTrajectoryEngine:
    """Simulates parallel multi-step state-space trajectories under alternative control actions."""
    
    def __init__(self,
                 world_model: WorldModel,
                 classes: List[str],
                 secondary_model: Optional[Any] = None,
                 device: str = "cpu",
                 wm_weight: float = 0.6):
        self.model = world_model
        self.classes = classes
        self.secondary_model = secondary_model
        self.device = torch.device(device)
        self.wm_weight = wm_weight
        self.model.to(self.device)
        self.model.eval()
        
    def simulate_action_trajectory(self,
                                  context_sequence: np.ndarray,
                                  action: MitigationAction,
                                  k_steps: int = 3) -> Dict:
        """Simulate a K-step forward trajectory under a specific defensive intervention."""
        intervened_ctx = context_sequence.copy()
        current_state = intervened_ctx[-1]
        intervened_state = apply_action_to_state_vector(current_state, action)
        intervened_ctx[-1] = intervened_state
        
        ctx_tensor = torch.from_numpy(intervened_ctx[np.newaxis, ...]).float().to(self.device)
        with torch.no_grad():
            rollout_out = self.model.rollout(ctx_tensor, k_steps=k_steps)
            pred_states = rollout_out["predicted_states"].detach().cpu().numpy()[0]   # (K, 84)
            wm_probs = torch.softmax(rollout_out["class_logits"], dim=-1).detach().cpu().numpy()[0]  # (K, C)
            pred_mitres = torch.argmax(rollout_out["mitre_logits"], dim=-1).detach().cpu().numpy()[0]   # (K,)
        
        # Dual-Engine Ensemble Blend across rollout steps
        if self.secondary_model is not None and hasattr(self.secondary_model, "predict_proba"):
            sec_probs = self.secondary_model.predict_proba(pred_states)  # (K, C_sec)
            if sec_probs.shape[1] < len(self.classes):
                pad = np.zeros((len(sec_probs), len(self.classes)), dtype=np.float32)
                pad[:, getattr(self.secondary_model, "classes_", range(sec_probs.shape[1]))] = sec_probs
                sec_probs = pad
            blended_probs = self.wm_weight * wm_probs + (1.0 - self.wm_weight) * sec_probs
        else:
            blended_probs = wm_probs
            
        pred_classes = np.argmax(blended_probs, axis=-1)
        benign_idx = self.classes.index("BENIGN") if "BENIGN" in self.classes else 0
        attack_probs = [float(1.0 - p[benign_idx]) for p in blended_probs]
        predicted_classes = [self.classes[int(c)] for c in pred_classes]
        predicted_mitre_stages = [int(m) for m in pred_mitres]
        
        return {
            "action": action.value,
            "cost": float(ACTION_COST_MAP[action]),
            "predicted_states": pred_states,
            "attack_probabilities": attack_probs,
            "predicted_classes": predicted_classes,
            "predicted_mitre_stages": predicted_mitre_stages,
            "final_attack_risk": attack_probs[-1],
            "system_engine": f"Dual-Engine Ensemble ({self.wm_weight:.0%} WM + {1.0-self.wm_weight:.0%} Tabular)"
        }
        
    def evaluate_all_counterfactuals(self,
                                     context_sequence: np.ndarray,
                                     k_steps: int = 3) -> Dict:
        """Run parallel counterfactual simulations across all available mitigation actions."""
        baseline_res = self.simulate_action_trajectory(context_sequence, MitigationAction.NO_ACTION, k_steps=k_steps)
        baseline_final_risk = baseline_res["final_attack_risk"]
        baseline_final_state = baseline_res["predicted_states"][-1]
        
        action_results = {MitigationAction.NO_ACTION.value: baseline_res}
        
        for action in [MitigationAction.RATE_LIMIT, MitigationAction.RESET_CONNECTIONS, MitigationAction.BLOCK_IP, MitigationAction.ISOLATE_HOST]:
            act_res = self.simulate_action_trajectory(context_sequence, action, k_steps=k_steps)
            div_l2 = float(np.linalg.norm(act_res["predicted_states"][-1] - baseline_final_state))
            risk_reduction = float(baseline_final_risk - act_res["final_attack_risk"])
            
            act_res["state_divergence_l2"] = div_l2
            act_res["risk_reduction"] = risk_reduction
            action_results[action.value] = act_res
            
        # Select optimal policy
        best_action = MitigationAction.NO_ACTION.value
        best_objective = float("-inf")
        lambda_cost = 0.3
        
        for act_name, res in action_results.items():
            if act_name == MitigationAction.NO_ACTION.value:
                continue
            obj = res["risk_reduction"] - (lambda_cost * res["cost"])
            if obj > best_objective and res["risk_reduction"] > 0:
                best_objective = obj
                best_action = act_name
                
        return {
            "baseline_unintervened": baseline_res,
            "candidate_interventions": action_results,
            "optimal_recommended_action": best_action,
            "projected_risk_drop": float(baseline_final_risk - action_results[best_action]["final_attack_risk"]),
            "system_engine": "NetGuard Dual-Engine Counterfactual Engine"
        }
