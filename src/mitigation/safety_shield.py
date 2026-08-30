"""
ShieldNet Operational Safety Shield & Mitigation Policy.

Enforces strict operational guardrails on autonomous network control actions:
- Prevents false-positive IP blocking / isolation on high-volume benign hosts or critical assets.
- Selects the optimal least-disruptive mitigation action maximizing risk reduction vs business cost.
- Emits structured, explainable safety certificates and audit decisions.
"""

from typing import Dict, List, Tuple, Optional
import numpy as np
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.mitigation.actions import MitigationAction, ACTION_COST_MAP, ACTION_DESCRIPTIONS
from src.mitigation.counterfactual_engine import CounterfactualTrajectoryEngine


class SafetyShieldPolicy:
    """Operational Safety Shield with Hard Business Guardrails and Counterfactual Optimization."""
    
    def __init__(self,
                 counterfactual_engine: CounterfactualTrajectoryEngine,
                 critical_attack_threshold: float = 0.90,
                 active_intervention_threshold: float = 0.35,
                 cost_penalty_weight: float = 0.30):
        """
        Args:
            counterfactual_engine: CounterfactualTrajectoryEngine instance.
            critical_attack_threshold: Minimum forecast confidence required to block benign/critical hosts.
            active_intervention_threshold: Minimum forecast attack risk required to trigger active mitigation.
            cost_penalty_weight: Weight gamma applied to business disruption cost in utility optimization.
        """
        self.engine = counterfactual_engine
        self.tau_crit = critical_attack_threshold
        self.tau_active = active_intervention_threshold
        self.gamma = cost_penalty_weight
        
    def evaluate_and_recommend(self,
                               context_sequence: np.ndarray,
                               historic_benign_ratio: float = 0.95,
                               is_critical_asset: bool = False,
                               host_identifier: str = "Host-1",
                               k_steps: int = 3) -> Dict:
        """Evaluate forward counterfactual trajectories and recommend optimal safe mitigation action.
        
        Args:
            context_sequence: Historical state sequence of shape (seq_len, 84).
            historic_benign_ratio: Proportion of historic flows from this host that were BENIGN (0.0 to 1.0).
            is_critical_asset: True if host is a mission-critical server (database, DNS, gateway).
            host_identifier: Host IP or ID for audit logging.
            k_steps: Future simulation horizon K.
            
        Returns:
            Dict containing recommended action, safety certificate, guardrail status, and counterfactuals.
        """
        # 1. Run full counterfactual rollout engine
        cf_results = self.engine.evaluate_all_counterfactuals(context_sequence, k_steps=k_steps)
        baseline_risk = cf_results["baseline_risk"]
        action_evals = cf_results["actions"]
        
        guardrail_violations = []
        eligible_actions = []
        
        # 2. Apply Hard Safety Guardrails
        for act_name, act_data in action_evals.items():
            action = MitigationAction(act_name)
            is_allowed = True
            rejection_reason = None
            
            # Guardrail 1: Low Threat Baseline -> No active intervention needed
            if baseline_risk < self.tau_active and action != MitigationAction.NO_ACTION:
                is_allowed = False
                rejection_reason = f"Forecast attack risk ({baseline_risk:.1%}) is below active threshold ({self.tau_active:.1%})."
                
            # Guardrail 2: False-Positive Blocker Protection for High-Benign Hosts / Critical Assets
            if action in [MitigationAction.BLOCK_IP, MitigationAction.ISOLATE_HOST]:
                if (historic_benign_ratio > 0.80 or is_critical_asset) and baseline_risk < self.tau_crit:
                    is_allowed = False
                    asset_desc = "critical business asset" if is_critical_asset else f"high-benign host ({historic_benign_ratio:.1%})"
                    rejection_reason = (
                        f"Safety Guardrail G-01: Disallowed aggressive action '{act_name}' on {asset_desc} "
                        f"because attack forecast confidence ({baseline_risk:.1%}) < critical threshold ({self.tau_crit:.1%})."
                    )
            
            if not is_allowed:
                guardrail_violations.append({
                    "action": act_name,
                    "rejection_reason": rejection_reason
                })
            else:
                # Calculate constrained shield utility
                risk_red = act_data["risk_reduction"]
                cost = act_data["cost"]
                shield_utility = risk_red - (self.gamma * cost)
                
                eligible_actions.append({
                    "action": act_name,
                    "shield_utility": float(shield_utility),
                    "risk_reduction": float(risk_red),
                    "cost": float(cost),
                    "final_attack_risk": float(act_data["final_attack_risk"]),
                    "details": act_data
                })
                
        # 3. Select Best Action maximizing Shield Utility
        if not eligible_actions:
            selected_action = MitigationAction.NO_ACTION.value
            best_choice = action_evals[selected_action]
        else:
            eligible_actions.sort(key=lambda x: x["shield_utility"], reverse=True)
            selected_action = eligible_actions[0]["action"]
            best_choice = action_evals[selected_action]
            
        # 4. Construct Explainable Safety Certificate
        decision_rationale = self._generate_decision_rationale(
            selected_action=selected_action,
            baseline_risk=baseline_risk,
            best_choice=best_choice,
            guardrail_violations=guardrail_violations,
            historic_benign_ratio=historic_benign_ratio,
            is_critical_asset=is_critical_asset
        )
        
        return {
            "host_identifier": host_identifier,
            "recommended_action": selected_action,
            "action_description": ACTION_DESCRIPTIONS[MitigationAction(selected_action)],
            "baseline_attack_risk": float(baseline_risk),
            "mitigated_attack_risk": float(best_choice["final_attack_risk"]),
            "risk_reduction": float(baseline_risk - best_choice["final_attack_risk"]),
            "operational_cost": float(ACTION_COST_MAP[MitigationAction(selected_action)]),
            "decision_rationale": decision_rationale,
            "guardrail_enforcements": guardrail_violations,
            "counterfactual_trajectories": action_evals,
            "safety_shield_status": "ACTIVE_PROTECTED"
        }
        
    def _generate_decision_rationale(self,
                                     selected_action: str,
                                     baseline_risk: float,
                                     best_choice: Dict,
                                     guardrail_violations: List[Dict],
                                     historic_benign_ratio: float,
                                     is_critical_asset: bool) -> str:
        """Construct human-interpretable plain-English explanation for SOC engineers."""
        if selected_action == MitigationAction.NO_ACTION.value:
            if baseline_risk < self.tau_active:
                return f"No mitigation required: Forecast attack probability ({baseline_risk:.1%}) remains within benign operating tolerance."
            else:
                return f"No action taken: Aggressive interventions suppressed by safety guardrails to protect legitimate host traffic."
                
        reasons = [
            f"Recommended '{selected_action}' to mitigate impending attack escalation (Baseline Risk: {baseline_risk:.1%} -> Mitigated: {best_choice['final_attack_risk']:.1%})."
        ]
        
        if guardrail_violations:
            blocked_acts = [v["action"] for v in guardrail_violations]
            reasons.append(f"Safety Shield actively blocked more disruptive action(s) {blocked_acts} due to high host legitimacy ({historic_benign_ratio:.1%}).")
            
        reasons.append(f"Optimal operational trade-off: Net risk reduction of {best_choice['risk_reduction']:.1%} achieved at business cost of {ACTION_COST_MAP[MitigationAction(selected_action)]:.2f}.")
        return " ".join(reasons)
