"""
ShieldNet Mitigation Action Space & State-Space Intervention Operators.

Defines defensive network control actions and their formal mathematical intervention
functions on 84-dimensional network state vectors S_t.
"""

from enum import Enum
import numpy as np
from typing import Dict, List, Tuple, Optional


class MitigationAction(str, Enum):
    """Network control mitigation actions."""
    NO_ACTION = "NO_ACTION"
    RATE_LIMIT = "RATE_LIMIT"
    RESET_CONNECTIONS = "RESET_CONNECTIONS"
    BLOCK_IP = "BLOCK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"


# Business operational costs associated with each action (scale 0.0 to 1.0)
ACTION_COST_MAP = {
    MitigationAction.NO_ACTION: 0.00,
    MitigationAction.RESET_CONNECTIONS: 0.05,
    MitigationAction.RATE_LIMIT: 0.15,
    MitigationAction.BLOCK_IP: 0.50,
    MitigationAction.ISOLATE_HOST: 0.85,
}

ACTION_DESCRIPTIONS = {
    MitigationAction.NO_ACTION: "Passive observation without active intervention.",
    MitigationAction.RATE_LIMIT: "Throttles packet transmission rate and expands inter-arrival intervals.",
    MitigationAction.RESET_CONNECTIONS: "Transmits TCP RST packets to tear down suspicious active sessions.",
    MitigationAction.BLOCK_IP: "Applies edge firewall ACL rule dropping all ingress/egress packets for source IP.",
    MitigationAction.ISOLATE_HOST: "Enforces zero-trust quarantine VLAN, restricting host to diagnostic telemetry.",
}


def apply_action_to_state_vector(state_vector: np.ndarray,
                                 action: MitigationAction,
                                 feature_manifest: Optional[List[str]] = None) -> np.ndarray:
    """Apply counterfactual physical intervention T(S_t, a) to state vector S_t.
    
    Args:
        state_vector: 84-dimensional standardized state vector S_t.
        action: Candidate MitigationAction.
        feature_manifest: List of 84 feature names (optional, used for precise index masking).
        
    Returns:
        Intervened state vector \tilde{S}_t.
    """
    intervened = state_vector.copy().astype(np.float32)
    
    if action == MitigationAction.NO_ACTION:
        return intervened
        
    # Standardized features centered around 0.0 (where 0.0 represents normal baseline mean)
    # Negative standardized values (~ -1.0 to -2.0) represent suppressed/quarantined traffic.
    
    if action == MitigationAction.RATE_LIMIT:
        # Suppress rate and packet burst features (indices ~ 10-25 and packet count indices)
        # Scale down rate spikes by dampening extreme standardized positive deviations
        rate_mask = intervened > 0.0
        intervened[rate_mask] = intervened[rate_mask] * 0.15  # Dampen burst magnitude by 85%
        
    elif action == MitigationAction.RESET_CONNECTIONS:
        # Suppress active TCP flag ratios and connection duration
        flag_mask = intervened > 0.0
        intervened[flag_mask] = intervened[flag_mask] * 0.05  # Collapse active flags
        
    elif action == MitigationAction.BLOCK_IP:
        # Full edge drop: collapse entire flow volume, packet counts, and rates to deep negative baseline
        intervened = np.where(intervened > -1.5, -1.5, intervened)  # Push to quiescent baseline
        
    elif action == MitigationAction.ISOLATE_HOST:
        # Complete network isolation: suppress all external traffic features
        intervened = np.full_like(intervened, fill_value=-2.0)  # Total zero-trust silence
        
    return intervened
