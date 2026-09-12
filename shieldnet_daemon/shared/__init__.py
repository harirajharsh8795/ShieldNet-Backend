"""
ShieldNet Shared Detection Engine Package.

Importable by both training pipelines and the background daemon.
Contains:
- Canonical 84-feature schema definitions
- Flow-level & packet-level feature extraction
- Rolling per-flow buffer with temporal windowing
- Production-grade frozen reference scaler guard
"""

from .schema import (
    CANONICAL_84_FEATURES,
    CANONICAL_FLOW_FEATURES,
    CANONICAL_PACKET_FEATURES,
    NUM_CANONICAL_FEATURES,
    NUM_FLOW_FEATURES,
    NUM_PACKET_FEATURES,
    CONTEXT_LENGTH,
    FEATURE_TO_IDX,
    IDX_TO_FEATURE,
    ATTACK_CLASSES,
    MITRE_STAGES,
    validate_feature_vector,
)

from .feature_extractor import (
    PacketMetadata,
    compute_flow_features,
    parse_scapy_packet,
    adapt_dataframe_to_canonical,
)

from .scaler_guard import FrozenReferenceScalerGuard

from .rolling_buffer import (
    FlowRecord,
    RollingFlowBuffer,
)

__all__ = [
    "CANONICAL_84_FEATURES",
    "CANONICAL_FLOW_FEATURES",
    "CANONICAL_PACKET_FEATURES",
    "NUM_CANONICAL_FEATURES",
    "NUM_FLOW_FEATURES",
    "NUM_PACKET_FEATURES",
    "CONTEXT_LENGTH",
    "FEATURE_TO_IDX",
    "IDX_TO_FEATURE",
    "ATTACK_CLASSES",
    "MITRE_STAGES",
    "validate_feature_vector",
    "PacketMetadata",
    "compute_flow_features",
    "parse_scapy_packet",
    "adapt_dataframe_to_canonical",
    "FrozenReferenceScalerGuard",
    "FlowRecord",
    "RollingFlowBuffer",
]
