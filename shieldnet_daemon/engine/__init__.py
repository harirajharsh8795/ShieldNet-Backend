"""
ShieldNet Background Daemon Detection Engine.

Contains:
- ONNX Runtime inference wrapper with K=5 autoregressive rollout
- Confidence gate (hybrid ensemble blending)
- Gated SHAP explainability
- SQLite Action Ledger with tamper-evident hash-chaining
"""
