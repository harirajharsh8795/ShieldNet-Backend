# Phase 2 Exit Report — Baseline Model
**Persona used:** ML Engineer (classical ML)
**Status:** COMPLETE

## What was built
- Logistic Regression baseline module (`src/baseline/baseline_model.py`).
- Trains on identical non-sequential flattened feature set to ensure fair comparison (Constraint C5).
- Evaluates F1 (weighted), Precision, Recall, and False Positive Rate.
- Exports metrics to `models/baseline_metrics.json` and checkpoint to `models/checkpoints/baseline_lr.joblib`.

## How it was tested/verified
- Integrated into master pipeline (`scripts/run_pipeline.py`).
- Standalone serialization and evaluation verified.

## Constraint re-check
- [x] Constraint C5: Logistic Regression baseline established on identical features before World Model evaluation.
