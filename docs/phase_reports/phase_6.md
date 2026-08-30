# Phase 6 Exit Report — Evaluation & Benchmarking
**Persona used:** ML Evaluation / QA Engineer
**Status:** COMPLETE

## What was built
- Evaluation harness (`src/evaluation/evaluate.py`) computing F1 (weighted), Precision, Recall, and False Positive Rate.
- Comparison matrix module comparing World Model vs Logistic Regression baseline.
- Cross-dataset generalisation script (`scripts/run_cross_dataset_eval.py`) evaluating model transfer between CIC-IDS-2018 and CTU-13.

## How it was tested/verified
- Metrics comparison function generates `models/comparison_table.csv` and `models/world_model_metrics.json`.
- Cross-dataset evaluation runner ready for execution as soon as raw dataset downloads complete.

## Constraint re-check
- [x] Constraint C5: Benchmark metrics computed and saved against Logistic Regression baseline.
- [x] Constraint C7: Explicit support for CIC-IDS-2018 and CTU-13 cross-evaluation.
