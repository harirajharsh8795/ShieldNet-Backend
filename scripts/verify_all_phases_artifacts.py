"""
NetGuard Comprehensive Artifact Verification Script.
Checks existence and status of every artifact from Phase 0 to Phase 8.
"""

import os
from pathlib import Path

ARTIFACTS = {
    "Phase 0: Environment & Architecture": [
        "README.md",
        "docs/DATASET_SETUP.md",
        "docs/MODEL_ARCHITECTURE.md",
        "requirements.txt",
    ],
    "Phase 0.5: Ingestion & Verification": [
        "data/processed/fused_matched_v1.parquet",
        "data/processed/flow_only_full.parquet",
        "docs/DATA_DICTIONARY.md",
    ],
    "Phase 1: Feature Engineering & Temporal Sequences": [
        "data/processed/train_v1.parquet",
        "data/processed/val_v1.parquet",
        "data/processed/test_v1.parquet",
        "data/processed/sequences_train.parquet",
        "data/processed/sequences_val.parquet",
        "data/processed/sequences_test.parquet",
        "models/checkpoints/scaler.joblib",
        "models/checkpoints/feature_columns.json",
    ],
    "Phase 2: Static Baseline Modeling": [
        "models/checkpoints/baseline_logreg_configA.joblib",
        "models/checkpoints/baseline_comparison_metrics.json",
    ],
    "Phase 3: World Model Architecture & Ablation": [
        "models/checkpoints/world_model_v1.pt",
        "models/checkpoints/multiseed_stability_audit.json",
        "models/checkpoints/final_shuffle_ablation_audit.json",
    ],
    "Phase 4: Forward Rollout & Counterfactual Simulation": [
        "src/simulation/rollout.py",
        "src/mitigation/counterfactual_engine.py",
        "src/mitigation/safety_shield.py",
        "src/mitigation/actions.py",
    ],
    "Phase 5: Explainability & Temporal Attention": [
        "src/explainability/feature_attribution.py",
        "models/checkpoints/xai_explanations.json",
    ],
    "Phase 6: Empirical Benchmark & Cross-Dataset Generalization": [
        "models/checkpoints/unsw_real_evaluation.json",
        "models/checkpoints/cicids2018_real_evaluation.json",
        "models/checkpoints/darpa1998_real_evaluation.json",
        "docs/EVALUATION_REPORT.md",
    ],
    "Phase 7: React + Vite Interactive Product & FastAPI Backend": [
        "src/api/server.py",
        "frontend/package.json",
        "frontend/src/App.tsx",
        "frontend/src/pages/HomePage.tsx",
        "frontend/src/pages/SimulationPage.tsx",
        "frontend/src/pages/UploadPage.tsx",
        "frontend/src/pages/ComparePage.tsx",
        "frontend/src/pages/ArchitecturePage.tsx",
    ],
    "Phase 8: Submission Packaging": [
        "docs/SLIDES_5SLIDES_OUTLINE.md",
        "docs/ARCHITECTURE_DOCUMENT_2PAGE.md",
        "docs/DEMO_VIDEO_SCRIPT.md",
        "docs/screenshots/landing_hero_final_1787998019396.png",
        "docs/screenshots/live_simulation_rollout_final_1787998247445.png",
        "docs/screenshots/landing_benchmarks_final_1787998149165.png",
    ],
    "Phase 9: Graph World Model (Optional Stretch Goal)": [
        "scripts/train_eval_graph_world_model.py",
        "models/checkpoints/graph_variant_audit.json",
        "docs/GRAPH_VARIANT_INVESTIGATION.md",
    ],
    "Phase 10: Model Tournament (Unified Bake-Off)": [
        "src/tournament/run_candidate.py",
        "src/tournament/candidates/lstm_model.py",
        "src/tournament/candidates/tcn_model.py",
        "src/tournament/candidates/vae_mdn_rnn_model.py",
        "src/tournament/candidates/xgboost_model.py",
        "src/tournament/candidates/cascade_model.py",
        "models/checkpoints/tournament_summary.json",
        "docs/MODEL_TOURNAMENT_RESULTS.md",
    ]
}

def main():
    print("=" * 95)
    print("NETGUARD PHASE-BY-PHASE ARTIFACT EXISTENCE VERIFICATION")
    print("=" * 95)
    
    total_files = 0
    existing_files = 0
    
    for phase_name, files in ARTIFACTS.items():
        print(f"\n[{phase_name}]")
        all_phase_ok = True
        for fpath in files:
            p = Path(fpath)
            exists = p.exists()
            total_files += 1
            if exists:
                existing_files += 1
                sz = p.stat().st_size
                sz_str = f"{sz/1024:.1f} KB" if sz < 1024*1024 else f"{sz/(1024*1024):.1f} MB"
                print(f"  [EXISTS] {fpath:65s} ({sz_str})")
            else:
                all_phase_ok = False
                print(f"  [MISSING] {fpath:65s}")
                
    print("\n" + "=" * 95)
    print(f"TOTAL ARTIFACTS AUDITED: {existing_files} / {total_files} confirmed present on disk ({(existing_files/total_files)*100:.1f}%)")
    print("=" * 95)

if __name__ == "__main__":
    main()
