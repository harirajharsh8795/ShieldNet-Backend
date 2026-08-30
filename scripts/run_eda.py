"""
EDA Script for ShieldNet — Exploratory Data Analysis of Network Traffic Datasets.
Covers: class distribution, missing values, feature ranges, and attack type summary.

This script generates the EDA analysis that would normally be in a Jupyter notebook.
Results are printed and key stats are saved to docs/eda_summary.md.
"""

import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import numpy as np


def analyze_dataset(csv_files, dataset_name):
    """Run EDA on a list of CSV files from a dataset."""
    print(f"\n{'='*70}")
    print(f"  EDA: {dataset_name}")
    print(f"{'='*70}")
    
    # Load all files
    dfs = []
    for f in sorted(csv_files):
        df = pd.read_csv(f, low_memory=False)
        print(f"  Loaded {f.name}: {len(df):,} rows × {len(df.columns)} cols")
        dfs.append(df)
    
    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n  Combined: {len(combined):,} rows × {len(combined.columns)} cols")
    
    results = {
        'name': dataset_name,
        'total_rows': len(combined),
        'total_cols': len(combined.columns),
        'files': len(csv_files),
    }
    
    # ─── Class Distribution ───────────────────────────────────────────
    label_col = None
    for candidate in ['label', 'Label', 'class', 'attack_cat', 'detailed_label']:
        if candidate in combined.columns:
            label_col = candidate
            break
    
    if label_col:
        print(f"\n  Class Distribution (column: '{label_col}'):")
        print(f"  {'─'*50}")
        class_counts = combined[label_col].value_counts()
        class_pcts = combined[label_col].value_counts(normalize=True) * 100
        
        class_table = []
        for cls in class_counts.index:
            count = class_counts[cls]
            pct = class_pcts[cls]
            bar = '█' * int(pct / 2)
            print(f"  {cls:>30s}: {count:>8,} ({pct:5.1f}%) {bar}")
            class_table.append({'class': cls, 'count': count, 'pct': round(pct, 2)})
        
        results['label_col'] = label_col
        results['class_distribution'] = class_table
        results['n_classes'] = len(class_counts)
        results['majority_class'] = class_counts.index[0]
        results['majority_pct'] = round(class_pcts.iloc[0], 2)
    else:
        print("  WARNING: No label column found!")
        results['label_col'] = None
    
    # ─── Missing Values ──────────────────────────────────────────────
    print(f"\n  Missing Values Report:")
    print(f"  {'─'*50}")
    missing = combined.isnull().sum()
    missing_pct = (missing / len(combined)) * 100
    missing_cols = missing[missing > 0].sort_values(ascending=False)
    
    if len(missing_cols) == 0:
        print("  No missing values found! ✓")
    else:
        for col in missing_cols.index[:20]:
            print(f"  {col:>35s}: {missing[col]:>8,} ({missing_pct[col]:5.1f}%)")
        if len(missing_cols) > 20:
            print(f"  ... and {len(missing_cols) - 20} more columns with missing values")
    
    results['missing_cols_count'] = len(missing_cols)
    results['total_missing'] = int(missing.sum())
    
    # ─── Feature Ranges (numeric only) ───────────────────────────────
    print(f"\n  Feature Range Summary (numeric columns):")
    print(f"  {'─'*50}")
    numeric_cols = combined.select_dtypes(include=[np.number]).columns
    print(f"  {len(numeric_cols)} numeric features found")
    
    range_data = []
    for col in numeric_cols[:30]:
        stats = combined[col].describe()
        inf_count = np.isinf(combined[col]).sum() if combined[col].dtype in [np.float64, np.float32] else 0
        range_data.append({
            'feature': col,
            'min': round(stats['min'], 4) if pd.notna(stats['min']) else 'NaN',
            'max': round(stats['max'], 4) if pd.notna(stats['max']) else 'NaN',
            'mean': round(stats['mean'], 4) if pd.notna(stats['mean']) else 'NaN',
            'std': round(stats['std'], 4) if pd.notna(stats['std']) else 'NaN',
            'inf_count': inf_count,
        })
        if inf_count > 0:
            print(f"  ⚠ {col}: contains {inf_count} infinite values")
    
    results['numeric_features'] = len(numeric_cols)
    results['inf_features'] = sum(1 for r in range_data if r['inf_count'] > 0)
    
    # ─── Attack Types Present ─────────────────────────────────────────
    if label_col:
        attack_types = [c for c in combined[label_col].unique() 
                       if c not in ['Benign', 'Normal', 'Background', 'BENIGN']]
        print(f"\n  Attack Types Present ({len(attack_types)}):")
        print(f"  {'─'*50}")
        for at in sorted(attack_types):
            count = (combined[label_col] == at).sum()
            print(f"  • {at} ({count:,} flows)")
        results['attack_types'] = sorted(attack_types)
    
    return results


def write_eda_summary(all_results, output_path):
    """Write EDA summary to markdown file."""
    with open(output_path, 'w') as f:
        f.write("# ShieldNet — Exploratory Data Analysis Summary\n\n")
        f.write(f"**Generated:** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')}\n\n")
        
        for res in all_results:
            f.write(f"## {res['name']}\n\n")
            f.write(f"- **Files:** {res['files']}\n")
            f.write(f"- **Total Rows:** {res['total_rows']:,}\n")
            f.write(f"- **Total Columns:** {res['total_cols']}\n")
            f.write(f"- **Numeric Features:** {res['numeric_features']}\n")
            f.write(f"- **Missing Value Columns:** {res['missing_cols_count']}\n")
            f.write(f"- **Label Column:** `{res.get('label_col', 'N/A')}`\n")
            f.write(f"- **Number of Classes:** {res.get('n_classes', 'N/A')}\n\n")
            
            if 'class_distribution' in res:
                f.write("### Class Distribution\n\n")
                f.write("| Class | Count | % |\n|-------|-------|---|\n")
                for cd in res['class_distribution']:
                    f.write(f"| {cd['class']} | {cd['count']:,} | {cd['pct']}% |\n")
                f.write("\n")
            
            if 'attack_types' in res:
                f.write("### Attack Types\n\n")
                for at in res['attack_types']:
                    f.write(f"- {at}\n")
                f.write("\n")
            
            f.write("---\n\n")
    
    print(f"\n  EDA summary saved to {output_path}")


def main():
    raw_dir = PROJECT_ROOT / "data" / "raw"
    docs_dir = PROJECT_ROOT / "docs"
    
    all_results = []
    
    # CIC-IDS-2018
    cic_dir = raw_dir / "cic-ids-2018"
    if cic_dir.exists():
        cic_files = list(cic_dir.glob("*.csv"))
        if cic_files:
            results = analyze_dataset(cic_files, "CIC-IDS-2018")
            all_results.append(results)
    else:
        print(f"SKIP: {cic_dir} not found. Run scripts/generate_synthetic_data.py first.")
    
    # CTU-13
    ctu_dir = raw_dir / "ctu-13"
    if ctu_dir.exists():
        ctu_files = list(ctu_dir.glob("*.csv"))
        if ctu_files:
            results = analyze_dataset(ctu_files, "CTU-13")
            all_results.append(results)
    else:
        print(f"SKIP: {ctu_dir} not found. Run scripts/generate_synthetic_data.py first.")
    
    if all_results:
        write_eda_summary(all_results, docs_dir / "eda_summary.md")
        print("\n✓ EDA complete.")
    else:
        print("\n✗ No datasets found. Generate synthetic data first.")
        sys.exit(1)


if __name__ == '__main__':
    main()
