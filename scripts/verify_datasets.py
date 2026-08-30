"""
Dataset verification and manifest generation script.
Verifies downloaded datasets, checks row counts, and generates MANIFEST.md files.
"""

import os
import sys
import hashlib
import pandas as pd
from datetime import datetime
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def compute_md5(filepath, chunk_size=8192):
    """Compute MD5 checksum of a file."""
    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
    return md5.hexdigest()


def verify_csv(filepath):
    """Verify a CSV file and return stats."""
    try:
        # Read with low_memory=False for mixed types
        df = pd.read_csv(filepath, low_memory=False, nrows=5)
        total_rows = sum(1 for _ in open(filepath, 'r', encoding='utf-8', errors='ignore')) - 1
        return {
            'filename': os.path.basename(filepath),
            'rows': total_rows,
            'columns': len(df.columns),
            'column_names': list(df.columns),
            'size_mb': round(os.path.getsize(filepath) / (1024 * 1024), 2),
            'md5': compute_md5(filepath),
            'status': 'OK'
        }
    except Exception as e:
        return {
            'filename': os.path.basename(filepath),
            'status': f'ERROR: {str(e)}',
            'rows': 0,
            'columns': 0,
            'size_mb': round(os.path.getsize(filepath) / (1024 * 1024), 2) if os.path.exists(filepath) else 0
        }


def generate_manifest(dataset_dir, dataset_name, source_url):
    """Generate MANIFEST.md for a dataset directory."""
    csv_files = sorted(Path(dataset_dir).glob('*.csv'))
    
    if not csv_files:
        print(f"  WARNING: No CSV files found in {dataset_dir}")
        return False
    
    results = []
    total_rows = 0
    total_size = 0
    
    for csv_file in csv_files:
        print(f"  Verifying {csv_file.name}...")
        stats = verify_csv(str(csv_file))
        results.append(stats)
        total_rows += stats.get('rows', 0)
        total_size += stats.get('size_mb', 0)
    
    # Write MANIFEST.md
    manifest_path = os.path.join(dataset_dir, 'MANIFEST.md')
    with open(manifest_path, 'w') as f:
        f.write(f"# {dataset_name} — Dataset Manifest\n\n")
        f.write(f"**Source URL:** {source_url}\n")
        f.write(f"**Download Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"**Total Files:** {len(csv_files)}\n")
        f.write(f"**Total Rows:** {total_rows:,}\n")
        f.write(f"**Total Size:** {total_size:.2f} MB\n\n")
        f.write("## File Details\n\n")
        f.write("| File | Rows | Columns | Size (MB) | MD5 | Status |\n")
        f.write("|------|------|---------|-----------|-----|--------|\n")
        for r in results:
            f.write(f"| {r['filename']} | {r.get('rows', 'N/A'):,} | "
                    f"{r.get('columns', 'N/A')} | {r.get('size_mb', 'N/A')} | "
                    f"`{r.get('md5', 'N/A')[:12]}...` | {r['status']} |\n")
        
        if results and results[0].get('column_names'):
            f.write(f"\n## Columns (from first file)\n\n")
            for col in results[0]['column_names']:
                f.write(f"- `{col}`\n")
    
    print(f"  Manifest written to {manifest_path}")
    print(f"  Total: {total_rows:,} rows, {total_size:.2f} MB across {len(csv_files)} files")
    return True


def main():
    raw_dir = PROJECT_ROOT / "data" / "raw"
    
    datasets = {
        'cic-ids-2018': {
            'name': 'CIC-IDS-2018',
            'source': 'https://www.unb.ca/cic/datasets/ids-2018.html (Kaggle mirror)'
        },
        'ctu-13': {
            'name': 'CTU-13',
            'source': 'https://www.stratosphereips.org/datasets-ctu13 (GitHub mirror)'
        }
    }
    
    all_ok = True
    for dir_name, info in datasets.items():
        dataset_dir = raw_dir / dir_name
        print(f"\n{'='*60}")
        print(f"Verifying {info['name']}...")
        print(f"{'='*60}")
        
        if not dataset_dir.exists():
            print(f"  MISSING: {dataset_dir} does not exist.")
            print(f"  See docs/DATASET_SETUP.md for download instructions.")
            all_ok = False
            continue
        
        ok = generate_manifest(str(dataset_dir), info['name'], info['source'])
        if not ok:
            all_ok = False
    
    if all_ok:
        print("\n✓ All datasets verified successfully.")
    else:
        print("\n✗ Some datasets are missing or have issues. See above.")
        sys.exit(1)


if __name__ == '__main__':
    main()
