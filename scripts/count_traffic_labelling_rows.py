import os
import glob
import pandas as pd
from pathlib import Path

csv_dir = Path("dataset/TrafficLabelling")
csv_files = sorted(glob.glob(str(csv_dir / "*.csv")))

print(f"Found {len(csv_files)} CSV files in {csv_dir}:")
total_rows = 0
for f in csv_files:
    fname = Path(f).name
    # Fast row count
    with open(f, 'rb') as fp:
        lines = sum(1 for _ in fp) - 1  # Minus header
    total_rows += lines
    print(f"  {fname:<50}: {lines:>10,} rows")

print("=" * 65)
print(f"TOTAL DATASET ROWS: {total_rows:>10,} flows")
