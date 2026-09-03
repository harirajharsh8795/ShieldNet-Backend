import glob
from pathlib import Path
import pandas as pd
from collections import Counter

csv_files = sorted(glob.glob("dataset/TrafficLabelling/*.csv"))
total_counter = Counter()

print("Reading label distributions from all 8 CSVs (chunked for memory safety)...")
for f in csv_files:
    fname = Path(f).name
    # read only Label column
    for chunk in pd.read_csv(f, usecols=lambda c: 'label' in c.lower(), chunksize=100000, encoding='latin1', low_memory=False):
        col = chunk.columns[0]
        cleaned = chunk[col].astype(str).str.strip()
        total_counter.update(cleaned)
    print(f"  Processed {fname}")

print("\n" + "=" * 60)
print(f"{'Attack Label in Full 3.12M Dataset':<35} | {'Flow Count':<12}")
print("-" * 60)
for lbl, cnt in total_counter.most_common():
    print(f"{lbl:<35} | {cnt:>12,}")
print("=" * 60)
