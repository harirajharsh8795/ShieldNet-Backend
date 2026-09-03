import os
from pathlib import Path

p = Path("dataset")
print("=" * 70)
print(f"{'Folder / File Name':<35} | {'Size (MB)':<12} | {'File Type'}")
print("=" * 70)

for item in sorted(p.iterdir()):
    if item.is_dir():
        total_bytes = sum(f.stat().st_size for f in item.glob("**/*") if f.is_file())
        file_count = len(list(item.glob("**/*")))
        print(f"{item.name:<35} | {total_bytes / (1024*1024):<12.1f} | Directory ({file_count} files)")
    else:
        print(f"{item.name:<35} | {item.stat().st_size / (1024*1024):<12.1f} | File")
print("=" * 70)
