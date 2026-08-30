"""
Replace all occurrences of ShieldNet with ShieldNet across the entire repository.
Preserves case:
- ShieldNet -> ShieldNet
- SHIELDNET -> SHIELDNET
- shieldnet -> shieldnet
- ShieldNet -> ShieldNet
"""

import os
from pathlib import Path

# Directories and files to process
ROOT_DIR = Path(".")

EXTENSIONS = {".py", ".tsx", ".ts", ".jsx", ".js", ".html", ".css", ".md", ".json", ".yaml", ".yml", ".txt", ".bat", ".sh"}

EXCLUDE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", ".vite"}

REPLACEMENTS = [
    ("ShieldNet Dual-Engine Ensemble", "ShieldNet Dual-Engine Ensemble"),
    ("SHIELDNET", "SHIELDNET"),
    ("ShieldNet", "ShieldNet"),
    ("ShieldNet", "ShieldNet"),
    ("shieldnet", "shieldnet"),
]

total_files_modified = 0
total_replacements = 0

for root, dirs, files in os.walk(ROOT_DIR):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
    
    for f in files:
        file_path = Path(root) / f
        if file_path.suffix.lower() in EXTENSIONS:
            try:
                content = file_path.read_text(encoding="utf-8")
                new_content = content
                file_count = 0
                
                for old_val, new_val in REPLACEMENTS:
                    count = new_content.count(old_val)
                    if count > 0:
                        new_content = new_content.replace(old_val, new_val)
                        file_count += count
                        
                if file_count > 0:
                    file_path.write_text(new_content, encoding="utf-8")
                    total_files_modified += 1
                    total_replacements += file_count
                    print(f"Updated: {file_path.as_posix()} ({file_count} replacements)")
            except Exception as e:
                # Binary or encoding issues
                pass

print(f"\nCompleted! Replaced ShieldNet with ShieldNet in {total_files_modified} files (Total replacements: {total_replacements}).")
