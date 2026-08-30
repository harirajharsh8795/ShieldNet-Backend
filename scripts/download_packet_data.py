"""
Download script for CIC-IDS2017 Packet-Fields data.
Downloads specified file(s) from HuggingFace dataset `rdpahalavan/CIC-IDS2017`.
"""

import sys
import os
from pathlib import Path
import pyarrow.parquet as pq

def download_file(file_num: int = 1, output_dir: str = "dataset/CIC-IDS2017/Packet-Fields"):
    from huggingface_hub import hf_hub_download
    
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    filename = f"Packet_Fields_File_{file_num}.parquet"
    target_path = out_dir / filename
    
    print(f"Downloading {filename} from HuggingFace (rdpahalavan/CIC-IDS2017)...")
    downloaded_path = hf_hub_download(
        repo_id="rdpahalavan/CIC-IDS2017",
        subfolder="Packet-Fields",
        filename=filename,
        repo_type="dataset",
        local_dir="dataset/CIC-IDS2017",
        local_dir_use_symlinks=False
    )
    
    print(f"Downloaded to: {downloaded_path}")
    
    # Verify file integrity with pyarrow
    parquet_file = pq.ParquetFile(downloaded_path)
    metadata = parquet_file.metadata
    num_rows = metadata.num_rows
    num_cols = metadata.num_columns
    num_row_groups = metadata.num_row_groups
    file_size_mb = os.path.getsize(downloaded_path) / (1024 * 1024)
    
    print(f"Integrity Check PASSED:")
    print(f"  Rows: {num_rows:,}")
    print(f"  Columns: {num_cols}")
    print(f"  Row Groups: {num_row_groups}")
    print(f"  File Size: {file_size_mb:.2f} MB")
    
    return downloaded_path

if __name__ == "__main__":
    file_num = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    download_file(file_num)
