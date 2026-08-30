# Dataset Setup Guide

## Required Datasets

### 1. CIC-IDS-2018
**Source:** Canadian Institute for Cybersecurity
**Official URL:** https://www.unb.ca/cic/datasets/ids-2018.html

#### Option A: AWS S3 (Original, ~80GB)
```bash
aws s3 sync --no-sign-request s3://cse-cic-ids2018/ data/raw/cic-ids-2018/
```

#### Option B: Kaggle CSV Mirror (Recommended for development)
```bash
pip install kaggle
kaggle datasets download -d solarmainframe/ids-intrusion-csv -p data/raw/cic-ids-2018/ --unzip
```

**Expected files after download:**
- Multiple CSV files (one per day of capture): Friday-02-02-2018, Thursday-01-03-2018, etc.
- Each CSV contains 80+ CICFlowMeter-extracted features
- Total rows: ~16 million across all files

### 2. CTU-13
**Source:** Stratosphere IPS, Czech Technical University
**Official URL:** https://www.stratosphereips.org/datasets-ctu13

#### Option A: Original Bulk Tarball (~30GB)
Download from the Stratosphere IPS website — contains raw PCAP + NetFlow.

#### Option B: GitHub CSV Mirror (Recommended for development)
```bash
git clone https://github.com/imfaisalmalik/CTU13-CSV-Dataset.git data/raw/ctu-13/
```

**Expected scenarios:** 13 scenarios, each containing botnet traffic mixed with normal traffic.
- Scenarios 1-13 with varying botnet types (Neris, Rbot, Virut, NSIS, Sogou, Murlo, Menti, etc.)

## Post-Download Verification

After downloading, run:
```bash
python scripts/verify_datasets.py
```

This will check file integrity, row counts, and generate manifests under `data/raw/*/MANIFEST.md`.

## Directory Structure After Setup
```
data/raw/
├── cic-ids-2018/
│   ├── MANIFEST.md (auto-generated)
│   ├── Friday-02-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
│   └── ... (more daily CSV files)
└── ctu-13/
    ├── MANIFEST.md (auto-generated)
    ├── scenario_1.csv
    ├── scenario_2.csv
    └── ... (13 scenarios)
```
