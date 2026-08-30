# Multi-Scale World Model: Research Exploration (NOT USED IN SUBMISSION)

**Status:** ABANDONED — No checkpoint was saved. No verifiable metrics exist.  
**Submission Model:** `world_model_v1.pt` (single-scale L=3 GRU)

---

## What Was Attempted

A multi-scale architecture coupling a fine-grained GRU branch (L=3, 30s) with a coarse statistical pooling branch (L=10, 100s mean+max summary) was explored as a research direction during development.

The hypothesis was that coupling short and long temporal windows would improve detection of both rapid volumetric floods and slow multi-minute reconnaissance scans.

## Why It Was Abandoned

1. **No checkpoint was ever saved to disk.** The model existed only in RAM during experimental runs.
2. **Cross-dataset generalization collapsed** — coarse pooling over raw flow tables (without host-session grouping) corrupted the summary vectors with cross-host noise.
3. **All previously reported metrics for this architecture are UNVERIFIABLE** because no saved model weights exist to reproduce them.

## Official Decision

The single-scale (L=3) GRU World Model (`world_model_v1.pt`) is the ONLY model in this project. Multi-scale is documented here solely as a research note for potential future work with proper IP session tracking infrastructure.

> **AUDIT NOTE (2026-08-30):** This document was rewritten during a forensic audit. The original version contained specific performance numbers attributed to a "multiscale_world_model_v1.pt" checkpoint that never existed on disk. Those numbers have been removed as unverifiable.
