# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Specification for ShieldNet Standalone Portable Executable.

Bundles:
- Unified CLI entrypoint (shieldnet cli.py)
- ONNX Runtime inference engine & GRU+Attention model
- Gated ensemble parameters & reference scaler guards
- Action Ledger & cryptographic hash-chaining engine
- Headless background service orchestrator
- Decoupled web monitoring dashboard & air-gapped SPA templates
"""

from pathlib import Path
import sys

block_cipher = None

SPEC_DIR = Path(SPECPATH)
PROJECT_DIR = SPEC_DIR.parent

# Data assets to bundle directly into binary package
datas = [
    (str(PROJECT_DIR / "models" / "onnx" / "world_model.onnx"), "models/onnx"),
    (str(PROJECT_DIR / "models" / "checkpoints" / "scaler_reference.npz"), "models/checkpoints"),
    (str(PROJECT_DIR / "models" / "checkpoints" / "logreg_params.npz"), "models/checkpoints"),
    (str(PROJECT_DIR / "models" / "checkpoints" / "feature_columns.json"), "models/checkpoints"),
    (str(PROJECT_DIR / "dashboard" / "templates" / "index.html"), "dashboard/templates"),
]

# Explicit hidden imports for dynamic ONNX, Scapy, and scikit-learn loaders
hiddenimports = [
    "scapy.layers.inet",
    "scapy.layers.l2",
    "scapy.sendrecv",
    "scapy.all",
    "onnxruntime",
    "sklearn",
    "sklearn.utils._typedefs",
    "sklearn.neighbors._typedefs",
    "sklearn.tree._utils",
    "shap",
    "shap.explainers._kernel",
    "shared",
    "shared.schema",
    "shared.feature_extractor",
    "shared.rolling_buffer",
    "shared.scaler_guard",
    "shared.paths",
    "engine",
    "engine.inference",
    "engine.confidence_gate",
    "engine.explainer",
    "engine.ledger",
    "daemon",
    "daemon.service",
    "daemon.windows_service",
    "dashboard",
    "dashboard.app",
    "scripts.simulate_traffic",
]

a = Analysis(
    [str(PROJECT_DIR / "cli.py")],
    pathex=[str(PROJECT_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "PIL", "notebook", "IPython"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="shieldnet",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="shieldnet",
)
