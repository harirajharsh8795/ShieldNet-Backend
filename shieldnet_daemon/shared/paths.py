"""
ShieldNet Resource Path Resolution.

Supports seamless asset resolution across both standard development environments
and PyInstaller frozen standalone binaries (sys._MEIPASS).
"""

from pathlib import Path
import sys
import os

# Project root resolution
SHARED_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SHARED_DIR.parent


def get_base_dir() -> Path:
    """Returns bundle directory if frozen with PyInstaller, else project root."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return PROJECT_ROOT


def get_resource_path(relative_path: str) -> Path:
    """
    Resolves path to static resources (models, ONNX checkpoints, HTML templates).
    If frozen, looks inside PyInstaller _MEIPASS; otherwise inside repository.
    """
    base = get_base_dir()
    target = base / relative_path
    if target.exists():
        return target
    # Fallback to repository root if not in bundle
    repo_target = PROJECT_ROOT / relative_path
    return repo_target


def get_data_dir() -> Path:
    """
    Resolves path for mutable runtime data (ledger.db, daemon_status.json).
    Mutable databases should NOT be written into _MEIPASS (which is ephemeral/read-only).
    Instead, they are written to a persistent 'data' folder alongside the executable
    or inside the project root.
    """
    if getattr(sys, "frozen", False):
        # Alongside the executable
        exe_dir = Path(sys.executable).resolve().parent
        data_dir = exe_dir / "data"
    else:
        data_dir = PROJECT_ROOT / "data"

    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir
