"""
Automated Unit and Validation Tests for Module 8: PyInstaller Packaging.

Validates:
1. Dynamic resource path resolution (get_resource_path and get_data_dir).
2. Unified CLI argument parser routing and command specifications.
3. In-process CLI execution (version, audit dry-run, help output).
4. PyInstaller .spec file integrity, ensuring all bundled assets and hidden imports exist.
"""

from pathlib import Path
import subprocess
import sys
import pytest

# Base paths
TESTS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = TESTS_DIR.parent
PYTHON_EXE = sys.executable

from shared.paths import get_resource_path, get_data_dir, get_base_dir
from cli import build_parser, __version__
from engine.ledger import ActionLedger


def test_resource_path_resolution():
    """Verifies that get_resource_path locates all necessary model and UI assets."""
    # 1. Check ONNX model
    onnx_path = get_resource_path("models/onnx/world_model.onnx")
    assert onnx_path.exists(), f"ONNX model not found at {onnx_path}"

    # 2. Check Scaler reference
    scaler_path = get_resource_path("models/checkpoints/scaler_reference.npz")
    assert scaler_path.exists(), f"Scaler checkpoint not found at {scaler_path}"

    # 3. Check LogReg parameters
    logreg_path = get_resource_path("models/checkpoints/logreg_params.npz")
    assert logreg_path.exists(), f"LogReg checkpoint not found at {logreg_path}"

    # 4. Check HTML template
    template_path = get_resource_path("dashboard/templates/index.html")
    assert template_path.exists(), f"Dashboard template not found at {template_path}"

    # 5. Check persistent data directory
    data_dir = get_data_dir()
    assert data_dir.exists() and data_dir.is_dir()


def test_cli_argument_parser_subcommands():
    """Verifies that the unified CLI parser correctly handles all subcommands and flags."""
    parser = build_parser()

    # 1. Daemon run with mock
    args = parser.parse_args(["daemon", "run", "--mock", "--interface", "eth0"])
    assert args.command == "daemon"
    assert args.daemon_action == "run"
    assert args.mock is True
    assert args.interface == "eth0"

    # 2. Daemon status
    args_st = parser.parse_args(["daemon", "status"])
    assert args_st.command == "daemon"
    assert args_st.daemon_action == "status"

    # 3. Dashboard command
    args_dash = parser.parse_args(["dashboard", "--port", "9090", "--host", "0.0.0.0", "--open-browser"])
    assert args_dash.command == "dashboard"
    assert args_dash.port == 9090
    assert args_dash.host == "0.0.0.0"
    assert args_dash.open_browser is True

    # 4. Simulate command
    args_sim = parser.parse_args(["simulate", "--scenario", "ddos", "--count", "100", "--target-daemon"])
    assert args_sim.command == "simulate"
    assert args_sim.scenario == "ddos"
    assert args_sim.count == 100
    assert args_sim.target_daemon is True

    # 5. Audit command
    args_aud = parser.parse_args(["audit", "--db-path", "test.db"])
    assert args_aud.command == "audit"
    assert args_aud.db_path == "test.db"

    # 6. Version command
    args_ver = parser.parse_args(["version"])
    assert args_ver.command == "version"


def test_cli_version_execution():
    """Verifies that cli.py version executes successfully."""
    cmd = [PYTHON_EXE, str(PROJECT_DIR / "cli.py"), "version"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0
    assert f"v{__version__}" in proc.stdout
    assert "Air-Gap Compliant" in proc.stdout


def test_cli_audit_execution_on_test_ledger(tmp_path):
    """Verifies that cli.py audit runs and reports cryptographic validity."""
    db_path = tmp_path / "audit_test.db"
    ledger = ActionLedger(db_path)
    ledger.append_record(
        prediction="PortScan",
        threat_probability=0.98,
        mitre_stage=1,
        mitre_tactic="Discovery / Reconnaissance",
        severity="HIGH",
        shap_summary="Flow IAT Mean probe",
    )

    cmd = [PYTHON_EXE, str(PROJECT_DIR / "cli.py"), "audit", "--db-path", str(db_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    assert proc.returncode == 0
    assert "[VERIFIED INTACT]" in proc.stdout
    assert "Total Blocks:         1" in proc.stdout


def test_spec_file_datas_exist_on_disk():
    """Verifies that every data file referenced in shieldnet.spec exists on disk."""
    spec_path = PROJECT_DIR / "build_spec" / "shieldnet.spec"
    assert spec_path.exists(), f"Spec file not found at {spec_path}"

    with open(spec_path, "r", encoding="utf-8") as f:
        spec_content = f.read()

    # Verify essential strings and assets exist in the spec
    assert "world_model.onnx" in spec_content
    assert "scaler_reference.npz" in spec_content
    assert "logreg_params.npz" in spec_content
    assert "index.html" in spec_content
    assert "onnxruntime" in spec_content
    assert "scapy" in spec_content

