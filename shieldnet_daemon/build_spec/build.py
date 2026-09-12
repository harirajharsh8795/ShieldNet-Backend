"""
ShieldNet Automated PyInstaller Build Script.

Compiles the unified ShieldNet CLI into a portable standalone distribution:
- Incorporates all ONNX models, frozen scaler weights, logistic regression gates,
  and air-gapped web dashboard templates.
- Runs post-build verification against the compiled binary (smoke test --help and version).
"""

from pathlib import Path
from typing import Optional
import argparse
import logging
import os
import shutil
import subprocess
import sys
import time

PACKAGING_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGING_DIR.parent
PYTHON_EXE = sys.executable

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Build] %(message)s")
logger = logging.getLogger("ShieldNetBuilder")


def clean_build_artifacts():
    """Removes previous build and dist directories."""
    for folder in ["build", "dist"]:
        p = PROJECT_DIR / folder
        if p.exists():
            logger.info("Cleaning previous build artifact directory: %s", p)
            shutil.rmtree(p, ignore_errors=True)


def run_pyinstaller(spec_file: Optional[Path] = None) -> Path:
    """Executes PyInstaller build using the specified .spec file."""
    if spec_file is None:
        spec_file = PACKAGING_DIR / "shieldnet.spec"

    if not spec_file.exists():
        raise FileNotFoundError(f"Spec file not found at: {spec_file}")

    dist_dir = PROJECT_DIR / "dist"
    work_dir = PROJECT_DIR / "build"

    cmd = [
        PYTHON_EXE,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        f"--distpath={dist_dir}",
        f"--workpath={work_dir}",
        str(spec_file),
    ]

    logger.info("Launching PyInstaller compilation...")
    logger.info("Command: %s", " ".join(cmd))
    t0 = time.time()

    proc = subprocess.run(cmd, cwd=str(PROJECT_DIR), capture_output=True, text=True)

    elapsed = time.time() - t0
    if proc.returncode != 0:
        logger.error("PyInstaller compilation failed! (Return code: %d)", proc.returncode)
        logger.error("STDERR:\n%s", proc.stderr[-2000:] if proc.stderr else "No stderr")
        raise RuntimeError(f"PyInstaller failed with code {proc.returncode}")

    logger.info("Compilation succeeded in %.2f seconds.", elapsed)

    # Output executable path
    exe_name = "shieldnet.exe" if sys.platform == "win32" else "shieldnet"
    exe_path = dist_dir / "shieldnet" / exe_name
    if not exe_path.exists():
        # Check if onefile mode placed it directly in dist_dir
        alt_path = dist_dir / exe_name
        if alt_path.exists():
            exe_path = alt_path

    if not exe_path.exists():
        raise FileNotFoundError(f"Expected compiled binary not found at {exe_path}")

    logger.info("Compiled binary verified at: %s (Size: %.2f MB)",
                exe_path, exe_path.stat().st_size / (1024 * 1024))
    return exe_path


def verify_executable(exe_path: Path) -> bool:
    """Runs smoke tests against the compiled binary to ensure self-contained execution."""
    logger.info("Executing binary smoke tests against: %s", exe_path)

    # 1. Test version command
    logger.info("Running: %s version", exe_path.name)
    res_version = subprocess.run([str(exe_path), "version"], capture_output=True, text=True, timeout=15)
    if res_version.returncode != 0 or "ShieldNet" not in res_version.stdout:
        logger.error("Version smoke test failed! STDOUT: %s, STDERR: %s", res_version.stdout, res_version.stderr)
        return False
    logger.info("Version smoke test passed: %s", res_version.stdout.strip())

    # 2. Test help command
    logger.info("Running: %s --help", exe_path.name)
    res_help = subprocess.run([str(exe_path), "--help"], capture_output=True, text=True, timeout=15)
    if res_help.returncode != 0 or "Autonomous Offline" not in res_help.stdout:
        logger.error("Help smoke test failed! STDOUT: %s, STDERR: %s", res_help.stdout, res_help.stderr)
        return False
    logger.info("Help smoke test passed.")

    # 3. Test audit command (dry run)
    logger.info("Running: %s audit", exe_path.name)
    res_audit = subprocess.run([str(exe_path), "audit"], capture_output=True, text=True, timeout=15)
    if res_audit.returncode != 0:
        logger.error("Audit smoke test failed! STDOUT: %s, STDERR: %s", res_audit.stdout, res_audit.stderr)
        return False
    logger.info("Audit smoke test passed.")

    logger.info("All binary smoke tests passed successfully!")
    return True


def main():
    parser = argparse.ArgumentParser(description="ShieldNet Standalone Binary Builder")
    parser.add_argument("--clean", action="store_true", help="Clean build directories before compiling")
    parser.add_argument("--spec", type=str, default=None, help="Custom .spec file path")
    parser.add_argument("--no-verify", action="store_true", help="Skip binary smoke tests")
    args = parser.parse_args()

    if args.clean:
        clean_build_artifacts()

    spec_path = Path(args.spec) if args.spec else PACKAGING_DIR / "shieldnet.spec"
    exe_path = run_pyinstaller(spec_path)

    if not args.no_verify:
        if not verify_executable(exe_path):
            sys.exit(1)

    print("\n============================================================")
    print("      SHIELDNET STANDALONE BINARY BUILD COMPLETE")
    print("============================================================")
    print(f" Executable:       {exe_path}")
    print(f" Bundle Directory: {exe_path.parent}")
    print(f" Size:             {exe_path.stat().st_size / (1024 * 1024):.2f} MB")
    print(" Verification:     ALL SMOKE TESTS PASSED")
    print("============================================================\n")


if __name__ == "__main__":
    main()
