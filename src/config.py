"""
ShieldNet configuration loader.
Loads and validates config from YAML files with defaults.
"""

import os
import yaml
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent

DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configs" / "default.yaml"


def load_config(config_path=None):
    """Load configuration from YAML file.
    
    Args:
        config_path: Path to config YAML. Defaults to configs/default.yaml.
    
    Returns:
        dict: Configuration dictionary.
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH
    
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Resolve relative paths against project root
    if 'data' in config:
        for key in ['raw_dir', 'processed_dir', 'cic_ids_2018_dir', 'ctu_13_dir']:
            if key in config['data']:
                path = config['data'][key]
                if not os.path.isabs(path):
                    config['data'][key] = str(PROJECT_ROOT / path)
    
    return config


def get_project_root():
    """Return the project root directory."""
    return PROJECT_ROOT
