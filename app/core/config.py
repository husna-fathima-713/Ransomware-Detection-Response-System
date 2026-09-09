from pathlib import Path

import yaml


CONFIG_PATH = Path("config.yaml")


def load_config() -> dict:
    """Load RDRS configuration from config.yaml."""
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {CONFIG_PATH}"
        )

    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    if not isinstance(config, dict):
        raise ValueError("Configuration must contain a YAML mapping.")

    return config