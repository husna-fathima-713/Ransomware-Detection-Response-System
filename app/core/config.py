
from copy import deepcopy
from pathlib import Path

import yaml


CONFIG_PATH = Path("config.yaml")

DEFAULT_CONFIG = {
    "monitoring": {
        "watch_paths": ["data/sandbox"],
        "scan_interval_seconds": 5,
        "sliding_window_seconds": 60,
    },
    "detection": {
        "thresholds": {
            "files_modified_per_minute": 20,
            "rename_count": 10,
            "extension_change_count": 5,
            "average_entropy": 7.2,
            "cpu_spike_percent": 80.0,
        },
    },
    "scoring": {
        "weights": {
            "rapid_encryption": 40,
            "mass_rename": 30,
            "high_entropy": 25,
            "cpu_spike": 15,
            "unknown_program": 10,
        },
        "levels": {
            "normal": 40,
            "warning": 70,
            "critical": 90,
        },
    },
    "response": {
        "simulation_mode": True,
        "quarantine_path": "data/quarantine",
    },
    "logging": {
        "directory": "logs",
        "level": "INFO",
    },
}


def _merge_defaults(config: dict, defaults: dict) -> dict:
    """Fill missing configuration values without overwriting user settings."""
    result = deepcopy(defaults)

    for key, value in config.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _merge_defaults(value, result[key])
        else:
            result[key] = value

    return result


def _require_mapping(value, name: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"Configuration section '{name}' must be a mapping.")


def _require_number(value, name: str, minimum=None, maximum=None) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"'{name}' must be a number.")

    if minimum is not None and value < minimum:
        raise ValueError(f"'{name}' must be at least {minimum}.")

    if maximum is not None and value > maximum:
        raise ValueError(f"'{name}' must not exceed {maximum}.")


def _require_positive_integer(value, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"'{name}' must be a positive integer.")


def validate_config(config: dict) -> None:
    """Validate configuration sections and supported values."""
    for section in ("monitoring", "detection", "scoring", "response", "logging"):
        _require_mapping(config.get(section), section)

    monitoring = config["monitoring"]

    watch_paths = monitoring.get("watch_paths")
    if (
        not isinstance(watch_paths, list)
        or not watch_paths
        or any(not isinstance(path, str) or not path.strip() for path in watch_paths)
    ):
        raise ValueError("'monitoring.watch_paths' must be a non-empty list of paths.")

    for key in ("scan_interval_seconds", "sliding_window_seconds"):
        _require_number(monitoring.get(key), f"monitoring.{key}", minimum=0.001)

    detection = config["detection"]
    _require_mapping(detection.get("thresholds"), "detection.thresholds")

    thresholds = detection["thresholds"]

    for key in (
        "files_modified_per_minute",
        "rename_count",
        "extension_change_count",
    ):
        _require_positive_integer(thresholds.get(key), f"detection.thresholds.{key}")

    _require_number(
        thresholds.get("average_entropy"),
        "detection.thresholds.average_entropy",
        minimum=0,
        maximum=8,
    )
    _require_number(
        thresholds.get("cpu_spike_percent"),
        "detection.thresholds.cpu_spike_percent",
        minimum=0,
        maximum=100,
    )

    scoring = config["scoring"]
    _require_mapping(scoring.get("weights"), "scoring.weights")
    _require_mapping(scoring.get("levels"), "scoring.levels")

    for key, value in scoring["weights"].items():
        _require_number(value, f"scoring.weights.{key}", minimum=0)

    levels = scoring["levels"]
    level_values = []

    for key in ("normal", "warning", "critical"):
        value = levels.get(key)
        _require_number(value, f"scoring.levels.{key}", minimum=0, maximum=100)
        level_values.append(value)

    if not level_values[0] < level_values[1] < level_values[2]:
        raise ValueError(
            "Scoring levels must be strictly increasing: "
            "normal < warning < critical."
        )

    response = config["response"]

    if not isinstance(response.get("simulation_mode"), bool):
        raise ValueError("'response.simulation_mode' must be a boolean.")

    quarantine_path = response.get("quarantine_path")
    if not isinstance(quarantine_path, str) or not quarantine_path.strip():
        raise ValueError("'response.quarantine_path' must be a non-empty path.")

    logging_config = config["logging"]

    directory = logging_config.get("directory")
    if not isinstance(directory, str) or not directory.strip():
        raise ValueError("'logging.directory' must be a non-empty path.")

    log_level = logging_config.get("level")
    allowed_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    if not isinstance(log_level, str) or log_level.upper() not in allowed_levels:
        raise ValueError(
            f"'logging.level' must be one of: {', '.join(sorted(allowed_levels))}."
        )


def load_config() -> dict:
    """Load, complete, and validate RDRS configuration."""
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {CONFIG_PATH}"
        )

    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    if not isinstance(config, dict):
        raise ValueError("Configuration must contain a YAML mapping.")

    config = _merge_defaults(config, DEFAULT_CONFIG)
    validate_config(config)

    return config
