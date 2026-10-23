
import pytest
import yaml

from app.core import config as config_module


def write_config(tmp_path, monkeypatch, data):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)
    return config_path


def test_load_config_accepts_valid_configuration(tmp_path, monkeypatch):
    write_config(tmp_path, monkeypatch, config_module.DEFAULT_CONFIG)

    config = config_module.load_config()

    assert config["monitoring"]["scan_interval_seconds"] == 5
    assert config["response"]["simulation_mode"] is True


def test_load_config_applies_optional_defaults(tmp_path, monkeypatch):
    write_config(
        tmp_path,
        monkeypatch,
        {"response": {"simulation_mode": True}},
    )

    config = config_module.load_config()

    assert config["monitoring"]["watch_paths"] == ["data/sandbox"]
    assert config["logging"]["level"] == "INFO"
    assert config["response"]["quarantine_path"] == "data/quarantine"


def test_load_config_rejects_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(
        config_module,
        "CONFIG_PATH",
        tmp_path / "missing.yaml",
    )

    with pytest.raises(FileNotFoundError):
        config_module.load_config()


def test_load_config_rejects_non_mapping_yaml(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("- invalid\n- configuration\n", encoding="utf-8")
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)

    with pytest.raises(ValueError, match="YAML mapping"):
        config_module.load_config()


def test_load_config_rejects_invalid_entropy_threshold(tmp_path, monkeypatch):
    data = config_module.DEFAULT_CONFIG.copy()
    data["detection"] = {
        "thresholds": {
            **config_module.DEFAULT_CONFIG["detection"]["thresholds"],
            "average_entropy": 9.5,
        }
    }
    write_config(tmp_path, monkeypatch, data)

    with pytest.raises(ValueError, match="average_entropy"):
        config_module.load_config()


def test_load_config_rejects_invalid_scoring_order(tmp_path, monkeypatch):
    data = {
        **config_module.DEFAULT_CONFIG,
        "scoring": {
            **config_module.DEFAULT_CONFIG["scoring"],
            "levels": {
                "normal": 70,
                "warning": 40,
                "critical": 90,
            },
        },
    }
    write_config(tmp_path, monkeypatch, data)

    with pytest.raises(ValueError, match="strictly increasing"):
        config_module.load_config()


def test_load_config_rejects_invalid_simulation_mode(tmp_path, monkeypatch):
    data = {
        **config_module.DEFAULT_CONFIG,
        "response": {
            **config_module.DEFAULT_CONFIG["response"],
            "simulation_mode": "true",
        },
    }
    write_config(tmp_path, monkeypatch, data)

    with pytest.raises(ValueError, match="simulation_mode"):
        config_module.load_config()


def test_load_config_rejects_empty_watch_paths(tmp_path, monkeypatch):
    data = {
        **config_module.DEFAULT_CONFIG,
        "monitoring": {
            **config_module.DEFAULT_CONFIG["monitoring"],
            "watch_paths": [],
        },
    }
    write_config(tmp_path, monkeypatch, data)

    with pytest.raises(ValueError, match="watch_paths"):
        config_module.load_config()
