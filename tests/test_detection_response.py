
from pathlib import Path

from app.core.response import ResponseEngine
from app.detectors.threat_scorer import ThreatScorer


def test_critical_detection_creates_incident_and_quarantines_files(
    tmp_path,
    monkeypatch,
):
    source_dir = tmp_path / "sandbox"
    quarantine_dir = tmp_path / "quarantine"
    source_dir.mkdir()

    suspicious_file = source_dir / "sample.locked"
    original_content = b"harmless ransomware simulation data"
    suspicious_file.write_bytes(original_content)

    saved_alerts = []
    saved_incidents = []

    monkeypatch.setattr(
        "app.core.response.save_alert",
        lambda **kwargs: saved_alerts.append(kwargs),
    )
    monkeypatch.setattr(
        "app.core.response.save_incident",
        lambda **kwargs: saved_incidents.append(kwargs),
    )

    engine = ResponseEngine(
        simulation_mode=True,
        quarantine_path=str(quarantine_dir),
    )

    quarantined = engine.handle_detection(
        score=95,
        level="critical",
        triggered_rules=[
            "rapid_file_modification",
            "mass_rename",
            "high_entropy",
        ],
        affected_files=[str(suspicious_file)],
    )

    assert len(quarantined) == 1

    quarantined_file = Path(quarantined[0])

    assert quarantined_file.exists()
    assert quarantined_file.read_bytes() == original_content

    assert suspicious_file.exists()
    assert suspicious_file.read_bytes() == original_content

    assert len(saved_alerts) == 3
    assert len(saved_incidents) == 1

    assert saved_incidents[0]["score"] == 95
    assert saved_incidents[0]["level"] == "critical"
    assert saved_incidents[0]["affected_files"] == quarantined


def test_warning_detection_does_not_quarantine_or_create_incident(
    tmp_path,
    monkeypatch,
):
    suspicious_file = tmp_path / "sample.txt"
    suspicious_file.write_bytes(b"warning-level test data")

    saved_alerts = []
    saved_incidents = []

    monkeypatch.setattr(
        "app.core.response.save_alert",
        lambda **kwargs: saved_alerts.append(kwargs),
    )
    monkeypatch.setattr(
        "app.core.response.save_incident",
        lambda **kwargs: saved_incidents.append(kwargs),
    )

    engine = ResponseEngine(
        simulation_mode=True,
        quarantine_path=str(tmp_path / "quarantine"),
    )

    quarantined = engine.handle_detection(
        score=75,
        level="warning",
        triggered_rules=["rapid_file_modification"],
        affected_files=[str(suspicious_file)],
    )

    assert quarantined == []
    assert suspicious_file.exists()
    assert not (tmp_path / "quarantine").exists()

    assert len(saved_alerts) == 1
    assert saved_incidents == []


def test_combined_signals_produce_critical_score():
    scorer = ThreatScorer(
        weights={
            "rapid_encryption": 40,
            "mass_rename": 30,
            "high_entropy": 25,
            "cpu_spike": 15,
            "unknown_program": 10,
        },
        levels={
            "normal": 40,
            "warning": 70,
            "critical": 90,
        },
    )

    detection = {
        "detected": True,
        "triggered_rules": [
            "rapid_file_modification",
            "mass_rename",
            "extension_changes",
            "high_entropy",
        ],
        "signals": {
            "rapid_encryption": True,
            "mass_rename": True,
            "high_entropy": True,
            "cpu_spike": False,
            "unknown_program": False,
        },
    }

    result = scorer.score_detection(detection)

    assert result["score"] == 95
    assert result["level"] == "critical"


def test_critical_detection_handles_missing_files(
    tmp_path,
    monkeypatch,
):
    saved_incidents = []

    monkeypatch.setattr(
        "app.core.response.save_alert",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "app.core.response.save_incident",
        lambda **kwargs: saved_incidents.append(kwargs),
    )

    engine = ResponseEngine(
        simulation_mode=True,
        quarantine_path=str(tmp_path / "quarantine"),
    )

    quarantined = engine.handle_detection(
        score=95,
        level="critical",
        triggered_rules=["mass_rename"],
        affected_files=[str(tmp_path / "missing.locked")],
    )

    assert quarantined == []
    assert len(saved_incidents) == 1
    assert saved_incidents[0]["affected_files"] == []


def test_critical_detection_records_incident_when_quarantine_raises(
    tmp_path,
    monkeypatch,
):
    saved_incidents = []

    monkeypatch.setattr(
        "app.core.response.save_alert",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "app.core.response.save_incident",
        lambda **kwargs: saved_incidents.append(kwargs),
    )

    engine = ResponseEngine(
        simulation_mode=True,
        quarantine_path=str(tmp_path / "quarantine"),
    )

    def failed_quarantine(file_paths):
        raise OSError("Simulated quarantine failure")

    monkeypatch.setattr(
        engine.quarantine,
        "quarantine_files",
        failed_quarantine,
    )

    quarantined = engine.handle_detection(
        score=95,
        level="critical",
        triggered_rules=["mass_rename"],
        affected_files=["suspicious.locked"],
    )

    assert quarantined == []
    assert len(saved_incidents) == 1
    assert saved_incidents[0]["score"] == 95
    assert saved_incidents[0]["level"] == "critical"
    assert saved_incidents[0]["affected_files"] == []
