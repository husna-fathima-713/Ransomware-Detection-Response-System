
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from app.core import response as response_module
from app.detectors import file_monitor
from app.detectors.file_monitor import RDRSEventHandler


def create_handler(monkeypatch, tmp_path, weights=None):
    recorded_events = []

    monkeypatch.setattr(
        file_monitor,
        "save_file_event",
        lambda **kwargs: recorded_events.append(kwargs),
    )

    monkeypatch.setattr(
        "app.detectors.threat_detector.get_process_stats",
        lambda: {
            "highest_cpu_percent": 0.0,
            "high_cpu_count": 0,
        },
    )

    handler = RDRSEventHandler(
        window_seconds=60,
        thresholds={
            "files_modified_per_minute": 100,
            "rename_count": 1,
            "extension_change_count": 1,
            "average_entropy": 7.2,
            "cpu_spike_percent": 80.0,
        },
        scoring_weights=weights or {"mass_rename": 70},
        scoring_levels={
            "normal": 0,
            "warning": 30,
            "critical": 70,
        },
        response_config={
            "simulation_mode": True,
            "quarantine_path": str(tmp_path / "quarantine"),
        },
    )

    return handler, recorded_events


def test_critical_rename_runs_full_detection_response_pipeline(
    monkeypatch,
    tmp_path,
):
    saved_alerts = []
    saved_incidents = []

    monkeypatch.setattr(
        response_module,
        "save_alert",
        lambda *args, **kwargs: saved_alerts.append(
            (args, kwargs)
        ),
    )

    monkeypatch.setattr(
        response_module,
        "save_incident",
        lambda *args, **kwargs: saved_incidents.append(
            (args, kwargs)
        ),
    )

    handler, recorded_events = create_handler(
        monkeypatch,
        tmp_path,
    )

    original = tmp_path / "evidence.txt"
    renamed = tmp_path / "evidence.locked"

    original.write_text("Harmless integration test data")
    original.rename(renamed)

    handler.on_moved(
        SimpleNamespace(
            is_directory=False,
            src_path=str(original),
            dest_path=str(renamed),
        )
    )

    assert handler.event_count == 1
    assert len(recorded_events) == 1

    event_record = recorded_events[0]

    assert event_record["event_type"] == "rename"
    assert event_record["path"] == str(renamed)
    assert event_record["old_extension"] == ".txt"
    assert event_record["extension"] == ".locked"
    assert isinstance(event_record["timestamp"], datetime)

    history = handler.history.get_events()

    assert len(history) == 1
    assert history[0].path == str(renamed)
    assert history[0].event_type == "rename"

    detection = handler.detector.detect(
        affected_files=[str(renamed)]
    )

    assert detection["detected"] is True
    assert "mass_rename" in detection["triggered_rules"]
    assert "extension_changes" in detection["triggered_rules"]

    scored = handler.scorer.score_detection(detection)

    assert scored["score"] == 70
    assert scored["level"] == "critical"

    assert len(saved_alerts) == 2
    assert len(saved_incidents) == 1

    incident_args, incident_kwargs = saved_incidents[0]

    affected_files = incident_kwargs.get(
        "affected_files",
        incident_args[2] if len(incident_args) > 2 else None,
    )

    assert affected_files == [str(renamed)]

    quarantine_path = tmp_path / "quarantine"

    quarantined_files = list(quarantine_path.iterdir())

    assert len(quarantined_files) == 1
    assert quarantined_files[0].read_text() == (
        "Harmless integration test data"
    )

    # Quarantine must preserve the original evidence.
    assert renamed.exists()


def test_affected_file_paths_are_deduplicated(
    monkeypatch,
    tmp_path,
):
    handler, recorded_events = create_handler(
        monkeypatch,
        tmp_path,
    )

    captured_paths = []

    def fake_detect(affected_files=None):
        captured_paths.append(affected_files)

        return {
            "detected": False,
            "triggered_rules": [],
            "signals": {},
            "statistics": {},
            "process_statistics": {
                "highest_cpu_percent": 0.0,
                "high_cpu_count": 0,
            },
        }

    monkeypatch.setattr(
        handler.detector,
        "detect",
        fake_detect,
    )

    test_file = tmp_path / "repeated.txt"
    test_file.write_text("Harmless content")

    handler.on_created(
        SimpleNamespace(
            is_directory=False,
            src_path=str(test_file),
        )
    )

    handler.on_modified(
        SimpleNamespace(
            is_directory=False,
            src_path=str(test_file),
        )
    )

    assert handler.event_count == 2
    assert len(recorded_events) == 2

    # Two events remain recorded, but the path is supplied once.
    assert captured_paths == [
        [str(test_file)],
        [str(test_file)],
    ]


def test_delete_event_is_not_in_affected_file_list(
    monkeypatch,
    tmp_path,
):
    handler, recorded_events = create_handler(
        monkeypatch,
        tmp_path,
    )

    captured_paths = []

    def fake_detect(affected_files=None):
        captured_paths.append(affected_files)

        return {
            "detected": False,
            "triggered_rules": [],
            "signals": {},
            "statistics": {},
            "process_statistics": {
                "highest_cpu_percent": 0.0,
                "high_cpu_count": 0,
            },
        }

    monkeypatch.setattr(
        handler.detector,
        "detect",
        fake_detect,
    )

    test_file = tmp_path / "deleted.txt"
    test_file.write_text("Temporary test content")

    handler.on_created(
        SimpleNamespace(
            is_directory=False,
            src_path=str(test_file),
        )
    )

    handler.on_deleted(
        SimpleNamespace(
            is_directory=False,
            src_path=str(test_file),
        )
    )

    assert handler.event_count == 2
    assert len(recorded_events) == 2
    assert captured_paths[-1] == [str(test_file)]


def test_response_failure_does_not_stop_future_events(
    monkeypatch,
    tmp_path,
    caplog,
):
    handler, recorded_events = create_handler(
        monkeypatch,
        tmp_path,
    )

    calls = 0

    def fake_detect(affected_files=None):
        return {
            "detected": True,
            "triggered_rules": ["test_rule"],
            "signals": {},
            "statistics": {},
            "process_statistics": {
                "highest_cpu_percent": 0.0,
                "high_cpu_count": 0,
            },
        }

    def failing_response(**kwargs):
        nonlocal calls
        calls += 1

        if calls == 1:
            raise RuntimeError("Simulated response failure")

        return []

    monkeypatch.setattr(
        handler.detector,
        "detect",
        fake_detect,
    )

    monkeypatch.setattr(
        handler.response_engine,
        "handle_detection",
        failing_response,
    )

    first_file = tmp_path / "first.txt"
    second_file = tmp_path / "second.txt"

    first_file.write_text("First harmless file")
    second_file.write_text("Second harmless file")

    with caplog.at_level("ERROR"):
        handler.on_created(
            SimpleNamespace(
                is_directory=False,
                src_path=str(first_file),
            )
        )

        handler.on_created(
            SimpleNamespace(
                is_directory=False,
                src_path=str(second_file),
            )
        )

    assert handler.event_count == 2
    assert len(recorded_events) == 2
    assert calls == 2
    assert "Failed to process filesystem event" in caplog.text
