from types import SimpleNamespace

from app.detectors import file_monitor
from app.detectors.file_monitor import RDRSEventHandler


def create_handler(monkeypatch, recorded_events, tmp_path):
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

    return RDRSEventHandler(
        thresholds={
            "files_modified_per_minute": 100,
            "rename_count": 100,
            "extension_change_count": 100,
            "average_entropy": 7.2,
            "cpu_spike_percent": 80.0,
        },
        scoring_weights={},
        response_config={
            "simulation_mode": True,
            "quarantine_path": str(tmp_path / "quarantine"),
        },
    )


def test_file_create_modify_delete_events(monkeypatch, tmp_path):
    recorded_events = []
    handler = create_handler(
        monkeypatch,
        recorded_events,
        tmp_path,
    )

    test_file = tmp_path / "test.txt"
    test_file.write_text("Harmless test content")

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

    handler.on_deleted(
        SimpleNamespace(
            is_directory=False,
            src_path=str(test_file),
        )
    )

    assert handler.event_count == 3
    assert [
        event["event_type"] for event in recorded_events
    ] == ["create", "modify", "delete"]


def test_file_rename_records_extension_change(monkeypatch, tmp_path):
    recorded_events = []
    handler = create_handler(
        monkeypatch,
        recorded_events,
        tmp_path,
    )

    old_path = str(tmp_path / "document.txt")
    new_path = str(tmp_path / "document.locked")

    handler.on_moved(
        SimpleNamespace(
            is_directory=False,
            src_path=old_path,
            dest_path=new_path,
        )
    )

    assert handler.event_count == 1
    assert recorded_events[0]["event_type"] == "rename"
    assert recorded_events[0]["path"] == new_path
    assert recorded_events[0]["old_extension"] == ".txt"
    assert recorded_events[0]["extension"] == ".locked"


def test_directory_events_are_ignored(monkeypatch, tmp_path):
    recorded_events = []
    handler = create_handler(
        monkeypatch,
        recorded_events,
        tmp_path,
    )

    directory_event = SimpleNamespace(
        is_directory=True,
        src_path=str(tmp_path / "folder"),
    )

    handler.on_created(directory_event)
    handler.on_modified(directory_event)
    handler.on_deleted(directory_event)

    assert handler.event_count == 0
    assert recorded_events == []