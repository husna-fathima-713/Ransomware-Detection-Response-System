
import math

import pytest

from app.core.entropy import calculate_entropy
from app.detectors.event import FileEvent
from app.detectors.event_history import EventHistory
from app.detectors.event_stats import EventStats
from app.detectors import threat_detector
from app.detectors.threat_detector import ThreatDetector
from app.detectors.threat_scorer import ThreatScorer


DEFAULT_THRESHOLDS = {
    "files_modified_per_minute": 20,
    "rename_count": 10,
    "extension_change_count": 5,
    "average_entropy": 7.2,
    "cpu_spike_percent": 80.0,
}


def create_detector(thresholds=None):
    history = EventHistory(window_seconds=60)
    return ThreatDetector(
        EventStats(history),
        thresholds or DEFAULT_THRESHOLDS.copy(),
    )


def test_entropy_of_empty_data():
    assert calculate_entropy(b"") == 0.0


def test_entropy_of_repeated_data():
    entropy = calculate_entropy(b"A" * 100)
    assert math.isclose(entropy, 0.0)


def test_event_statistics():
    history = EventHistory(window_seconds=60)

    history.add(FileEvent.create("create", "data/sandbox/test.txt"))
    history.add(FileEvent.create("modify", "data/sandbox/test.txt"))
    history.add(
        FileEvent.create(
            "rename",
            "data/sandbox/test.locked",
            old_extension=".txt",
        )
    )

    stats = EventStats(history).calculate()

    assert stats["total_events"] == 3
    assert stats["created"] == 1
    assert stats["modified"] == 1
    assert stats["renamed"] == 1
    assert stats["extension_changes"] == 1


def test_threat_detector_rapid_modification(monkeypatch):
    history = EventHistory(window_seconds=60)

    for index in range(20):
        history.add(
            FileEvent.create(
                "modify",
                f"data/sandbox/file_{index}.txt",
            )
        )

    monkeypatch.setattr(
        threat_detector,
        "get_process_stats",
        lambda: {"highest_cpu_percent": 0.0},
    )

    detector = ThreatDetector(EventStats(history), DEFAULT_THRESHOLDS)
    result = detector.detect()

    assert result["detected"] is True
    assert "rapid_file_modification" in result["triggered_rules"]
    assert result["signals"]["rapid_encryption"] is True


def test_threat_scorer():
    scorer = ThreatScorer(
        weights={
            "rapid_encryption": 40,
            "mass_rename": 30,
            "high_entropy": 25,
            "cpu_spike": 15,
            "unknown_program": 10,
        },
    )

    signals = {
        "rapid_encryption": True,
        "mass_rename": True,
        "high_entropy": False,
        "cpu_spike": False,
        "unknown_program": False,
    }

    score = scorer.calculate_score(signals)

    assert score == 70
    assert scorer.get_level(score) == "warning"


@pytest.mark.parametrize(
    "invalid_value",
    [True, -1, float("inf"), float("nan"), "invalid", None],
)
def test_detector_rejects_invalid_threshold_values(invalid_value):
    thresholds = DEFAULT_THRESHOLDS.copy()
    thresholds["files_modified_per_minute"] = invalid_value

    with pytest.raises(ValueError):
        create_detector(thresholds)


def test_detector_rejects_missing_threshold():
    thresholds = DEFAULT_THRESHOLDS.copy()
    del thresholds["cpu_spike_percent"]

    with pytest.raises(ValueError):
        create_detector(thresholds)


def test_detector_rejects_entropy_threshold_above_eight():
    thresholds = DEFAULT_THRESHOLDS.copy()
    thresholds["average_entropy"] = 8.1

    with pytest.raises(ValueError):
        create_detector(thresholds)


def test_detector_rejects_zero_event_threshold():
    thresholds = DEFAULT_THRESHOLDS.copy()
    thresholds["rename_count"] = 0

    with pytest.raises(ValueError):
        create_detector(thresholds)


@pytest.mark.parametrize("affected_files", ["file.txt", ( "file.txt", )])
def test_detector_rejects_invalid_affected_files(affected_files):
    detector = create_detector()

    with pytest.raises(TypeError):
        detector.detect(affected_files)


def test_detector_rejects_non_string_file_paths():
    detector = create_detector()

    with pytest.raises(ValueError):
        detector.detect(["file.txt", 123])


def test_detector_skips_inaccessible_files(monkeypatch):
    detector = create_detector()

    def raise_os_error(path):
        raise OSError("File is inaccessible")

    monkeypatch.setattr(
        threat_detector,
        "calculate_file_entropy",
        raise_os_error,
    )
    monkeypatch.setattr(
        threat_detector,
        "get_process_stats",
        lambda: {"highest_cpu_percent": 0.0},
    )
    monkeypatch.setattr(
        threat_detector.Path,
        "is_file",
        lambda self: True,
    )

    result = detector.detect(["sample.txt"])

    assert result["average_entropy"] == 0.0
    assert result["signals"]["high_entropy"] is False


def test_detector_ignores_invalid_entropy_values(monkeypatch):
    detector = create_detector()

    monkeypatch.setattr(
        threat_detector.Path,
        "is_file",
        lambda self: True,
    )
    monkeypatch.setattr(
        threat_detector,
        "calculate_file_entropy",
        lambda path: 9.0,
    )
    monkeypatch.setattr(
        threat_detector,
        "get_process_stats",
        lambda: {"highest_cpu_percent": 0.0},
    )

    result = detector.detect(["sample.txt"])

    assert result["average_entropy"] == 0.0
    assert result["signals"]["high_entropy"] is False


@pytest.mark.parametrize(
    "cpu_value",
    [None, -1, float("inf"), float("nan"), "invalid", True],
)
def test_detector_ignores_invalid_cpu_metrics(monkeypatch, cpu_value):
    detector = create_detector()

    monkeypatch.setattr(
        threat_detector,
        "get_process_stats",
        lambda: {"highest_cpu_percent": cpu_value},
    )

    result = detector.detect()

    assert result["signals"]["cpu_spike"] is False
    assert "cpu_spike" not in result["triggered_rules"]


def test_detector_handles_missing_cpu_metric(monkeypatch):
    detector = create_detector()

    monkeypatch.setattr(
        threat_detector,
        "get_process_stats",
        lambda: {},
    )

    result = detector.detect()

    assert result["signals"]["cpu_spike"] is False


def test_detector_triggers_cpu_spike_at_threshold(monkeypatch):
    detector = create_detector()

    monkeypatch.setattr(
        threat_detector,
        "get_process_stats",
        lambda: {"highest_cpu_percent": 80.0},
    )

    result = detector.detect()

    assert result["signals"]["cpu_spike"] is True
    assert "cpu_spike" in result["triggered_rules"]


def test_detector_keeps_triggered_rules_and_signals_consistent(monkeypatch):
    detector = create_detector()

    monkeypatch.setattr(
        threat_detector,
        "get_process_stats",
        lambda: {"highest_cpu_percent": 90.0},
    )

    result = detector.detect()

    assert result["detected"] is True
    assert ("cpu_spike" in result["triggered_rules"]) == result["signals"]["cpu_spike"]
