
import math

import pytest

from app.core.entropy import calculate_entropy
from app.detectors.event import FileEvent
from app.detectors.event_history import EventHistory
from app.detectors.event_stats import EventStats
from app.detectors.threat_detector import ThreatDetector


DEFAULT_THRESHOLDS = {
    "files_modified_per_minute": 20,
    "rename_count": 10,
    "extension_change_count": 5,
    "average_entropy": 7.2,
    "cpu_spike_percent": 80.0,
}


def create_detector(
    monkeypatch=None,
    thresholds=None,
    process_stats=None,
):
    history = EventHistory(window_seconds=60)
    stats = EventStats(history)

    if monkeypatch is not None:
        monkeypatch.setattr(
            "app.detectors.threat_detector.get_process_stats",
            lambda: process_stats or {
                "highest_cpu_percent": 0.0,
                "high_cpu_count": 0,
            },
        )

    detector = ThreatDetector(
        stats,
        thresholds or DEFAULT_THRESHOLDS.copy(),
    )

    return detector, history


def add_events(history, event_type, count, extension=".txt"):
    for index in range(count):
        history.add(
            FileEvent.create(
                event_type,
                f"data/sandbox/file_{index}{extension}",
            )
        )


# ---------------------------------------------------------
# Entropy tests
# ---------------------------------------------------------

def test_entropy_of_empty_data():
    assert calculate_entropy(b"") == 0.0


def test_entropy_of_repeated_data():
    entropy = calculate_entropy(b"A" * 100)

    assert math.isclose(entropy, 0.0)


def test_entropy_of_random_data_is_high():
    data = bytes(range(256)) * 4

    entropy = calculate_entropy(data)

    assert math.isclose(entropy, 8.0)


# ---------------------------------------------------------
# Event statistics tests
# ---------------------------------------------------------

def test_event_statistics():
    history = EventHistory(window_seconds=60)

    history.add(FileEvent.create("create", "test.txt"))
    history.add(FileEvent.create("modify", "test.txt"))
    history.add(
        FileEvent.create(
            "rename",
            "test.locked",
            old_extension=".txt",
        )
    )

    stats = EventStats(history).calculate()

    assert stats["total_events"] == 3
    assert stats["created"] == 1
    assert stats["modified"] == 1
    assert stats["renamed"] == 1
    assert stats["extension_changes"] == 1


def test_rename_without_extension_change_is_not_counted():
    history = EventHistory(window_seconds=60)

    history.add(
        FileEvent.create(
            "rename",
            "renamed.txt",
            old_extension=".txt",
        )
    )

    stats = EventStats(history).calculate()

    assert stats["renamed"] == 1
    assert stats["extension_changes"] == 0


def test_rename_without_old_extension_is_not_counted():
    history = EventHistory(window_seconds=60)

    history.add(
        FileEvent.create(
            "rename",
            "renamed.locked",
        )
    )

    stats = EventStats(history).calculate()

    assert stats["renamed"] == 1
    assert stats["extension_changes"] == 0


# ---------------------------------------------------------
# Threat detector construction and validation
# ---------------------------------------------------------

def test_detector_rejects_invalid_event_stats():
    with pytest.raises(TypeError):
        ThreatDetector(
            event_stats=None,
            thresholds=DEFAULT_THRESHOLDS,
        )


def test_detector_rejects_non_dictionary_thresholds():
    history = EventHistory(window_seconds=60)

    with pytest.raises(TypeError):
        ThreatDetector(
            EventStats(history),
            [],
        )


def test_detector_rejects_missing_thresholds():
    history = EventHistory(window_seconds=60)

    with pytest.raises(ValueError, match="Missing detection thresholds"):
        ThreatDetector(
            EventStats(history),
            {"rename_count": 10},
        )


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        -1,
        float("inf"),
        float("-inf"),
        float("nan"),
        "20",
        None,
    ],
)
def test_detector_rejects_invalid_numeric_thresholds(value):
    history = EventHistory(window_seconds=60)
    thresholds = DEFAULT_THRESHOLDS.copy()
    thresholds["rename_count"] = value

    with pytest.raises(ValueError):
        ThreatDetector(
            EventStats(history),
            thresholds,
        )


@pytest.mark.parametrize(
    "threshold_name",
    [
        "files_modified_per_minute",
        "rename_count",
        "extension_change_count",
        "average_entropy",
    ],
)
def test_detector_rejects_zero_event_thresholds(threshold_name):
    history = EventHistory(window_seconds=60)
    thresholds = DEFAULT_THRESHOLDS.copy()
    thresholds[threshold_name] = 0

    with pytest.raises(ValueError):
        ThreatDetector(
            EventStats(history),
            thresholds,
        )


def test_detector_allows_zero_cpu_threshold():
    history = EventHistory(window_seconds=60)
    thresholds = DEFAULT_THRESHOLDS.copy()
    thresholds["cpu_spike_percent"] = 0

    detector = ThreatDetector(
        EventStats(history),
        thresholds,
    )

    assert detector.thresholds["cpu_spike_percent"] == 0


def test_detector_rejects_entropy_threshold_above_eight():
    history = EventHistory(window_seconds=60)
    thresholds = DEFAULT_THRESHOLDS.copy()
    thresholds["average_entropy"] = 8.1

    with pytest.raises(ValueError, match="cannot exceed 8"):
        ThreatDetector(
            EventStats(history),
            thresholds,
        )


# ---------------------------------------------------------
# Detection input validation
# ---------------------------------------------------------

def test_detector_rejects_non_list_affected_files(monkeypatch):
    detector, _ = create_detector(monkeypatch)

    with pytest.raises(TypeError):
        detector.detect(affected_files="test.txt")


def test_detector_rejects_non_string_affected_file_paths(
    monkeypatch,
):
    detector, _ = create_detector(monkeypatch)

    with pytest.raises(ValueError):
        detector.detect(
            affected_files=["test.txt", 123]
        )


# ---------------------------------------------------------
# File activity detection
# ---------------------------------------------------------

def test_threat_detector_rapid_modification(monkeypatch):
    detector, history = create_detector(monkeypatch)

    add_events(history, "modify", 20)

    result = detector.detect()

    assert result["detected"] is True
    assert "rapid_file_modification" in result["triggered_rules"]
    assert result["signals"]["rapid_encryption"] is True


def test_rapid_modification_below_threshold_is_not_detected(
    monkeypatch,
):
    detector, history = create_detector(monkeypatch)

    add_events(history, "modify", 19)

    result = detector.detect()

    assert "rapid_file_modification" not in result["triggered_rules"]
    assert result["signals"]["rapid_encryption"] is False


def test_mass_rename_detection(monkeypatch):
    detector, history = create_detector(monkeypatch)

    add_events(history, "rename", 10)

    result = detector.detect()

    assert result["detected"] is True
    assert "mass_rename" in result["triggered_rules"]
    assert result["signals"]["mass_rename"] is True


def test_extension_change_detection(monkeypatch):
    detector, history = create_detector(monkeypatch)

    for index in range(5):
        history.add(
            FileEvent.create(
                "rename",
                f"file_{index}.locked",
                old_extension=".txt",
            )
        )

    result = detector.detect()

    assert "extension_changes" in result["triggered_rules"]


# ---------------------------------------------------------
# Entropy detection
# ---------------------------------------------------------

def test_high_entropy_detection(monkeypatch, tmp_path):
    detector, _ = create_detector(monkeypatch)

    test_file = tmp_path / "high_entropy.bin"
    test_file.write_bytes(bytes(range(256)) * 4)

    monkeypatch.setattr(
        "app.detectors.threat_detector.calculate_file_entropy",
        lambda path: 7.9,
    )

    result = detector.detect(
        affected_files=[str(test_file)]
    )

    assert result["detected"] is True
    assert "high_entropy" in result["triggered_rules"]
    assert result["signals"]["high_entropy"] is True
    assert result["average_entropy"] == 7.9


def test_low_entropy_file_is_not_detected(monkeypatch, tmp_path):
    detector, _ = create_detector(monkeypatch)

    test_file = tmp_path / "low_entropy.txt"
    test_file.write_text("Repeated harmless content")

    monkeypatch.setattr(
        "app.detectors.threat_detector.calculate_file_entropy",
        lambda path: 3.0,
    )

    result = detector.detect(
        affected_files=[str(test_file)]
    )

    assert "high_entropy" not in result["triggered_rules"]
    assert result["signals"]["high_entropy"] is False


@pytest.mark.parametrize(
    "invalid_entropy",
    [
        float("nan"),
        float("inf"),
        -1.0,
        8.1,
        True,
        "invalid",
    ],
)
def test_invalid_entropy_values_are_ignored(
    monkeypatch,
    tmp_path,
    invalid_entropy,
):
    detector, _ = create_detector(monkeypatch)

    test_file = tmp_path / "invalid_entropy.bin"
    test_file.write_bytes(b"test data")

    monkeypatch.setattr(
        "app.detectors.threat_detector.calculate_file_entropy",
        lambda path: invalid_entropy,
    )

    result = detector.detect(
        affected_files=[str(test_file)]
    )

    assert result["average_entropy"] == 0.0
    assert "high_entropy" not in result["triggered_rules"]


def test_missing_file_is_skipped(monkeypatch, tmp_path):
    detector, _ = create_detector(monkeypatch)

    result = detector.detect(
        affected_files=[str(tmp_path / "missing.bin")]
    )

    assert result["average_entropy"] == 0.0
    assert "high_entropy" not in result["triggered_rules"]


def test_entropy_read_failure_is_ignored(monkeypatch, tmp_path):
    detector, _ = create_detector(monkeypatch)

    test_file = tmp_path / "unreadable.bin"
    test_file.write_bytes(b"test data")

    def fail_entropy(path):
        raise OSError("Simulated file access failure")

    monkeypatch.setattr(
        "app.detectors.threat_detector.calculate_file_entropy",
        fail_entropy,
    )

    result = detector.detect(
        affected_files=[str(test_file)]
    )

    assert result["average_entropy"] == 0.0
    assert "high_entropy" not in result["triggered_rules"]


# ---------------------------------------------------------
# Process statistics and CPU detection
# ---------------------------------------------------------

def test_cpu_spike_detection(monkeypatch):
    detector, _ = create_detector(
        monkeypatch,
        process_stats={
            "highest_cpu_percent": 95.0,
            "high_cpu_count": 2,
        },
    )

    result = detector.detect()

    assert result["detected"] is True
    assert "cpu_spike" in result["triggered_rules"]
    assert result["signals"]["cpu_spike"] is True


def test_cpu_below_threshold_is_not_detected(monkeypatch):
    detector, _ = create_detector(
        monkeypatch,
        process_stats={
            "highest_cpu_percent": 50.0,
            "high_cpu_count": 0,
        },
    )

    result = detector.detect()

    assert "cpu_spike" not in result["triggered_rules"]
    assert result["signals"]["cpu_spike"] is False


@pytest.mark.parametrize(
    "invalid_cpu",
    [
        True,
        -1,
        float("nan"),
        float("inf"),
        "90",
        None,
    ],
)
def test_invalid_cpu_statistics_are_ignored(
    monkeypatch,
    invalid_cpu,
):
    detector, _ = create_detector(
        monkeypatch,
        process_stats={
            "highest_cpu_percent": invalid_cpu,
            "high_cpu_count": 0,
        },
    )

    result = detector.detect()

    assert "cpu_spike" not in result["triggered_rules"]
    assert result["signals"]["cpu_spike"] is False


# ---------------------------------------------------------
# Detection output consistency
# ---------------------------------------------------------

def test_no_detection_when_all_signals_are_false(monkeypatch):
    detector, _ = create_detector(monkeypatch)

    result = detector.detect()

    assert result["detected"] is False
    assert result["triggered_rules"] == []
    assert result["signals"]["rapid_encryption"] is False
    assert result["signals"]["mass_rename"] is False
    assert result["signals"]["high_entropy"] is False
    assert result["signals"]["cpu_spike"] is False
    assert result["signals"]["unknown_program"] is False


def test_detection_rules_match_triggered_signals(monkeypatch):
    detector, history = create_detector(
        monkeypatch,
        process_stats={
            "highest_cpu_percent": 95.0,
            "high_cpu_count": 2,
        },
    )

    add_events(history, "modify", 20)

    for index in range(10):
        history.add(
            FileEvent.create(
                "rename",
                f"file_{index}.locked",
                old_extension=".txt",
            )
        )

    result = detector.detect()

    expected_rules = {
        "rapid_file_modification",
        "mass_rename",
        "extension_changes",
        "cpu_spike",
    }

    assert set(result["triggered_rules"]) == expected_rules
    assert result["detected"] is True
