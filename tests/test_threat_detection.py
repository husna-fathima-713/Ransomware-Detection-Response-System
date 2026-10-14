
import math

from app.core.entropy import calculate_entropy
from app.detectors.event import FileEvent
from app.detectors.event_history import EventHistory
from app.detectors.event_stats import EventStats
from app.detectors.threat_detector import ThreatDetector
from app.detectors.threat_scorer import ThreatScorer


def test_entropy_of_empty_data():
    assert calculate_entropy(b"") == 0.0


def test_entropy_of_repeated_data():
    entropy = calculate_entropy(b"A" * 100)

    assert math.isclose(entropy, 0.0)


def test_event_statistics():
    history = EventHistory(window_seconds=60)

    history.add(
        FileEvent.create(
            "create",
            "data/sandbox/test.txt",
        )
    )

    history.add(
        FileEvent.create(
            "modify",
            "data/sandbox/test.txt",
        )
    )

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


def test_threat_detector_rapid_modification():
    history = EventHistory(window_seconds=60)

    for index in range(20):
        history.add(
            FileEvent.create(
                "modify",
                f"data/sandbox/file_{index}.txt",
            )
        )

    stats = EventStats(history)

    detector = ThreatDetector(
        stats,
        {
            "files_modified_per_minute": 20,
            "rename_count": 10,
            "extension_change_count": 5,
            "average_entropy": 7.2,
            "cpu_spike_percent": 80.0,
        },
    )

    result = detector.detect()

    assert result["detected"] is True
    assert "rapid_file_modification" in result[
        "triggered_rules"
    ]


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
