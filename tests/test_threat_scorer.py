
import pytest

from app.detectors.threat_scorer import ThreatScorer


@pytest.fixture
def scorer():
    return ThreatScorer(
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


def test_calculate_weighted_score(scorer):
    signals = {
        "rapid_encryption": True,
        "mass_rename": True,
        "high_entropy": False,
        "cpu_spike": False,
        "unknown_program": False,
    }

    assert scorer.calculate_score(signals) == 70


def test_score_is_capped_at_100(scorer):
    signals = {
        "rapid_encryption": True,
        "mass_rename": True,
        "high_entropy": True,
        "cpu_spike": True,
        "unknown_program": True,
    }

    assert scorer.calculate_score(signals) == 100


def test_inactive_signals_produce_zero(scorer):
    signals = {
        "rapid_encryption": False,
        "mass_rename": False,
    }

    assert scorer.calculate_score(signals) == 0


def test_unknown_signal_is_ignored(scorer):
    assert scorer.calculate_score(
        {"unconfigured_signal": True}
    ) == 0


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "normal"),
        (39, "normal"),
        (40, "normal"),
        (69, "normal"),
        (70, "warning"),
        (89, "warning"),
        (90, "critical"),
        (100, "critical"),
    ],
)
def test_severity_boundaries(scorer, score, expected):
    assert scorer.get_level(score) == expected


def test_score_detection_preserves_original_fields(scorer):
    detection = {
        "detected": True,
        "triggered_rules": ["mass_rename"],
        "signals": {
            "mass_rename": True,
            "high_entropy": True,
        },
    }

    result = scorer.score_detection(detection)

    assert result["detected"] is True
    assert result["triggered_rules"] == ["mass_rename"]
    assert result["score"] == 55
    assert result["level"] == "normal"


def test_missing_signals_default_to_empty_dictionary(scorer):
    result = scorer.score_detection({"detected": False})

    assert result["score"] == 0
    assert result["level"] == "normal"


@pytest.mark.parametrize(
    "weights",
    [
        None,
        [],
        {"rapid_encryption": -1},
        {"rapid_encryption": True},
        {"rapid_encryption": float("inf")},
        {"": 10},
    ],
)
def test_invalid_weights_are_rejected(weights):
    with pytest.raises(ValueError):
        ThreatScorer(weights)


@pytest.mark.parametrize(
    "levels",
    [
        {},
        {"normal": 40, "warning": 70},
        {"normal": 70, "warning": 40, "critical": 90},
        {"normal": 40, "warning": 40, "critical": 90},
        {"normal": 40, "warning": 70, "critical": 101},
        {"normal": -1, "warning": 70, "critical": 90},
        {"normal": True, "warning": 70, "critical": 90},
    ],
)
def test_invalid_severity_levels_are_rejected(levels):
    with pytest.raises(ValueError):
        ThreatScorer({}, levels)


@pytest.mark.parametrize(
    "signals",
    [
        None,
        [],
        {"rapid_encryption": "true"},
        {"rapid_encryption": 1},
        {"rapid_encryption": None},
    ],
)
def test_invalid_signals_are_rejected(scorer, signals):
    with pytest.raises(ValueError):
        scorer.calculate_score(signals)


@pytest.mark.parametrize(
    "score",
    [-1, 101, True, float("nan"), float("inf"), "90"],
)
def test_invalid_scores_are_rejected(scorer, score):
    with pytest.raises(ValueError):
        scorer.get_level(score)


def test_invalid_detection_result_is_rejected(scorer):
    with pytest.raises(ValueError):
        scorer.score_detection([])
