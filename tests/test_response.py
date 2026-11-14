
import pytest

from app.core import response


class FakeQuarantineManager:
    def __init__(
        self,
        quarantine_path="data/quarantine",
        simulation_mode=True,
    ):
        self.quarantine_path = quarantine_path
        self.simulation_mode = simulation_mode
        self.files_to_return = []
        self.error = None
        self.received_files = []

    def quarantine_files(self, file_paths):
        self.received_files = file_paths

        if self.error:
            raise self.error

        return self.files_to_return


@pytest.fixture
def saved_records(monkeypatch):
    records = {
        "alerts": [],
        "incidents": [],
    }

    def fake_save_alert(**kwargs):
        records["alerts"].append(kwargs)

    def fake_save_incident(**kwargs):
        records["incidents"].append(kwargs)

    monkeypatch.setattr(response, "save_alert", fake_save_alert)
    monkeypatch.setattr(response, "save_incident", fake_save_incident)

    return records


@pytest.fixture
def fake_quarantine(monkeypatch):
    managers = []

    def create_manager(**kwargs):
        manager = FakeQuarantineManager(**kwargs)
        managers.append(manager)
        return manager

    monkeypatch.setattr(response, "QuarantineManager", create_manager)

    return managers


def test_response_engine_initializes_quarantine(fake_quarantine):
    engine = response.ResponseEngine(
        simulation_mode=True,
        quarantine_path="test/quarantine",
    )

    assert engine.simulation_mode is True
    assert engine.quarantine.simulation_mode is True
    assert engine.quarantine.quarantine_path == "test/quarantine"


def test_response_engine_rejects_invalid_simulation_mode():
    with pytest.raises(TypeError):
        response.ResponseEngine(simulation_mode="true")


def test_response_engine_rejects_empty_quarantine_path():
    with pytest.raises(ValueError):
        response.ResponseEngine(quarantine_path=" ")


def test_normal_detection_saves_alerts_without_incident(
    fake_quarantine,
    saved_records,
):
    engine = response.ResponseEngine()

    result = engine.handle_detection(
        score=20,
        level="normal",
        triggered_rules=["low_activity"],
        affected_files=[],
    )

    assert result == []
    assert len(saved_records["alerts"]) == 1
    assert saved_records["alerts"][0]["rule"] == "low_activity"
    assert saved_records["incidents"] == []
    assert fake_quarantine[0].received_files == []


def test_warning_detection_does_not_quarantine(
    fake_quarantine,
    saved_records,
):
    engine = response.ResponseEngine()

    result = engine.handle_detection(
        score=60,
        level="warning",
        triggered_rules=["mass_rename"],
        affected_files=["sample.txt"],
    )

    assert result == []
    assert len(saved_records["alerts"]) == 1
    assert saved_records["incidents"] == []
    assert fake_quarantine[0].received_files == []


def test_critical_detection_quarantines_and_saves_incident(
    fake_quarantine,
    saved_records,
):
    engine = response.ResponseEngine()

    fake_quarantine[0].files_to_return = [
        "data/quarantine/sample.txt"
    ]

    original_files = ["data/sandbox/sample.txt"]

    result = engine.handle_detection(
        score=95,
        level="critical",
        triggered_rules=["rapid_encryption", "high_entropy"],
        affected_files=original_files,
    )

    assert result == ["data/quarantine/sample.txt"]
    assert len(saved_records["alerts"]) == 2
    assert len(saved_records["incidents"]) == 1

    assert saved_records["incidents"][0]["affected_files"] == original_files
    assert fake_quarantine[0].received_files == original_files


def test_critical_detection_saves_incident_after_quarantine_failure(
    fake_quarantine,
    saved_records,
):
    engine = response.ResponseEngine()
    fake_quarantine[0].error = OSError("Simulated quarantine failure")

    original_files = ["data/sandbox/suspicious.txt"]

    result = engine.handle_detection(
        score=100,
        level="critical",
        triggered_rules=["rapid_encryption"],
        affected_files=original_files,
    )

    assert result == []
    assert len(saved_records["incidents"]) == 1
    assert saved_records["incidents"][0]["affected_files"] == original_files


def test_critical_detection_records_partial_quarantine_results(
    fake_quarantine,
    saved_records,
):
    engine = response.ResponseEngine()

    fake_quarantine[0].files_to_return = [
        "data/quarantine/first.txt"
    ]

    original_files = [
        "data/sandbox/first.txt",
        "data/sandbox/second.txt",
    ]

    result = engine.handle_detection(
        score=90,
        level="critical",
        triggered_rules=["mass_rename"],
        affected_files=original_files,
    )

    assert result == ["data/quarantine/first.txt"]
    assert saved_records["incidents"][0]["affected_files"] == original_files


def test_alert_failure_does_not_stop_remaining_alerts(
    fake_quarantine,
    saved_records,
    monkeypatch,
):
    engine = response.ResponseEngine()
    original_save_alert = response.save_alert
    attempts = []

    def selective_failure(**kwargs):
        attempts.append(kwargs["rule"])

        if kwargs["rule"] == "first_rule":
            raise RuntimeError("Simulated database failure")

        original_save_alert(**kwargs)

    monkeypatch.setattr(response, "save_alert", selective_failure)

    engine.handle_detection(
        score=95,
        level="critical",
        triggered_rules=["first_rule", "second_rule"],
        affected_files=["sample.txt"],
    )

    assert attempts == ["first_rule", "second_rule"]
    assert len(saved_records["alerts"]) == 1
    assert saved_records["alerts"][0]["rule"] == "second_rule"
    assert len(saved_records["incidents"]) == 1


def test_incident_database_failure_is_propagated(
    fake_quarantine,
    monkeypatch,
):
    engine = response.ResponseEngine()

    def failed_incident(**kwargs):
        raise RuntimeError("Database unavailable")

    monkeypatch.setattr(response, "save_incident", failed_incident)

    with pytest.raises(RuntimeError, match="Database unavailable"):
        engine.handle_detection(
            score=95,
            level="critical",
            triggered_rules=["rapid_encryption"],
            affected_files=["sample.txt"],
        )


@pytest.mark.parametrize(
    "invalid_score",
    [
        -1,
        101,
        True,
        float("inf"),
        float("nan"),
        "95",
        None,
    ],
)
def test_response_rejects_invalid_scores(
    fake_quarantine,
    invalid_score,
):
    engine = response.ResponseEngine()

    with pytest.raises(ValueError):
        engine.handle_detection(
            score=invalid_score,
            level="critical",
            triggered_rules=[],
            affected_files=[],
        )


@pytest.mark.parametrize(
    "invalid_level",
    [
        "CRITICAL",
        "unknown",
        "",
        None,
        123,
    ],
)
def test_response_rejects_invalid_levels(
    fake_quarantine,
    invalid_level,
):
    engine = response.ResponseEngine()

    with pytest.raises(ValueError):
        engine.handle_detection(
            score=90,
            level=invalid_level,
            triggered_rules=[],
            affected_files=[],
        )


def test_response_rejects_invalid_triggered_rules(fake_quarantine):
    engine = response.ResponseEngine()

    with pytest.raises(ValueError):
        engine.handle_detection(
            score=90,
            level="critical",
            triggered_rules=["valid_rule", ""],
            affected_files=[],
        )


def test_response_rejects_non_list_triggered_rules(fake_quarantine):
    engine = response.ResponseEngine()

    with pytest.raises(TypeError):
        engine.handle_detection(
            score=90,
            level="critical",
            triggered_rules="rapid_encryption",
            affected_files=[],
        )


def test_response_rejects_invalid_affected_files(fake_quarantine):
    engine = response.ResponseEngine()

    with pytest.raises(ValueError):
        engine.handle_detection(
            score=90,
            level="critical",
            triggered_rules=[],
            affected_files=["valid.txt", ""],
        )


def test_response_rejects_non_list_affected_files(fake_quarantine):
    engine = response.ResponseEngine()

    with pytest.raises(TypeError):
        engine.handle_detection(
            score=90,
            level="critical",
            triggered_rules=[],
            affected_files="sample.txt",
        )


def test_alerts_and_incident_share_timestamp(
    fake_quarantine,
    saved_records,
):
    engine = response.ResponseEngine()

    engine.handle_detection(
        score=95,
        level="critical",
        triggered_rules=["rapid_encryption", "high_entropy"],
        affected_files=["sample.txt"],
    )

    alert_timestamps = {
        record["timestamp"] for record in saved_records["alerts"]
    }

    incident_timestamp = saved_records["incidents"][0]["timestamp"]

    assert alert_timestamps == {incident_timestamp}


def test_quarantine_return_value_is_validated(
    fake_quarantine,
    saved_records,
):
    engine = response.ResponseEngine()
    fake_quarantine[0].files_to_return = [""]

    result = engine.handle_detection(
        score=95,
        level="critical",
        triggered_rules=["rapid_encryption"],
        affected_files=["sample.txt"],
    )

    assert result == []
    assert len(saved_records["incidents"]) == 1
    assert saved_records["incidents"][0]["affected_files"] == ["sample.txt"]
