
import pytest

from app.core.response import ResponseEngine


class FakeQuarantineManager:
    def __init__(self, quarantine_path, simulation_mode):
        self.quarantine_path = quarantine_path
        self.simulation_mode = simulation_mode
        self.result = []
        self.error = None
        self.calls = []

    def quarantine_files(self, file_paths):
        self.calls.append(file_paths)

        if self.error is not None:
            raise self.error

        return self.result


@pytest.fixture
def response_setup(monkeypatch, tmp_path):
    import app.core.response as response_module

    saved_alerts = []
    saved_incidents = []
    managers = []

    def fake_quarantine_manager(quarantine_path, simulation_mode):
        manager = FakeQuarantineManager(
            quarantine_path,
            simulation_mode,
        )
        managers.append(manager)
        return manager

    monkeypatch.setattr(
        response_module,
        "QuarantineManager",
        fake_quarantine_manager,
    )

    monkeypatch.setattr(
        response_module,
        "save_alert",
        lambda **kwargs: saved_alerts.append(kwargs),
    )

    monkeypatch.setattr(
        response_module,
        "save_incident",
        lambda **kwargs: saved_incidents.append(kwargs),
    )

    engine = ResponseEngine(
        simulation_mode=True,
        quarantine_path=str(tmp_path / "quarantine"),
    )

    return {
        "engine": engine,
        "manager": managers[0],
        "alerts": saved_alerts,
        "incidents": saved_incidents,
    }


def test_initializes_quarantine_manager(response_setup):
    engine = response_setup["engine"]
    manager = response_setup["manager"]

    assert engine.simulation_mode is True
    assert manager.simulation_mode is True
    assert manager.quarantine_path.endswith("quarantine")


def test_rejects_non_boolean_simulation_mode(tmp_path):
    with pytest.raises(TypeError):
        ResponseEngine(
            simulation_mode="true",
            quarantine_path=str(tmp_path / "quarantine"),
        )


def test_rejects_empty_quarantine_path():
    with pytest.raises(ValueError):
        ResponseEngine(quarantine_path="   ")


def test_normal_detection_saves_alert_without_incident(response_setup):
    engine = response_setup["engine"]

    result = engine.handle_detection(
        score=20,
        level="normal",
        triggered_rules=["low_activity"],
        affected_files=[],
    )

    assert result == []
    assert len(response_setup["alerts"]) == 1
    assert response_setup["incidents"] == []
    assert response_setup["manager"].calls == []


def test_warning_detection_does_not_quarantine(response_setup):
    engine = response_setup["engine"]

    result = engine.handle_detection(
        score=75,
        level="warning",
        triggered_rules=["mass_rename"],
        affected_files=["sample.txt"],
    )

    assert result == []
    assert len(response_setup["alerts"]) == 1
    assert response_setup["incidents"] == []
    assert response_setup["manager"].calls == []


def test_critical_detection_quarantines_and_saves_incident(
    response_setup,
):
    engine = response_setup["engine"]
    manager = response_setup["manager"]

    manager.result = ["quarantine/sample.txt"]

    result = engine.handle_detection(
        score=95,
        level="critical",
        triggered_rules=["mass_rename", "high_entropy"],
        affected_files=["sample.txt"],
    )

    assert result == ["quarantine/sample.txt"]
    assert manager.calls == [["sample.txt"]]
    assert len(response_setup["alerts"]) == 2
    assert len(response_setup["incidents"]) == 1

    incident = response_setup["incidents"][0]

    assert incident["score"] == 95
    assert incident["level"] == "critical"
    assert incident["affected_files"] == ["sample.txt"]


def test_critical_detection_saves_incident_if_quarantine_fails(
    response_setup,
):
    engine = response_setup["engine"]
    manager = response_setup["manager"]

    manager.error = OSError("Quarantine failed")

    result = engine.handle_detection(
        score=95,
        level="critical",
        triggered_rules=["mass_rename"],
        affected_files=["sample.txt"],
    )

    assert result == []
    assert len(response_setup["incidents"]) == 1
    assert response_setup["incidents"][0]["affected_files"] == [
        "sample.txt"
    ]


def test_partial_quarantine_results_are_returned(response_setup):
    engine = response_setup["engine"]
    manager = response_setup["manager"]

    manager.result = ["quarantine/first.txt"]

    result = engine.handle_detection(
        score=95,
        level="critical",
        triggered_rules=["mass_rename"],
        affected_files=["first.txt", "second.txt"],
    )

    assert result == ["quarantine/first.txt"]
    assert len(response_setup["incidents"]) == 1
    assert response_setup["incidents"][0]["affected_files"] == [
        "first.txt",
        "second.txt",
    ]


def test_alert_failure_does_not_stop_remaining_alerts(
    response_setup,
    monkeypatch,
):
    import app.core.response as response_module

    saved = []

    def save_alert(**kwargs):
        if kwargs["rule"] == "first_rule":
            raise OSError("Database unavailable")
        saved.append(kwargs)

    monkeypatch.setattr(response_module, "save_alert", save_alert)

    response_setup["engine"].handle_detection(
        score=95,
        level="critical",
        triggered_rules=["first_rule", "second_rule"],
        affected_files=[],
    )

    assert len(saved) == 1
    assert saved[0]["rule"] == "second_rule"
    assert len(response_setup["incidents"]) == 1


def test_incident_database_failure_is_propagated(
    response_setup,
    monkeypatch,
):
    import app.core.response as response_module

    def failed_save_incident(**kwargs):
        raise OSError("Incident database write failed")

    monkeypatch.setattr(
        response_module,
        "save_incident",
        failed_save_incident,
    )

    with pytest.raises(OSError):
        response_setup["engine"].handle_detection(
            score=95,
            level="critical",
            triggered_rules=["mass_rename"],
            affected_files=["sample.txt"],
        )


@pytest.mark.parametrize("score", [-1, 101, True, float("inf"), float("nan"), "95", None])
def test_rejects_invalid_scores(response_setup, score):
    with pytest.raises(ValueError):
        response_setup["engine"].handle_detection(
            score=score,
            level="warning",
            triggered_rules=[],
            affected_files=[],
        )


@pytest.mark.parametrize(
    "level",
    ["CRITICAL", "unknown", "", None, 123],
)
def test_rejects_invalid_levels(response_setup, level):
    with pytest.raises(ValueError):
        response_setup["engine"].handle_detection(
            score=50,
            level=level,
            triggered_rules=[],
            affected_files=[],
        )


def test_rejects_non_list_triggered_rules(response_setup):
    with pytest.raises(TypeError):
        response_setup["engine"].handle_detection(
            score=50,
            level="warning",
            triggered_rules="mass_rename",
            affected_files=[],
        )


def test_rejects_empty_triggered_rule(response_setup):
    with pytest.raises(ValueError):
        response_setup["engine"].handle_detection(
            score=50,
            level="warning",
            triggered_rules=[""],
            affected_files=[],
        )


def test_rejects_non_list_affected_files(response_setup):
    with pytest.raises(TypeError):
        response_setup["engine"].handle_detection(
            score=50,
            level="warning",
            triggered_rules=[],
            affected_files="sample.txt",
        )


def test_rejects_empty_affected_file_path(response_setup):
    with pytest.raises(ValueError):
        response_setup["engine"].handle_detection(
            score=50,
            level="warning",
            triggered_rules=[],
            affected_files=[" "],
        )


def test_alerts_and_incident_share_timestamp(response_setup):
    response_setup["engine"].handle_detection(
        score=95,
        level="critical",
        triggered_rules=["mass_rename", "high_entropy"],
        affected_files=["sample.txt"],
    )

    alerts = response_setup["alerts"]
    incident = response_setup["incidents"][0]

    assert alerts[0]["timestamp"] == alerts[1]["timestamp"]
    assert alerts[0]["timestamp"] == incident["timestamp"]


def test_rejects_invalid_quarantine_result(
    response_setup,
):
    manager = response_setup["manager"]
    manager.result = ["valid-path", " "]

    result = response_setup["engine"].handle_detection(
        score=95,
        level="critical",
        triggered_rules=["mass_rename"],
        affected_files=["sample.txt"],
    )

    assert result == []
    assert len(response_setup["incidents"]) == 1


def test_empty_rules_still_records_critical_incident(response_setup):
    response_setup["engine"].handle_detection(
        score=95,
        level="critical",
        triggered_rules=[],
        affected_files=["sample.txt"],
    )

    assert response_setup["alerts"] == []
    assert len(response_setup["incidents"]) == 1
