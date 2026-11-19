
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from sqlalchemy.exc import IntegrityError

from app.database import database, repository
from app.database.models import Alert, Base, ProcessRecord


def test_database_engine_is_reused(monkeypatch, tmp_path):
    database_path = tmp_path / "rdrs.db"

    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    monkeypatch.setattr(
        database,
        "DATABASE_URL",
        f"sqlite:///{database_path}",
    )

    database._get_engine.cache_clear()
    database._get_session_factory.cache_clear()

    try:
        first_engine = database.get_engine()
        second_engine = database.get_engine()

        assert first_engine is second_engine

    finally:
        database._get_session_factory.cache_clear()
        database._get_engine.cache_clear()
        first_engine.dispose()


def test_database_session_uses_shared_engine(monkeypatch, tmp_path):
    database_path = tmp_path / "session_test.db"

    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    monkeypatch.setattr(
        database,
        "DATABASE_URL",
        f"sqlite:///{database_path}",
    )

    database._get_engine.cache_clear()
    database._get_session_factory.cache_clear()

    try:
        session = database.get_session()

        assert session.get_bind() is database.get_engine()

        session.close()

    finally:
        database._get_session_factory.cache_clear()
        database._get_engine.cache_clear()


def test_session_factory_is_reused(monkeypatch, tmp_path):
    database_path = tmp_path / "factory_test.db"

    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    monkeypatch.setattr(
        database,
        "DATABASE_URL",
        f"sqlite:///{database_path}",
    )

    database._get_engine.cache_clear()
    database._get_session_factory.cache_clear()

    try:
        first_factory = database._get_session_factory(
            database.DATABASE_URL
        )
        second_factory = database._get_session_factory(
            database.DATABASE_URL
        )

        assert first_factory is second_factory

    finally:
        database._get_session_factory.cache_clear()
        database._get_engine.cache_clear()


def test_save_record_rolls_back_and_closes_after_commit_failure(
    monkeypatch,
):
    session = MagicMock()
    session.commit.side_effect = RuntimeError(
        "Simulated database commit failure"
    )

    monkeypatch.setattr(repository, "get_session", lambda: session)

    record = object()

    with pytest.raises(
        RuntimeError,
        match="Simulated database commit failure",
    ):
        repository._save_record(record)

    session.add.assert_called_once_with(record)
    session.commit.assert_called_once()
    session.rollback.assert_called_once()
    session.close.assert_called_once()


def test_save_record_commits_and_closes_successfully(monkeypatch):
    session = MagicMock()

    monkeypatch.setattr(repository, "get_session", lambda: session)

    record = object()

    repository._save_record(record)

    session.add.assert_called_once_with(record)
    session.commit.assert_called_once()
    session.rollback.assert_not_called()
    session.close.assert_called_once()


def test_save_record_closes_session_when_add_fails(monkeypatch):
    session = MagicMock()
    session.add.side_effect = RuntimeError("Add failed")

    monkeypatch.setattr(repository, "get_session", lambda: session)

    with pytest.raises(RuntimeError, match="Add failed"):
        repository._save_record(object())

    session.rollback.assert_called_once()
    session.close.assert_called_once()


def test_save_alert_rejects_invalid_score():
    with pytest.raises(ValueError):
        repository.save_alert(
            score=101,
            level="critical",
            rule="mass_rename",
        )


def test_save_alert_rejects_boolean_score():
    with pytest.raises(ValueError):
        repository.save_alert(
            score=True,
            level="critical",
            rule="mass_rename",
        )


def test_save_alert_rejects_invalid_level():
    with pytest.raises(ValueError):
        repository.save_alert(
            score=90,
            level="CRITICAL",
            rule="mass_rename",
        )


def test_save_alert_rejects_empty_rule():
    with pytest.raises(ValueError):
        repository.save_alert(
            score=90,
            level="critical",
            rule=" ",
        )


def test_save_file_event_rejects_empty_path():
    with pytest.raises(ValueError):
        repository.save_file_event(
            event_type="modify",
            path=" ",
        )


def test_save_file_event_rejects_invalid_timestamp():
    with pytest.raises(TypeError):
        repository.save_file_event(
            event_type="modify",
            path="sample.txt",
            timestamp="not-a-date",
        )


def test_save_process_snapshot_rejects_missing_fields():
    with pytest.raises(ValueError, match="Missing process fields"):
        repository.save_process_snapshot({"pid": 123})


def test_save_process_snapshot_rejects_invalid_pid():
    process = {
        "pid": 0,
        "name": "test",
        "username": None,
        "cpu_percent": 10.0,
        "memory_percent": 20.0,
    }

    with pytest.raises(ValueError):
        repository.save_process_snapshot(process)


@pytest.mark.parametrize(
    "cpu_percent",
    [-1, float("inf"), float("nan"), True, "10"],
)
def test_save_process_snapshot_rejects_invalid_cpu(cpu_percent):
    process = {
        "pid": 123,
        "name": "test",
        "username": None,
        "cpu_percent": cpu_percent,
        "memory_percent": 20.0,
    }

    with pytest.raises(ValueError):
        repository.save_process_snapshot(process)


@pytest.mark.parametrize(
    "memory_percent",
    [-1, 101, float("inf"), float("nan"), True],
)
def test_save_process_snapshot_rejects_invalid_memory(memory_percent):
    process = {
        "pid": 123,
        "name": "test",
        "username": None,
        "cpu_percent": 10.0,
        "memory_percent": memory_percent,
    }

    with pytest.raises(ValueError):
        repository.save_process_snapshot(process)


def test_save_process_snapshot_accepts_unavailable_metrics(monkeypatch):
    session = MagicMock()

    monkeypatch.setattr(repository, "get_session", lambda: session)

    process = {
        "pid": 123,
        "name": "test",
        "username": None,
        "cpu_percent": None,
        "memory_percent": None,
    }

    repository.save_process_snapshot(process)

    record = session.add.call_args.args[0]

    assert record.cpu_percent == 0.0
    assert record.memory_percent == 0.0
    session.commit.assert_called_once()
    session.close.assert_called_once()


def test_save_incident_rejects_non_list_files():
    with pytest.raises(TypeError):
        repository.save_incident(
            score=90,
            level="critical",
            affected_files="sample.txt",
        )


def test_save_incident_rejects_empty_file_path():
    with pytest.raises(ValueError):
        repository.save_incident(
            score=90,
            level="critical",
            affected_files=["sample.txt", " "],
        )


@pytest.mark.parametrize(
    "limit",
    [0, -1, True, 1.5, "10"],
)
def test_repository_queries_reject_invalid_limits(limit):
    with pytest.raises(ValueError):
        repository.get_recent_alerts(limit=limit)


def test_repository_persists_and_retrieves_alerts(monkeypatch, tmp_path):
    database_path = tmp_path / "repository_test.db"

    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    monkeypatch.setattr(
        database,
        "DATABASE_URL",
        f"sqlite:///{database_path}",
    )

    database._get_engine.cache_clear()
    database._get_session_factory.cache_clear()

    try:
        database.create_database()

        repository.save_alert(
            score=95,
            level="critical",
            rule="mass_rename",
        )

        alerts = repository.get_recent_alerts()

        assert len(alerts) == 1
        assert alerts[0]["score"] == 95
        assert alerts[0]["level"] == "critical"
        assert alerts[0]["rule"] == "mass_rename"

    finally:
        database._get_session_factory.cache_clear()
        engine = database._get_engine(database.DATABASE_URL)
        engine.dispose()
        database._get_engine.cache_clear()


def test_database_rejects_invalid_alert_score(monkeypatch, tmp_path):
    database_path = tmp_path / "constraint_test.db"

    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    monkeypatch.setattr(
        database,
        "DATABASE_URL",
        f"sqlite:///{database_path}",
    )

    database._get_engine.cache_clear()
    database._get_session_factory.cache_clear()

    try:
        database.create_database()

        session = database.get_session()

        try:
            session.add(
                Alert(
                    score=101,
                    level="critical",
                    rule="mass_rename",
                    timestamp=datetime.now(),
                )
            )

            with pytest.raises(IntegrityError):
                session.commit()

            session.rollback()

        finally:
            session.close()

    finally:
        database._get_session_factory.cache_clear()
        engine = database._get_engine(database.DATABASE_URL)
        engine.dispose()
        database._get_engine.cache_clear()


def test_database_rejects_invalid_process_memory(monkeypatch, tmp_path):
    database_path = tmp_path / "process_constraint_test.db"

    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    monkeypatch.setattr(
        database,
        "DATABASE_URL",
        f"sqlite:///{database_path}",
    )

    database._get_engine.cache_clear()
    database._get_session_factory.cache_clear()

    try:
        database.create_database()

        session = database.get_session()

        try:
            session.add(
                ProcessRecord(
                    pid=123,
                    name="test",
                    username=None,
                    cpu_percent=10.0,
                    memory_percent=150.0,
                    timestamp=datetime.now(),
                )
            )

            with pytest.raises(IntegrityError):
                session.commit()

            session.rollback()

        finally:
            session.close()

    finally:
        database._get_session_factory.cache_clear()
        engine = database._get_engine(database.DATABASE_URL)
        engine.dispose()
        database._get_engine.cache_clear()
