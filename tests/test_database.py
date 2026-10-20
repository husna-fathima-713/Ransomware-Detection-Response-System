
from unittest.mock import MagicMock

import pytest

from app.database import database, repository


def test_database_engine_is_reused(monkeypatch, tmp_path):
    database_path = tmp_path / "rdrs.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        database_path,
    )
    monkeypatch.setattr(
        database,
        "DATABASE_URL",
        f"sqlite:///{database_path}",
    )

    database._get_engine.cache_clear()

    try:
        first_engine = database.get_engine()
        second_engine = database.get_engine()

        assert first_engine is second_engine
    finally:
        database._get_engine.cache_clear()
        first_engine.dispose()


def test_database_session_uses_shared_engine(monkeypatch, tmp_path):
    database_path = tmp_path / "session_test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        database_path,
    )
    monkeypatch.setattr(
        database,
        "DATABASE_URL",
        f"sqlite:///{database_path}",
    )

    database._get_engine.cache_clear()

    try:
        session = database.get_session()

        assert session.get_bind() is database.get_engine()

        session.close()
    finally:
        database._get_engine.cache_clear()


def test_save_record_rolls_back_and_closes_after_commit_failure(
    monkeypatch,
):
    session = MagicMock()
    session.commit.side_effect = RuntimeError(
        "Simulated database commit failure"
    )

    monkeypatch.setattr(
        repository,
        "get_session",
        lambda: session,
    )

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

    monkeypatch.setattr(
        repository,
        "get_session",
        lambda: session,
    )

    record = object()

    repository._save_record(record)

    session.add.assert_called_once_with(record)
    session.commit.assert_called_once()
    session.rollback.assert_not_called()
    session.close.assert_called_once()
