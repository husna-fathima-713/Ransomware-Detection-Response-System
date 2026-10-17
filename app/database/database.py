
from functools import lru_cache
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


DATABASE_PATH = Path("data/rdrs.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"


class Base(DeclarativeBase):
    pass


@lru_cache(maxsize=4)
def _get_engine(database_url: str):
    """Return a cached SQLAlchemy engine for the database URL."""
    return create_engine(
        database_url,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )


def get_engine():
    """Get the shared database engine."""
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    return _get_engine(DATABASE_URL)


def create_database() -> None:
    """Create the RDRS SQLite database and its tables."""
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    from app.database.models import (
        Alert,
        FileEventRecord,
        Incident,
        ProcessRecord,
    )

    Base.metadata.create_all(get_engine())


def get_session():
    """Create a session using the shared database engine."""
    SessionLocal = sessionmaker(
        bind=get_engine(),
        autoflush=False,
        autocommit=False,
    )

    return SessionLocal()
