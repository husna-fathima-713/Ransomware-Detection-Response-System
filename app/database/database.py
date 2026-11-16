
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


@lru_cache(maxsize=4)
def _get_session_factory(database_url: str):
    """Return a cached session factory for the database URL."""
    return sessionmaker(
        bind=_get_engine(database_url),
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


def get_engine():
    """Get the shared database engine."""
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    return _get_engine(DATABASE_URL)


def create_database() -> None:
    """Create the RDRS database and all registered tables."""
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Import models so SQLAlchemy registers their table definitions.
    from app.database import models  # noqa: F401

    Base.metadata.create_all(bind=get_engine())


def get_session():
    """Create a session using the shared session factory."""
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    return _get_session_factory(DATABASE_URL)()
