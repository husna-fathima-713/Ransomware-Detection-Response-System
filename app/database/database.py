from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


DATABASE_PATH = Path("data/rdrs.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"


class Base(DeclarativeBase):
    pass


def create_database() -> None:
    """Create the RDRS SQLite database."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    from app.database.models import Alert, FileEventRecord, ProcessRecord

    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)


def get_session():
    """Create a database session."""
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )

    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    return SessionLocal()