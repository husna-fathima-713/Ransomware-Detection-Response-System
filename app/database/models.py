
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.database import Base


class FileEventRecord(Base):
    __tablename__ = "file_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    extension: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="",
    )
    old_extension: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )


class ProcessRecord(Base):
    __tablename__ = "processes"

    __table_args__ = (
        CheckConstraint("pid > 0", name="ck_process_positive_pid"),
        CheckConstraint(
            "cpu_percent >= 0",
            name="ck_process_nonnegative_cpu",
        ),
        CheckConstraint(
            "memory_percent >= 0 AND memory_percent <= 100",
            name="ck_process_valid_memory",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    pid: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="",
    )
    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    cpu_percent: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    memory_percent: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )


class Alert(Base):
    __tablename__ = "alerts"

    __table_args__ = (
        CheckConstraint(
            "score >= 0 AND score <= 100",
            name="ck_alert_valid_score",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    level: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    rule: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )


class Incident(Base):
    __tablename__ = "incidents"

    __table_args__ = (
        CheckConstraint(
            "score >= 0 AND score <= 100",
            name="ck_incident_valid_score",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    level: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="open",
    )
    affected_files: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )
