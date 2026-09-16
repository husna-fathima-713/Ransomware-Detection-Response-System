from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.database import Base


class FileEventRecord(Base):
    __tablename__ = "file_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(50))
    path: Mapped[str] = mapped_column(String(500))
    extension: Mapped[str] = mapped_column(String(50), default="")
    old_extension: Mapped[str] = mapped_column(String(50), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime)


class ProcessRecord(Base):
    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pid: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(255))
    username: Mapped[str | None] = mapped_column(String(255))
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0)
    memory_percent: Mapped[float] = mapped_column(Float, default=0.0)
    timestamp: Mapped[datetime] = mapped_column(DateTime)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    score: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(50))
    rule: Mapped[str] = mapped_column(String(255))
    timestamp: Mapped[datetime] = mapped_column(DateTime)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    score: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50), default="open")
    affected_files: Mapped[str] = mapped_column(String(2000), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime)