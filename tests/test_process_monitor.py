
import psutil

from app.detectors import process_monitor


class FakeProcess:
    def __init__(self, info=None, error=None):
        self._info = info
        self._error = error

    @property
    def info(self):
        if self._error:
            raise self._error
        return self._info


def valid_process_info():
    return {
        "pid": 1234,
        "name": "test.exe",
        "username": "user",
        "cpu_percent": 12.5,
        "memory_percent": 4.2,
    }


def test_process_snapshot_returns_valid_processes(monkeypatch):
    process = FakeProcess(valid_process_info())
    monkeypatch.setattr(
        process_monitor.psutil,
        "process_iter",
        lambda attrs: [process],
    )

    result = process_monitor.get_process_snapshot()

    assert len(result) == 1
    assert result[0]["pid"] == 1234
    assert result[0]["name"] == "test.exe"


def test_process_snapshot_preserves_unavailable_metrics(monkeypatch):
    info = valid_process_info()
    info["cpu_percent"] = None
    info["memory_percent"] = None

    monkeypatch.setattr(
        process_monitor.psutil,
        "process_iter",
        lambda attrs: [FakeProcess(info)],
    )

    result = process_monitor.get_process_snapshot()

    assert len(result) == 1
    assert result[0]["cpu_percent"] is None
    assert result[0]["memory_percent"] is None


def test_process_snapshot_skips_invalid_pid(monkeypatch):
    info = valid_process_info()
    info["pid"] = -1

    monkeypatch.setattr(
        process_monitor.psutil,
        "process_iter",
        lambda attrs: [FakeProcess(info)],
    )

    assert process_monitor.get_process_snapshot() == []


def test_process_snapshot_skips_invalid_cpu_value(monkeypatch):
    info = valid_process_info()
    info["cpu_percent"] = float("inf")

    monkeypatch.setattr(
        process_monitor.psutil,
        "process_iter",
        lambda attrs: [FakeProcess(info)],
    )

    assert process_monitor.get_process_snapshot() == []


def test_process_snapshot_skips_invalid_memory_value(monkeypatch):
    info = valid_process_info()
    info["memory_percent"] = 101.0

    monkeypatch.setattr(
        process_monitor.psutil,
        "process_iter",
        lambda attrs: [FakeProcess(info)],
    )

    assert process_monitor.get_process_snapshot() == []


def test_process_snapshot_skips_malformed_process_info(monkeypatch):
    monkeypatch.setattr(
        process_monitor.psutil,
        "process_iter",
        lambda attrs: [FakeProcess(None)],
    )

    assert process_monitor.get_process_snapshot() == []


def test_process_snapshot_skips_inaccessible_process(monkeypatch):
    process = FakeProcess(error=psutil.AccessDenied(pid=1234))

    monkeypatch.setattr(
        process_monitor.psutil,
        "process_iter",
        lambda attrs: [process],
    )

    assert process_monitor.get_process_snapshot() == []


def test_process_snapshot_continues_after_process_disappears(monkeypatch):
    processes = [
        FakeProcess(error=psutil.NoSuchProcess(pid=1234)),
        FakeProcess(valid_process_info()),
    ]

    monkeypatch.setattr(
        process_monitor.psutil,
        "process_iter",
        lambda attrs: processes,
    )

    result = process_monitor.get_process_snapshot()

    assert len(result) == 1
    assert result[0]["pid"] == 1234
