
import math
from numbers import Real

import psutil


PROCESS_ATTRIBUTES = [
    "pid",
    "name",
    "username",
    "cpu_percent",
    "memory_percent",
]


def _is_valid_number(value, maximum=None):
    """Check whether a process metric is a finite, non-negative number."""
    if isinstance(value, bool) or not isinstance(value, Real):
        return False

    if not math.isfinite(value) or value < 0:
        return False

    if maximum is not None and value > maximum:
        return False

    return True


def _is_valid_process_info(info):
    """Validate the fields required for a process snapshot."""
    if not isinstance(info, dict):
        return False

    pid = info.get("pid")

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False

    for field in ("name", "username"):
        if info.get(field) is not None and not isinstance(info[field], str):
            return False

    cpu_percent = info.get("cpu_percent")
    memory_percent = info.get("memory_percent")

    if cpu_percent is not None and not _is_valid_number(cpu_percent):
        return False

    if memory_percent is not None and not _is_valid_number(
        memory_percent,
        maximum=100.0,
    ):
        return False

    return True


def get_process_snapshot() -> list[dict]:
    """Collect validated information about currently running processes."""
    processes = []

    for process in psutil.process_iter(PROCESS_ATTRIBUTES):
        try:
            info = process.info

            if not _is_valid_process_info(info):
                continue

            processes.append(
                {
                    "pid": info["pid"],
                    "name": info.get("name"),
                    "username": info.get("username"),
                    "cpu_percent": info.get("cpu_percent"),
                    "memory_percent": info.get("memory_percent"),
                }
            )

        except (psutil.Error, OSError, AttributeError):
            continue

    return processes
