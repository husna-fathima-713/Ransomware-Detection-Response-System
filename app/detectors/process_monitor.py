import psutil


def get_process_snapshot() -> list[dict]:
    """Collect basic information about running processes."""
    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_percent"]
    ):
        try:
            info = process.info

            processes.append(
                {
                    "pid": info["pid"],
                    "name": info["name"],
                    "username": info["username"],
                    "cpu_percent": info["cpu_percent"],
                    "memory_percent": info["memory_percent"],
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes