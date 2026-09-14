from app.detectors.process_monitor import get_process_snapshot


def get_process_stats(cpu_threshold: float = 50.0) -> dict:
    """Calculate statistics for currently running processes."""
    processes = get_process_snapshot()

    high_cpu_processes = [
        process
        for process in processes
        if (process["cpu_percent"] or 0.0) >= cpu_threshold
    ]

    highest_cpu = max(
        (
            process["cpu_percent"] or 0.0
            for process in processes
        ),
        default=0.0,
    )

    return {
        "total_processes": len(processes),
        "high_cpu_count": len(high_cpu_processes),
        "highest_cpu_percent": highest_cpu,
        "high_cpu_processes": high_cpu_processes,
    }