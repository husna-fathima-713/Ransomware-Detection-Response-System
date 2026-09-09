import math
from pathlib import Path


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte sequence."""
    if not data:
        return 0.0

    frequencies = [0] * 256

    for byte in data:
        frequencies[byte] += 1

    entropy = 0.0
    length = len(data)

    for count in frequencies:
        if count == 0:
            continue

        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_file_entropy(
    file_path: str | Path,
    sample_size: int = 64 * 1024,
) -> float:
    """Calculate entropy from the first sample_size bytes of a file."""
    path = Path(file_path)

    with path.open("rb") as file:
        data = file.read(sample_size)

    return calculate_entropy(data)