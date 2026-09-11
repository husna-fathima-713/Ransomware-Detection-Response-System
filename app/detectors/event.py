from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class FileEvent:
    event_type: str
    path: str
    timestamp: datetime
    extension: str
    old_extension: str = ""

    @classmethod
    def create(
        cls,
        event_type: str,
        path: str,
        old_extension: str = "",
    ) -> "FileEvent":
        file_path = Path(path)

        return cls(
            event_type=event_type,
            path=str(file_path),
            timestamp=datetime.now(),
            extension=file_path.suffix.lower(),
            old_extension=old_extension.lower(),
        )