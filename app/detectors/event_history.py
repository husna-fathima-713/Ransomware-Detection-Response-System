
import math
from collections import deque
from datetime import datetime, timedelta
from numbers import Real

from app.detectors.event import FileEvent


class EventHistory:
    """Maintain filesystem events within a validated sliding time window."""

    def __init__(self, window_seconds: int = 60) -> None:
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, Real)
            or not math.isfinite(window_seconds)
            or window_seconds <= 0
        ):
            raise ValueError(
                "Window duration must be a positive finite number."
            )

        self.window = timedelta(seconds=window_seconds)
        self.events: deque[FileEvent] = deque()

    def add(self, event: FileEvent) -> None:
        """Add a valid event and remove expired history."""
        if not isinstance(event, FileEvent):
            raise ValueError("Event must be a FileEvent instance.")

        if not isinstance(event.timestamp, datetime):
            raise ValueError("Event timestamp must be a datetime.")

        now = datetime.now(tz=event.timestamp.tzinfo)

        if event.timestamp > now:
            raise ValueError("Future-dated events are not allowed.")

        self.events.append(event)
        self._remove_expired()

    def _remove_expired(self) -> None:
        """Remove expired events, including out-of-order entries."""
        retained_events = deque()

        for event in self.events:
            now = datetime.now(tz=event.timestamp.tzinfo)
            cutoff = now - self.window

            if event.timestamp >= cutoff:
                retained_events.append(event)

        self.events = retained_events

    def get_events(self) -> list[FileEvent]:
        """Return events currently inside the sliding window."""
        self._remove_expired()
        return list(self.events)

    def count(self) -> int:
        """Return the number of events currently inside the window."""
        self._remove_expired()
        return len(self.events)
