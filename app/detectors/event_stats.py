from collections import Counter

from app.detectors.event import FileEvent
from app.detectors.event_history import EventHistory


class EventStats:
    """Calculate statistics from events in the sliding window."""

    def __init__(self, history: EventHistory) -> None:
        self.history = history

    def calculate(self) -> dict:
        events = self.history.get_events()

        event_types = Counter(event.event_type for event in events)

        return {
            "total_events": len(events),
            "created": event_types.get("create", 0),
            "modified": event_types.get("modify", 0),
            "deleted": event_types.get("delete", 0),
            "renamed": event_types.get("rename", 0),
        }