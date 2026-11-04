
from datetime import datetime, timedelta

import pytest

from app.detectors.event import FileEvent
from app.detectors.event_history import EventHistory


def make_event(timestamp):
    return FileEvent(
        event_type="modify",
        path="data/sandbox/test.txt",
        timestamp=timestamp,
        extension=".txt",
    )


def test_history_stores_valid_event():
    history = EventHistory(window_seconds=60)

    event = FileEvent.create(
        "modify",
        "data/sandbox/test.txt",
    )

    history.add(event)

    assert history.count() == 1
    assert history.get_events() == [event]


def test_expired_event_is_removed():
    history = EventHistory(window_seconds=60)

    expired_event = make_event(
        datetime.now() - timedelta(seconds=120)
    )

    history.add(expired_event)

    assert history.count() == 0
    assert history.get_events() == []


def test_out_of_order_expired_event_is_removed():
    history = EventHistory(window_seconds=60)

    recent_event = make_event(datetime.now())

    expired_event = make_event(
        datetime.now() - timedelta(seconds=120)
    )

    history.add(recent_event)
    history.add(expired_event)

    events = history.get_events()

    assert len(events) == 1
    assert events[0] == recent_event


def test_future_dated_event_is_rejected():
    history = EventHistory(window_seconds=60)

    future_event = make_event(
        datetime.now() + timedelta(seconds=30)
    )

    with pytest.raises(ValueError, match="Future-dated"):
        history.add(future_event)

    assert history.count() == 0


def test_non_file_event_is_rejected():
    history = EventHistory()

    with pytest.raises(ValueError, match="FileEvent"):
        history.add("invalid event")


@pytest.mark.parametrize(
    "window_seconds",
    [
        0,
        -1,
        True,
        None,
        float("inf"),
        float("nan"),
    ],
)
def test_invalid_window_duration_is_rejected(window_seconds):
    with pytest.raises(ValueError):
        EventHistory(window_seconds=window_seconds)


def test_fractional_window_duration_is_supported():
    history = EventHistory(window_seconds=0.5)

    event = FileEvent.create(
        "modify",
        "data/sandbox/test.txt",
    )

    history.add(event)

    assert history.count() == 1


def test_count_and_get_events_remove_expired_entries():
    history = EventHistory(window_seconds=60)

    history.events.append(
        make_event(datetime.now() - timedelta(seconds=120))
    )

    assert history.count() == 0
    assert history.get_events() == []
