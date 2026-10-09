"""
Correlation of related Windows Event Log records.

Correlation identifies relationships between events. It does not
establish root cause.
"""

from collections.abc import Iterable

from eventlog_analyzer.models import EventRecord
from eventlog_analyzer.rules import CODE_INTEGRITY_PROVIDER


def correlate_code_integrity_events(
    events: Iterable[EventRecord],
) -> list[tuple[EventRecord, EventRecord]]:
    """
    Match CodeIntegrity 3077 and 3089 records by ActivityID and computer.

    Each returned tuple contains (event_3077, event_3089).
    """

    grouped: dict[tuple[str, str], dict[int, list[EventRecord]]] = {}

    for event in events:
        if event.provider != CODE_INTEGRITY_PROVIDER:
            continue

        if event.event_id not in (3077, 3089):
            continue

        if not event.activity_id or not event.computer:
            continue

        key = (event.computer.casefold(), event.activity_id.casefold())

        group = grouped.setdefault(key, {3077: [], 3089: []})
        group[event.event_id].append(event)

    pairs: list[tuple[EventRecord, EventRecord]] = []

    for group in grouped.values():
        if len(group[3077]) != 1 or len(group[3089]) != 1:
            continue

        event_3077 = group[3077][0]
        event_3089 = group[3089][0]

        if (
            event_3077.process_id is not None
            and event_3089.process_id is not None
            and event_3077.process_id != event_3089.process_id
        ):
            continue

        if (
            event_3077.thread_id is not None
            and event_3089.thread_id is not None
            and event_3077.thread_id != event_3089.thread_id
        ):
            continue

        if (
            event_3077.timestamp is not None
            and event_3089.timestamp is not None
        ):
            timestamp_3077 = event_3077.timestamp
            timestamp_3089 = event_3089.timestamp

            aware_3077 = (
                timestamp_3077.utcoffset() is not None
            )
            aware_3089 = (
                timestamp_3089.utcoffset() is not None
            )

            if aware_3077 != aware_3089:
                continue

            time_difference = abs(
                (timestamp_3077 - timestamp_3089).total_seconds()
            )

            if time_difference > 5:
                continue

        pairs.append((event_3077, event_3089))

    return pairs
