from eventlog_analyzer.correlation import correlate_code_integrity_events
from eventlog_analyzer.models import EventRecord


def test_correlates_3077_and_3089_with_same_activity_id():
    activity_id = "{11111111-2222-3333-4444-555555555555}"

    event_3077 = EventRecord(
        event_id=3077,
        record_id=101,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=5678,
    )

    event_3089 = EventRecord(
        event_id=3089,
        record_id=100,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=5678,
    )

    pairs = correlate_code_integrity_events([event_3089, event_3077])

    assert len(pairs) == 1
    assert pairs[0][0] is event_3077
    assert pairs[0][1] is event_3089



def test_does_not_correlate_different_activity_ids():
    event_3077 = EventRecord(
        event_id=3077,
        record_id=201,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id="{11111111-2222-3333-4444-555555555555}",
    )

    event_3089 = EventRecord(
        event_id=3089,
        record_id=200,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id="{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
    )

    pairs = correlate_code_integrity_events([event_3077, event_3089])

    assert pairs == []


def test_does_not_correlate_events_from_different_computers():
    activity_id = "{11111111-2222-3333-4444-555555555555}"

    event_3077 = EventRecord(
        event_id=3077,
        record_id=301,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC-A",
        activity_id=activity_id,
    )

    event_3089 = EventRecord(
        event_id=3089,
        record_id=300,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC-B",
        activity_id=activity_id,
    )

    pairs = correlate_code_integrity_events([event_3077, event_3089])

    assert pairs == []


def test_does_not_correlate_events_without_activity_ids():
    event_3077 = EventRecord(
        event_id=3077,
        record_id=401,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=None,
    )

    event_3089 = EventRecord(
        event_id=3089,
        record_id=400,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=None,
    )

    pairs = correlate_code_integrity_events([event_3077, event_3089])

    assert pairs == []


def test_does_not_correlate_ambiguous_event_groups():
    activity_id = "{11111111-2222-3333-4444-555555555555}"

    def make_event(event_id, record_id):
        return EventRecord(
            event_id=event_id,
            record_id=record_id,
            timestamp=None,
            provider="Microsoft-Windows-CodeIntegrity",
            channel="Microsoft-Windows-CodeIntegrity/Operational",
            computer="TEST-PC",
            activity_id=activity_id,
        )

    events = [
        make_event(3089, 500),
        make_event(3077, 501),
        make_event(3089, 502),
        make_event(3077, 503),
    ]

    pairs = correlate_code_integrity_events(events)

    assert pairs == []


def test_does_not_correlate_different_process_ids():
    activity_id = "{11111111-2222-3333-4444-555555555555}"

    event_3077 = EventRecord(
        event_id=3077,
        record_id=601,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=5678,
    )

    event_3089 = EventRecord(
        event_id=3089,
        record_id=600,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=9999,
        thread_id=5678,
    )

    pairs = correlate_code_integrity_events([event_3077, event_3089])

    assert pairs == []


def test_does_not_correlate_different_thread_ids():
    activity_id = "{11111111-2222-3333-4444-555555555555}"

    event_3077 = EventRecord(
        event_id=3077,
        record_id=701,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=5678,
    )

    event_3089 = EventRecord(
        event_id=3089,
        record_id=700,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=9999,
    )

    pairs = correlate_code_integrity_events([event_3077, event_3089])

    assert pairs == []


def test_does_not_correlate_events_far_apart_in_time():
    from datetime import datetime, timedelta, timezone

    activity_id = "{11111111-2222-3333-4444-555555555555}"
    start = datetime(2026, 10, 3, 13, 0, tzinfo=timezone.utc)

    event_3077 = EventRecord(
        event_id=3077,
        record_id=801,
        timestamp=start + timedelta(minutes=10),
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=5678,
    )

    event_3089 = EventRecord(
        event_id=3089,
        record_id=800,
        timestamp=start,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=5678,
    )

    pairs = correlate_code_integrity_events([event_3077, event_3089])

    assert pairs == []


def test_correlates_events_with_close_timestamps():
    from datetime import datetime, timedelta, timezone

    activity_id = "{11111111-2222-3333-4444-555555555555}"
    start = datetime(2026, 10, 3, 13, 0, tzinfo=timezone.utc)

    event_3077 = EventRecord(
        event_id=3077,
        record_id=901,
        timestamp=start + timedelta(milliseconds=150),
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=5678,
    )

    event_3089 = EventRecord(
        event_id=3089,
        record_id=900,
        timestamp=start,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=5678,
    )

    pairs = correlate_code_integrity_events([event_3089, event_3077])

    assert len(pairs) == 1
    assert pairs[0] == (event_3077, event_3089)


def test_correlates_events_when_one_timestamp_is_missing():
    from datetime import datetime, timezone

    activity_id = "{11111111-2222-3333-4444-555555555555}"

    event_3077 = EventRecord(
        event_id=3077,
        record_id=1001,
        timestamp=datetime(2026, 10, 3, 13, 0, tzinfo=timezone.utc),
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=5678,
    )

    event_3089 = EventRecord(
        event_id=3089,
        record_id=1000,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
        process_id=1234,
        thread_id=5678,
    )

    pairs = correlate_code_integrity_events([event_3089, event_3077])

    assert pairs == [(event_3077, event_3089)]


def test_does_not_correlate_mixed_timezone_timestamps():
    from datetime import datetime, timezone

    activity_id = "{11111111-2222-3333-4444-555555555555}"

    event_3077 = EventRecord(
        event_id=3077,
        record_id=1101,
        timestamp=datetime(2026, 10, 3, 13, 0, tzinfo=timezone.utc),
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
    )

    event_3089 = EventRecord(
        event_id=3089,
        record_id=1100,
        timestamp=datetime(2026, 10, 3, 13, 0),
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id=activity_id,
    )

    pairs = correlate_code_integrity_events([event_3077, event_3089])

    assert pairs == []
