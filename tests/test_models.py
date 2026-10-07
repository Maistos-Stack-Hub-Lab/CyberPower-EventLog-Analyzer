from datetime import datetime, timezone

from eventlog_analyzer.models import Finding, Severity


def test_finding_preserves_structured_analysis_data():
    timestamp = datetime(
        2026,
        10,
        3,
        13,
        4,
        40,
        tzinfo=timezone.utc,
    )

    finding = Finding(
        rule_id="test.example",
        category="Test",
        severity=Severity.HIGH,
        title="Example finding",
        observation="An example event was observed.",
        interpretation="The event has a documented technical meaning.",
        hypothesis="A possible cause requires additional confirmation.",
        evidence={
            "Status": "0xc0e90002",
            "File Name": r"C:\Program Files\Example\example.pyd",
        },
        event_id=3077,
        record_id=1234,
        timestamp=timestamp,
    )

    assert finding.rule_id == "test.example"
    assert finding.category == "Test"
    assert finding.severity is Severity.HIGH

    assert finding.observation == "An example event was observed."
    assert finding.interpretation is not None
    assert finding.hypothesis is not None

    assert finding.evidence["Status"] == "0xc0e90002"
    assert finding.event_id == 3077
    assert finding.record_id == 1234
    assert finding.timestamp == timestamp
