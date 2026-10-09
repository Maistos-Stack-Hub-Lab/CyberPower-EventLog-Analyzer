from eventlog_analyzer.analyzer import analyze_event
from eventlog_analyzer.models import EventRecord, Severity


def test_analyze_event_applies_default_rules():
    event = EventRecord(
        event_id=3077,
        record_id=1969,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        event_data={
            "File Name": r"C:\Example\component.pyd",
            "Requested Signing Level": "2",
            "Validated Signing Level": "1",
            "Status": "0xc0e90002",
        },
    )

    findings = analyze_event(event)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "codeintegrity.event_3077"
    assert finding.severity is Severity.HIGH
    assert finding.event_id == 3077
    assert finding.record_id == 1969

    assert finding.interpretation is not None
    assert finding.hypothesis is None
    assert finding.evidence["Status"] == "0xc0e90002"


def test_analyze_event_returns_empty_list_for_unmatched_event():
    event = EventRecord(
        event_id=3089,
        record_id=1970,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
    )

    findings = analyze_event(event)

    assert findings == []


def test_analyze_event_collects_multiple_findings():
    from eventlog_analyzer.models import Finding

    event = EventRecord(
        event_id=9999,
        record_id=2000,
        timestamp=None,
        provider="TEST-PROVIDER",
        channel="TEST-CHANNEL",
        computer="TEST-PC",
    )

    def first_rule(event):
        return Finding(
            rule_id="test.first_rule",
            category="test",
            severity=Severity.INFO,
            title="First finding",
            observation="First test rule matched.",
            evidence={},
            event_id=event.event_id,
            record_id=event.record_id,
            timestamp=event.timestamp,
        )

    def second_rule(event):
        return Finding(
            rule_id="test.second_rule",
            category="test",
            severity=Severity.LOW,
            title="Second finding",
            observation="Second test rule matched.",
            evidence={},
            event_id=event.event_id,
            record_id=event.record_id,
            timestamp=event.timestamp,
        )

    findings = analyze_event(
        event,
        rules=(first_rule, second_rule),
    )

    assert len(findings) == 2
    assert findings[0].rule_id == "test.first_rule"
    assert findings[1].rule_id == "test.second_rule"


def test_analyze_event_skips_rules_without_findings():
    from eventlog_analyzer.models import Finding

    event = EventRecord(
        event_id=9999,
        record_id=2001,
        timestamp=None,
        provider="TEST-PROVIDER",
        channel="TEST-CHANNEL",
        computer="TEST-PC",
    )

    def non_matching_rule(event):
        return None

    def matching_rule(event):
        return Finding(
            rule_id="test.matching_rule",
            category="test",
            severity=Severity.INFO,
            title="Matching rule",
            observation="This rule produced a finding.",
            evidence={},
            event_id=event.event_id,
            record_id=event.record_id,
            timestamp=event.timestamp,
        )

    findings = analyze_event(
        event,
        rules=(non_matching_rule, matching_rule, non_matching_rule),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "test.matching_rule"


def test_analyze_events_processes_multiple_events_in_order():
    from eventlog_analyzer.analyzer import analyze_events

    def make_event(event_id, record_id):
        return EventRecord(
            event_id=event_id,
            record_id=record_id,
            timestamp=None,
            provider="Microsoft-Windows-CodeIntegrity",
            channel="Microsoft-Windows-CodeIntegrity/Operational",
            computer="TEST-PC",
            event_data={
                "File Name": r"C:\Example\component.pyd",
                "Requested Signing Level": "2",
                "Validated Signing Level": "1",
                "Status": "0xc0e90002",
            },
        )

    events = [
        make_event(3077, 100),
        make_event(3089, 101),
        make_event(3077, 102),
    ]

    findings = analyze_events(events)

    assert len(findings) == 2
    assert [finding.record_id for finding in findings] == [100, 102]
    assert all(
        finding.rule_id == "codeintegrity.event_3077"
        for finding in findings
    )


def test_analyze_events_handles_empty_collection():
    from eventlog_analyzer.analyzer import analyze_events

    findings = analyze_events([])

    assert findings == []


def test_analyze_events_accepts_generator():
    from eventlog_analyzer.analyzer import analyze_events

    def generate_events():
        for record_id in (300, 301, 302):
            yield EventRecord(
                event_id=3077,
                record_id=record_id,
                timestamp=None,
                provider="Microsoft-Windows-CodeIntegrity",
                channel="Microsoft-Windows-CodeIntegrity/Operational",
                computer="TEST-PC",
                event_data={
                    "File Name": r"C:\Example\component.pyd",
                    "Requested Signing Level": "2",
                    "Validated Signing Level": "1",
                    "Status": "0xc0e90002",
                },
            )

    findings = analyze_events(generate_events())

    assert len(findings) == 3
    assert [finding.record_id for finding in findings] == [300, 301, 302]
