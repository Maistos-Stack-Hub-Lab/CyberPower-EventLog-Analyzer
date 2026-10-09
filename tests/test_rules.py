from datetime import datetime, timezone

from eventlog_analyzer.models import EventRecord, Severity
from eventlog_analyzer.rules import analyze_code_integrity_3077


def test_code_integrity_3077_creates_finding():
    timestamp = datetime(
        2026,
        10,
        3,
        13,
        4,
        40,
        tzinfo=timezone.utc,
    )

    event = EventRecord(
        event_id=3077,
        record_id=1969,
        timestamp=timestamp,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        event_data={
            "File Name": r"\Device\HarddiskVolume3\Example\component.pyd",
            "Process Name": r"\Device\HarddiskVolume3\Example\application.exe",
            "Requested Signing Level": "2",
            "Validated Signing Level": "1",
            "Status": "0xc0e90002",
            "PolicyName": "VerifiedAndReputableDesktop",
            "Unrelated Field": "should not be copied",
        },
    )

    finding = analyze_code_integrity_3077(event)

    assert finding is not None
    assert finding.rule_id == "codeintegrity.event_3077"
    assert finding.category == "CodeIntegrity"
    assert finding.severity is Severity.HIGH
    assert finding.event_id == 3077
    assert finding.record_id == 1969
    assert finding.timestamp == timestamp

    assert finding.interpretation is not None
    assert finding.hypothesis is None

    assert finding.evidence["Status"] == "0xc0e90002"
    assert finding.evidence["PolicyName"] == "VerifiedAndReputableDesktop"
    assert "Unrelated Field" not in finding.evidence


def test_code_integrity_3077_ignores_other_event_ids():
    event = EventRecord(
        event_id=3089,
        record_id=2000,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
    )

    finding = analyze_code_integrity_3077(event)

    assert finding is None


def test_code_integrity_3077_ignores_other_providers():
    event = EventRecord(
        event_id=3077,
        record_id=2001,
        timestamp=None,
        provider="Some-Other-Provider",
        channel="Some-Other-Channel",
        computer="TEST-PC",
    )

    finding = analyze_code_integrity_3077(event)

    assert finding is None


def test_code_integrity_3077_adds_documented_interpretation():
    event = EventRecord(
        event_id=3077,
        record_id=1969,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        event_data={
            "File Name": r"\Device\HarddiskVolume3\Example\component.pyd",
            "Process Name": r"\Device\HarddiskVolume3\Example\application.exe",
            "Requested Signing Level": "2",
            "Validated Signing Level": "1",
            "Status": "0xc0e90002",
            "PolicyName": "VerifiedAndReputableDesktop",
        },
    )

    finding = analyze_code_integrity_3077(event)

    assert finding is not None
    assert finding.interpretation is not None

    assert "blocked" in finding.interpretation.lower()
    assert "App Control" in finding.interpretation
    assert "signing level 2" in finding.interpretation
    assert "signing level 1" in finding.interpretation

    # Event 3077 alone must not claim that the file is definitely unsigned.
    assert "file is unsigned" not in finding.interpretation.lower()

    # Root cause remains unconfirmed until additional evidence is correlated.
    assert finding.hypothesis is None


def test_code_integrity_3089_records_signature_information():
    from eventlog_analyzer.rules import analyze_code_integrity_3089

    event = EventRecord(
        event_id=3089,
        record_id=200,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
        activity_id="{11111111-2222-3333-4444-555555555555}",
        event_data={
            "TotalSignatureCount": "0",
            "Signature": "0",
            "SignatureType": "0",
            "ValidatedSigningLevel": "0",
            "VerificationError": "0",
            "PublisherName": "Unknown",
            "IssuerName": "Unknown",
        },
    )

    finding = analyze_code_integrity_3089(event)

    assert finding is not None
    assert finding.rule_id == "codeintegrity.event_3089"
    assert finding.severity is Severity.INFO
    assert finding.event_id == 3089
    assert finding.record_id == 200

    assert finding.evidence["TotalSignatureCount"] == "0"
    assert finding.evidence["ActivityID"] == event.activity_id

    assert "zero signatures" in finding.interpretation
    assert finding.hypothesis is None


def test_code_integrity_3089_ignores_unrelated_events():
    from eventlog_analyzer.rules import analyze_code_integrity_3089

    wrong_event_id = EventRecord(
        event_id=3077,
        record_id=201,
        timestamp=None,
        provider="Microsoft-Windows-CodeIntegrity",
        channel="Microsoft-Windows-CodeIntegrity/Operational",
        computer="TEST-PC",
    )

    wrong_provider = EventRecord(
        event_id=3089,
        record_id=202,
        timestamp=None,
        provider="TEST-PROVIDER",
        channel="TEST-CHANNEL",
        computer="TEST-PC",
    )

    assert analyze_code_integrity_3089(wrong_event_id) is None
    assert analyze_code_integrity_3089(wrong_provider) is None
