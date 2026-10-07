"""
Analysis rules for Windows Event Log records.

Rules convert normalized EventRecord objects into structured Finding
objects. A rule must not present an unconfirmed cause as established fact.
"""

from eventlog_analyzer.models import EventRecord, Finding, Severity


CODE_INTEGRITY_PROVIDER = "Microsoft-Windows-CodeIntegrity"


def analyze_code_integrity_3077(event: EventRecord) -> Finding | None:
    """
    Create an observation for a CodeIntegrity Event ID 3077.

    This rule currently records observed event data only. Documented
    interpretation and possible causes will be added separately.
    """

    if event.provider != CODE_INTEGRITY_PROVIDER:
        return None

    if event.event_id != 3077:
        return None

    evidence_keys = (
        "File Name",
        "Process Name",
        "Requested Signing Level",
        "Validated Signing Level",
        "Status",
        "PolicyName",
        "PolicyID",
        "PolicyGUID",
    )

    evidence = {
        key: event.event_data[key]
        for key in evidence_keys
        if key in event.event_data
    }

    return Finding(
        rule_id="codeintegrity.event_3077",
        category="CodeIntegrity",
        severity=Severity.HIGH,
        title="Windows Code Integrity Event 3077 detected",
        observation=(
            "A Microsoft-Windows-CodeIntegrity event with Event ID 3077 "
            "was recorded."
        ),
        evidence=evidence,
        event_id=event.event_id,
        record_id=event.record_id,
        timestamp=event.timestamp,
    )
