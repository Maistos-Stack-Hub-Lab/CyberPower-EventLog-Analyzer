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

    interpretation = (
        "The referenced file was blocked by an enforced App Control policy."
    )

    requested_signing_level = event.event_data.get("Requested Signing Level")
    validated_signing_level = event.event_data.get("Validated Signing Level")

    if requested_signing_level == "2" and validated_signing_level == "1":
        interpretation += (
            " Requested signing level 2 required the file to pass the "
            "App Control policy. Validated signing level 1 means Windows "
            "treated the file as unsigned or as having no signature that "
            "passed the active policy."
        )

    return Finding(
        rule_id="codeintegrity.event_3077",
        category="CodeIntegrity",
        severity=Severity.HIGH,
        title="Windows Code Integrity Event 3077 detected",
        observation=(
            "A Microsoft-Windows-CodeIntegrity event with Event ID 3077 "
            "was recorded."
        ),
        interpretation=interpretation,
        evidence=evidence,
        event_id=event.event_id,
        record_id=event.record_id,
        timestamp=event.timestamp,
    )


def analyze_code_integrity_3089(event: EventRecord) -> Finding | None:
    """
    Record signature information from CodeIntegrity Event ID 3089.

    This event provides signature details associated with a CodeIntegrity
    validation. It does not independently establish a block or root cause.
    """

    if event.provider != CODE_INTEGRITY_PROVIDER:
        return None

    if event.event_id != 3089:
        return None

    evidence_keys = (
        "TotalSignatureCount",
        "Signature",
        "SignatureType",
        "ValidatedSigningLevel",
        "VerificationError",
        "PublisherName",
        "IssuerName",
        "Hash",
        "PageHash",
    )

    evidence = {
        key: event.event_data[key]
        for key in evidence_keys
        if key in event.event_data
    }

    if event.activity_id is not None:
        evidence["ActivityID"] = event.activity_id

    interpretation = (
        "This event records signature information associated with "
        "a Windows CodeIntegrity validation."
    )

    if event.event_data.get("TotalSignatureCount") == "0":
        interpretation += (
            " Windows reported zero signatures for the inspected file "
            "in this event. This alone does not establish the cause "
            "of any application block."
        )

    return Finding(
        rule_id="codeintegrity.event_3089",
        category="CodeIntegrity",
        severity=Severity.INFO,
        title="Windows Code Integrity Event 3089 detected",
        observation=(
            "A Microsoft-Windows-CodeIntegrity event with Event ID 3089 "
            "was recorded."
        ),
        interpretation=interpretation,
        evidence=evidence,
        event_id=event.event_id,
        record_id=event.record_id,
        timestamp=event.timestamp,
    )
