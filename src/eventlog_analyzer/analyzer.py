"""
Analysis orchestration for Windows Event Log records.

This module applies registered analysis rules to normalized events
and collects their findings. It does not parse EVTX files directly.
"""

from collections.abc import Callable, Iterable

from eventlog_analyzer.models import EventRecord, Finding
from eventlog_analyzer.rules import analyze_code_integrity_3077


# Every rule accepts an EventRecord and may return a Finding.
Rule = Callable[[EventRecord], Finding | None]


# The initial rule registry. Additional rules can be registered later.
DEFAULT_RULES: tuple[Rule, ...] = (
    analyze_code_integrity_3077,
)


def analyze_event(
    event: EventRecord,
    rules: tuple[Rule, ...] = DEFAULT_RULES,
) -> list[Finding]:
    """
    Apply the selected rules to a single event.

    Rules that do not match return None. All matching findings
    are collected in the order in which the rules are registered.
    """

    findings: list[Finding] = []

    for rule in rules:
        finding = rule(event)

        if finding is not None:
            findings.append(finding)

    return findings


def analyze_events(
    events: Iterable[EventRecord],
    rules: tuple[Rule, ...] = DEFAULT_RULES,
) -> list[Finding]:
    """
    Analyze multiple events and collect their findings.

    Events are processed in input order. Findings retain that order.
    """

    findings: list[Finding] = []

    for event in events:
        findings.extend(analyze_event(event, rules=rules))

    return findings
