"""
Data models used by the CyberPower EventLog Analyzer.

This module defines the normalized representation of Windows Event Log
records used throughout the application.

The models in this file do not analyze or interpret events. They only
represent data extracted from the original event log.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Severity assigned to an analysis finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(str, Enum):
    """Evidence confidence/type used by an analysis finding."""

    OBSERVATION = "observation"
    INTERPRETATION = "interpretation"
    HYPOTHESIS = "hypothesis"


@dataclass(slots=True)
class EventRecord:
    """
    Normalized representation of a single Windows Event Log record.

    Provider-specific information is stored in ``event_data`` so that
    the core model is not tied to individual Windows event providers
    or Event IDs.

    ``raw_xml`` is retained so findings can be traced back to the
    original event representation.
    """

    event_id: int
    record_id: int | None
    timestamp: datetime | None
    provider: str | None
    channel: str | None
    computer: str | None

    level: int | None = None
    process_id: int | None = None
    thread_id: int | None = None
    activity_id: str | None = None
    user_id: str | None = None

    event_data: dict[str, Any] = field(default_factory=dict)

    raw_xml: str | None = None
    source_file: Path | None = None


@dataclass(slots=True)
class Finding:
    """
    Structured result produced by the analysis layer.

    Observation, interpretation, and hypothesis are kept separate so
    reports can distinguish directly observed evidence from technical
    interpretation and unconfirmed possible causes.
    """

    rule_id: str
    category: str
    severity: Severity
    title: str
    observation: str

    interpretation: str | None = None
    hypothesis: str | None = None

    evidence: dict[str, Any] = field(default_factory=dict)

    event_id: int | None = None
    record_id: int | None = None
    timestamp: datetime | None = None


@dataclass(slots=True)
class AnalysisResult:
    """Combined event findings and candidate event correlations."""

    findings: list[Finding] = field(default_factory=list)
    correlations: list[tuple[EventRecord, EventRecord]] = field(
        default_factory=list
    )
