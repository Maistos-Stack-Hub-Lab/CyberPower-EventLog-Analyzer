"""
Data models used by the CyberPower EventLog Analyzer.

This module defines the normalized representation of Windows Event Log
records used throughout the application.

The models in this file do not analyze or interpret events. They only
represent data extracted from the original event log.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


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
