"""
Windows EVTX file reader.

This module provides the low-level interface between Windows .evtx files
and the rest of the CyberPower EventLog Analyzer.

At this layer we only read records from the EVTX file. Interpretation and
analysis belong in other modules.
"""

from collections.abc import Iterator
from pathlib import Path

from Evtx.Evtx import Evtx


def iter_evtx_xml(file_path: str | Path) -> Iterator[str]:
    """
    Yield the XML representation of each record in an EVTX file.

    Records are yielded one at a time so large event logs do not need to
    be loaded completely into memory.

    Args:
        file_path:
            Path to the Windows .evtx file.

    Yields:
        XML representation of each event record.

    Raises:
        FileNotFoundError:
            If the supplied path does not exist.

        IsADirectoryError:
            If the supplied path points to a directory instead of a file.

        ValueError:
            If the supplied file does not have the .evtx extension.
    """

    path = Path(file_path).expanduser()

    if not path.exists():
        raise FileNotFoundError(f"EVTX file not found: {path}")

    if not path.is_file():
        raise IsADirectoryError(f"EVTX path is not a file: {path}")

    if path.suffix.lower() != ".evtx":
        raise ValueError(f"Expected an .evtx file: {path}")

    with Evtx(str(path)) as evtx:
        for record in evtx.records():
            yield record.xml()


# Microsoft Windows Event Log XML namespace.
EVENT_XML_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
XML_NAMESPACES = {"event": EVENT_XML_NAMESPACE}


def _optional_int(value: str | None) -> int | None:
    """
    Convert an optional string to an integer.

    Missing or empty values are represented as None.
    """

    if value is None or not value.strip():
        return None

    return int(value)


def _parse_timestamp(value: str | None):
    """
    Convert a Windows event timestamp into a timezone-aware datetime.

    Missing or empty timestamps are represented as None.
    """

    if value is None or not value.strip():
        return None

    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_event_xml(
    xml_text: str,
    source_file: str | Path | None = None,
):
    """
    Parse Windows Event XML into a normalized EventRecord.

    This function extracts common System metadata and preserves
    provider-specific EventData without interpreting its meaning.
    """

    import xml.etree.ElementTree as ET

    from eventlog_analyzer.models import EventRecord

    root = ET.fromstring(xml_text)

    system = root.find("event:System", XML_NAMESPACES)

    if system is None:
        raise ValueError("Windows Event XML does not contain a System element.")

    def system_text(element_name: str) -> str | None:
        element = system.find(f"event:{element_name}", XML_NAMESPACES)

        if element is None or element.text is None:
            return None

        return element.text.strip()

    provider_element = system.find("event:Provider", XML_NAMESPACES)
    time_element = system.find("event:TimeCreated", XML_NAMESPACES)
    correlation_element = system.find("event:Correlation", XML_NAMESPACES)
    execution_element = system.find("event:Execution", XML_NAMESPACES)
    security_element = system.find("event:Security", XML_NAMESPACES)

    event_data: dict[str, str | None] = {}

    event_data_element = root.find("event:EventData", XML_NAMESPACES)

    if event_data_element is not None:
        for index, data_element in enumerate(
            event_data_element.findall("event:Data", XML_NAMESPACES)
        ):
            name = data_element.get("Name")

            # Some Windows providers may emit unnamed Data elements.
            # Preserve them rather than silently discarding information.
            if not name:
                name = f"_unnamed_{index}"

            event_data[name] = data_element.text

    return EventRecord(
        event_id=_optional_int(system_text("EventID")) or 0,
        record_id=_optional_int(system_text("EventRecordID")),
        timestamp=_parse_timestamp(
            time_element.get("SystemTime") if time_element is not None else None
        ),
        provider=(
            provider_element.get("Name")
            if provider_element is not None
            else None
        ),
        channel=system_text("Channel"),
        computer=system_text("Computer"),
        level=_optional_int(system_text("Level")),
        process_id=_optional_int(
            execution_element.get("ProcessID")
            if execution_element is not None
            else None
        ),
        thread_id=_optional_int(
            execution_element.get("ThreadID")
            if execution_element is not None
            else None
        ),
        activity_id=(
            correlation_element.get("ActivityID")
            if correlation_element is not None
            else None
        ),
        user_id=(
            security_element.get("UserID")
            if security_element is not None
            else None
        ),
        event_data=event_data,
        raw_xml=xml_text,
        source_file=Path(source_file) if source_file is not None else None,
    )


def iter_events(file_path: str | Path) -> Iterator["EventRecord"]:
    """
    Yield normalized EventRecord objects from an EVTX file.

    This is the primary high-level interface for reading Windows EVTX
    files. Records are parsed one at a time to avoid loading the entire
    event log into memory.
    """

    from eventlog_analyzer.models import EventRecord

    path = Path(file_path).expanduser()

    for xml_text in iter_evtx_xml(path):
        yield parse_event_xml(
            xml_text,
            source_file=path,
        )
