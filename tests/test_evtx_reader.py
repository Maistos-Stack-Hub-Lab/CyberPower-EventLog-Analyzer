from datetime import timezone
from pathlib import Path

from eventlog_analyzer.evtx_reader import parse_event_xml


SAMPLE_EVENT_XML = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-CodeIntegrity" />
    <EventID>3077</EventID>
    <Level>2</Level>
    <TimeCreated SystemTime="2026-10-03T13:04:40.850800Z" />
    <EventRecordID>1234</EventRecordID>
    <Correlation ActivityID="{11111111-2222-3333-4444-555555555555}" />
    <Execution ProcessID="1000" ThreadID="2000" />
    <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel>
    <Computer>TEST-PC</Computer>
    <Security UserID="S-1-5-21-TEST" />
  </System>
  <EventData>
    <Data Name="File Name">C:\\Program Files\\Example\\example.pyd</Data>
    <Data Name="Process Name">C:\\Program Files\\Example\\example.exe</Data>
    <Data Name="Status">0xc0e90002</Data>
    <Data Name="PolicyName">VerifiedAndReputableDesktop</Data>
  </EventData>
</Event>
"""


def test_parse_event_xml():
    event = parse_event_xml(
        SAMPLE_EVENT_XML,
        source_file="input/test.evtx",
    )

    assert event.event_id == 3077
    assert event.record_id == 1234
    assert event.provider == "Microsoft-Windows-CodeIntegrity"
    assert event.level == 2

    assert event.process_id == 1000
    assert event.thread_id == 2000

    assert event.channel == "Microsoft-Windows-CodeIntegrity/Operational"
    assert event.computer == "TEST-PC"
    assert event.user_id == "S-1-5-21-TEST"

    assert event.activity_id == "{11111111-2222-3333-4444-555555555555}"

    assert event.timestamp is not None
    assert event.timestamp.tzinfo == timezone.utc

    assert event.event_data["File Name"] == (
        "C:\\Program Files\\Example\\example.pyd"
    )
    assert event.event_data["Process Name"] == (
        "C:\\Program Files\\Example\\example.exe"
    )
    assert event.event_data["Status"] == "0xc0e90002"
    assert event.event_data["PolicyName"] == "VerifiedAndReputableDesktop"

    assert event.source_file == Path("input/test.evtx")
    assert event.raw_xml == SAMPLE_EVENT_XML


def test_parse_event_xml_preserves_duplicate_event_data_names():
    xml_text = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Test-Provider" />
    <EventID>9999</EventID>
    <EventRecordID>1</EventRecordID>
  </System>
  <EventData>
    <Data Name="RuleName">First rule</Data>
    <Data Name="RuleName">Second rule</Data>
    <Data Name="Status">Test status</Data>
  </EventData>
</Event>
"""

    event = parse_event_xml(xml_text)

    assert event.event_data["RuleName"] == [
        "First rule",
        "Second rule",
    ]

    assert event.event_data["Status"] == "Test status"


def test_parse_event_xml_preserves_multiple_and_empty_duplicate_values():
    xml_text = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Test-Provider" />
    <EventID>9999</EventID>
    <EventRecordID>2</EventRecordID>
  </System>
  <EventData>
    <Data Name="RuleName">First rule</Data>
    <Data Name="RuleName"></Data>
    <Data Name="RuleName">Third rule</Data>
  </EventData>
</Event>
"""

    event = parse_event_xml(xml_text)

    assert event.event_data["RuleName"] == [
        "First rule",
        None,
        "Third rule",
    ]


def test_parse_event_xml_preserves_correlation_activity_id():
    from eventlog_analyzer.evtx_reader import parse_event_xml

    xml = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-CodeIntegrity" />
    <EventID>3089</EventID>
    <EventRecordID>101</EventRecordID>
    <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel>
    <Computer>TEST-PC</Computer>
    <Correlation ActivityID="{11111111-2222-3333-4444-555555555555}" />
    <Execution ProcessID="1234" ThreadID="5678" />
  </System>
  <EventData>
    <Data Name="TotalSignatureCount">0</Data>
  </EventData>
</Event>
"""

    event = parse_event_xml(xml)

    assert event.event_id == 3089
    assert event.activity_id == "{11111111-2222-3333-4444-555555555555}"
    assert event.process_id == 1234
    assert event.thread_id == 5678
    assert event.event_data["TotalSignatureCount"] == "0"
