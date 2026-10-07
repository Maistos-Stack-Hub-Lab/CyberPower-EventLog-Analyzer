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
