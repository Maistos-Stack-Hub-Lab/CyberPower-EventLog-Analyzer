# CyberPower EventLog Analyzer

A Python project for analyzing Windows Event Log records, initially focusing on Windows CodeIntegrity events relevant to software troubleshooting.

## Current functionality

- Parse Windows EVTX records into structured event data.
- Analyze CodeIntegrity Events 3077 and 3089.
- Produce individual findings with supporting evidence.
- Identify candidate correlations between related events.
- Preserve ActivityID information.

## CodeIntegrity correlation

Events 3077 and 3089 are correlated when:

- Both originate from Microsoft-Windows-CodeIntegrity.
- ActivityID and computer name match.
- Exactly one event of each type exists in the matching group.
- Process IDs and thread IDs do not conflict when available.
- Timestamps differ by no more than five seconds when both are available.

Mixed timezone-aware and timezone-naive timestamps are rejected.

The five-second threshold is an engineering choice, not a documented Windows requirement.

## Limitations

- Correlation does not establish root cause.
- Event 3089 does not independently establish an application block.
- Missing event metadata can reduce correlation confidence.
- Ambiguous event groups are excluded.
- Combined analysis loads all input events into memory.
- Findings require technical interpretation and supporting evidence.

## Development and testing

Run the test suite from the project root:

    PYTHONPATH=src python -m pytest -v

## Data privacy

Never commit customer EVTX files, diagnostic packages, credentials, or sensitive customer information.

Use synthetic event records for public tests.

## Project status

v0.2.0 is planned as a pre-release.

This project is under active development.
