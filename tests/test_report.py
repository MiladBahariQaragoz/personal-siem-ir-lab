"""Tests for siem_ir.report — NIST SP 800-61 IR report drafter."""
import pathlib
import re

import pytest

from siem_ir.report import draft_report

FIXTURE = pathlib.Path("fixtures/ssh-bruteforce-chain.json")
SCENARIO = "ssh-bruteforce-chain"

_REQUIRED_SECTIONS = [
    "Detection Summary",
    "Timeline",
    "Affected Hosts",
    "ATT&CK Techniques Observed",
    # NIST SP 800-61r2 phases — all must be present
    "Detection & Analysis",
    "Triage",
    "Containment",
    "Eradication",
    "Recovery",
    "Lessons Learned",
]


# ---------------------------------------------------------------------------
# Structure: all required NIST sections must be present
# ---------------------------------------------------------------------------


def _report() -> str:
    return draft_report(FIXTURE, SCENARIO)


def test_returns_string():
    assert isinstance(_report(), str)


@pytest.mark.parametrize("section", _REQUIRED_SECTIONS)
def test_required_section_present(section):
    assert section in _report(), f"Required section missing: {section!r}"


def test_scenario_name_in_report():
    assert SCENARIO in _report()


# ---------------------------------------------------------------------------
# Timeline: events must be in chronological order
# ---------------------------------------------------------------------------


def test_timeline_is_chronological():
    """All ISO timestamps in the Timeline section must be sorted ascending."""
    report = _report()
    # Find the Timeline section
    match = re.search(r"Timeline(.+?)(?=\n## |\Z)", report, re.DOTALL)
    assert match, "Timeline section not found"
    section_text = match.group(1)

    # Extract all ISO timestamps
    ts_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    timestamps = re.findall(ts_pattern, section_text)
    assert len(timestamps) >= 2, "Timeline should contain at least 2 timestamps"
    assert timestamps == sorted(timestamps), (
        f"Timestamps not in chronological order: {timestamps}"
    )


def test_timeline_contains_alert_timestamps():
    """The three fixture alerts' timestamps should appear in the report."""
    report = _report()
    assert "2026-06-27T09:01:00" in report
    assert "2026-06-27T09:04:37" in report
    assert "2026-06-27T09:06:15" in report


# ---------------------------------------------------------------------------
# ATT&CK IDs: detected techniques must appear
# ---------------------------------------------------------------------------


def test_observed_ttps_in_report():
    report = _report()
    assert "T1110.001" in report
    assert "T1548.003" in report
    assert "T1136.001" in report


# ---------------------------------------------------------------------------
# Affected hosts: victim agent name must appear
# ---------------------------------------------------------------------------


def test_affected_host_in_report():
    report = _report()
    assert "victim" in report


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_missing_fixture_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        draft_report(pathlib.Path("fixtures/nonexistent.json"), "test-scenario")
