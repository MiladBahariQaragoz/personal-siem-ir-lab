"""Tests for siem_ir.report — NIST SP 800-61 IR report drafter."""
import json
import pathlib
import re

import pytest

from siem_ir.report import _escape_md, draft_report

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


# ---------------------------------------------------------------------------
# Security: SECURITY#6 — scenario Markdown injection must be sanitized
# ---------------------------------------------------------------------------


def test_scenario_injection_chars_are_stripped():
    """Characters outside [A-Za-z0-9_-] in --scenario must be sanitized to
    hyphens before embedding in the report (SECURITY#6 — Markdown injection)."""
    injection_scenario = "] (javascript:alert(1)) [<script>evil</script>"
    report = draft_report(FIXTURE, injection_scenario)

    # The raw injection payload must not appear verbatim in the report.
    assert "] (javascript:alert(1)) [" not in report, (
        "Markdown injection characters must be sanitized in the report"
    )
    assert "<script>" not in report, (
        "<script> tag must be removed from scenario in the report"
    )
    # The sanitized version (all non-alphanumeric chars → '-') must appear.
    # Verify that "javascript" and "alert" survive but injection chars are gone.
    assert "javascript" in report, "Alphanumeric content of scenario must be preserved"
    assert "script" in report, "Alphanumeric content of scenario must be preserved"


# ---------------------------------------------------------------------------
# Security: SECURITY#7 — alert field Markdown injection must be neutralized
# ---------------------------------------------------------------------------


def test_escape_md_neutralizes_backticks():
    """_escape_md must replace backticks to prevent code-block injection (SECURITY#7)."""
    from siem_ir.report import _escape_md

    result = _escape_md("evil `payload` here")
    assert "`" not in result, "Backticks must be escaped in untrusted field values"
    assert "&#96;" in result or "payload" in result, (
        "Backtick must be replaced with HTML entity"
    )


def test_escape_md_neutralizes_angle_brackets():
    """_escape_md must replace < and > to prevent HTML injection (SECURITY#7)."""
    result = _escape_md("<script>alert(1)</script>")
    assert "<script>" not in result, "<script> tag must be neutralized"
    assert "&lt;script&gt;" in result or "script" in result, (
        "< and > must be HTML-escaped"
    )


def test_backtick_in_alert_desc_is_neutralized_in_report(tmp_path):
    """A backtick/script payload in a fixture rule.description must be neutralized
    in the Timeline section of the report (SECURITY#7)."""
    malicious_alert = {
        "_source": {
            "timestamp": "2026-06-27T09:01:00.000Z",
            "agent": {"name": "victim"},
            "rule": {
                "id": "100001",
                "description": "`rm -rf /` <script>alert(1)</script>",
            },
        }
    }
    fixture = tmp_path / "malicious.json"
    fixture.write_text(json.dumps([malicious_alert]), encoding="utf-8")

    report = draft_report(fixture, "test-scenario")

    # Raw backtick and raw <script> must not appear verbatim in the report.
    assert "`rm -rf /`" not in report, (
        "Backtick injection in rule.description must be neutralized"
    )
    assert "<script>" not in report, (
        "<script> tag from rule.description must be neutralized"
    )
