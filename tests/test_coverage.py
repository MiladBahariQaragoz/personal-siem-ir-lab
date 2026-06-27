"""Tests for siem_ir.coverage — ATT&CK coverage matrix from alert fixture."""
import json
import os
import pathlib
import tempfile

import pytest

from siem_ir.coverage import CoverageResult, coverage_matrix

FIXTURE = pathlib.Path("fixtures/ssh-bruteforce-chain.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _matrix() -> CoverageResult:
    return coverage_matrix(FIXTURE)


# ---------------------------------------------------------------------------
# Structure tests
# ---------------------------------------------------------------------------


def test_returns_coverage_result():
    result = _matrix()
    assert isinstance(result, CoverageResult)


def test_hits_are_detected_ttps():
    """The fixture contains T1110.001, T1548.003, T1136.001."""
    result = _matrix()
    assert "T1110.001" in result.hits
    assert "T1548.003" in result.hits
    assert "T1136.001" in result.hits


def test_gaps_are_undetected_planned_ttps():
    """T1059.004 and T1565.001 are planned but not in the fixture."""
    result = _matrix()
    assert "T1059.004" in result.gaps
    assert "T1565.001" in result.gaps


def test_hits_not_in_gaps():
    result = _matrix()
    assert not (set(result.hits) & set(result.gaps)), "A TTP cannot be both a hit and a gap"


def test_markdown_output_contains_planned_ttps():
    result = _matrix()
    for ttp in ["T1110.001", "T1548.003", "T1136.001"]:
        assert ttp in result.markdown


def test_markdown_output_contains_detected_marker():
    result = _matrix()
    assert (
        "DETECTED" in result.markdown
        or "✓" in result.markdown
        or "detected" in result.markdown.lower()
    )


def test_markdown_output_contains_gap_marker():
    result = _matrix()
    assert (
        "GAP" in result.markdown or "✗" in result.markdown or "gap" in result.markdown.lower()
    )


def test_json_output_is_valid():
    result = _matrix()
    parsed = json.loads(result.json_output)
    assert "hits" in parsed
    assert "gaps" in parsed


def test_json_hits_match_hits_attr():
    result = _matrix()
    parsed = json.loads(result.json_output)
    assert set(parsed["hits"]) == set(result.hits)


def test_json_gaps_match_gaps_attr():
    result = _matrix()
    parsed = json.loads(result.json_output)
    assert set(parsed["gaps"]) == set(result.gaps)


def test_missing_file_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        coverage_matrix(pathlib.Path("fixtures/nonexistent.json"))


def test_rule_ids_not_in_map_are_ignored():
    """Alerts with unmapped rule IDs should not cause crashes."""
    alerts = [{"_source": {"rule": {"id": "999999"}, "timestamp": "2026-06-27T00:00:00.000Z"}}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(alerts, f)
        path = pathlib.Path(f.name)
    try:
        result = coverage_matrix(path)
        assert result.hits == []
    finally:
        os.unlink(path)
