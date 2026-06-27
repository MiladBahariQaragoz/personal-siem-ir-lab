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


# ---------------------------------------------------------------------------
# Finding #2: non-list JSON must raise ValueError, not AttributeError
# ---------------------------------------------------------------------------


def test_non_list_json_raises_value_error():
    """A JSON object at top level must raise ValueError, not AttributeError."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({}, f)
        path = pathlib.Path(f.name)
    try:
        with pytest.raises(ValueError, match="Expected a JSON list"):
            coverage_matrix(path)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Finding #3: malformed JSON must raise ValueError, not JSONDecodeError
# ---------------------------------------------------------------------------


def test_malformed_json_raises_value_error():
    """Invalid JSON content must raise ValueError with a clean message."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("NOT JSON")
        path = pathlib.Path(f.name)
    try:
        with pytest.raises(ValueError, match="Invalid JSON"):
            coverage_matrix(path)
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Security: SECURITY#4 — input size caps must be enforced
# ---------------------------------------------------------------------------


def test_oversized_file_rejected(tmp_path, monkeypatch):
    """Files larger than MAX_FIXTURE_BYTES must raise ValueError (SECURITY#4)."""
    from siem_ir.coverage import MAX_FIXTURE_BYTES

    oversized = tmp_path / "big.json"
    # Write a valid JSON list but fake a huge file size via stat mock.
    oversized.write_text("[]", encoding="utf-8")

    import pathlib as _pathlib

    original_stat = _pathlib.Path.stat

    def fake_stat(self, **kwargs):
        s = original_stat(self, **kwargs)
        # Return a stat result with inflated st_size
        import os
        return os.stat_result((
            s.st_mode, s.st_ino, s.st_dev, s.st_nlink,
            s.st_uid, s.st_gid,
            MAX_FIXTURE_BYTES + 1,  # inflated size
            s.st_atime, s.st_mtime, s.st_ctime,
        ))

    monkeypatch.setattr(_pathlib.Path, "stat", fake_stat)

    with pytest.raises(ValueError, match=r"(?i)bytes|max|filtered"):
        coverage_matrix(oversized)


def test_too_many_alerts_rejected(tmp_path):
    """Alert counts exceeding MAX_ALERTS must raise ValueError (SECURITY#4)."""
    from siem_ir.coverage import MAX_ALERTS

    # Write MAX_ALERTS + 1 minimal alert objects.
    alert = {"rule": {"id": "999999"}, "timestamp": "2026-06-27T00:00:00.000Z"}
    fixture = tmp_path / "overflow.json"
    import json as _json
    fixture.write_text(_json.dumps([alert] * (MAX_ALERTS + 1)), encoding="utf-8")

    with pytest.raises(ValueError, match=r"(?i)too many|max"):
        coverage_matrix(fixture)
