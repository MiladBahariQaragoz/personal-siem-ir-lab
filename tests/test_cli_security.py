"""Security tests for siem_ir.cli — path-traversal guard (SECURITY#5)."""
import pytest

from siem_ir.cli import _safe_output_path

# ---------------------------------------------------------------------------
# Security: SECURITY#5 — _safe_output_path must reject traversal escapes
# ---------------------------------------------------------------------------


def test_traversal_path_is_refused(tmp_path):
    """A path like '../../evil' that escapes the allowed directory must raise
    ValueError (SECURITY#5 — output path traversal)."""
    allowed = tmp_path / "output"
    allowed.mkdir()

    with pytest.raises(ValueError, match=r"(?i)escapes|refuse"):
        _safe_output_path("../../evil.txt", allowed)


def test_absolute_path_outside_allowed_refused(tmp_path):
    """An absolute path outside allowed_parent must be refused (SECURITY#5)."""
    allowed = tmp_path / "output"
    allowed.mkdir()
    evil = str(tmp_path.parent / "evil.txt")  # one level above allowed's parent

    with pytest.raises(ValueError, match=r"(?i)escapes|refuse"):
        _safe_output_path(evil, allowed)


def test_in_repo_subpath_is_accepted(tmp_path):
    """A normal in-repo relative path must be accepted (SECURITY#5 — allow-list)."""
    allowed = tmp_path
    result = _safe_output_path("examples/report.md", allowed)
    assert result == (allowed / "examples" / "report.md").resolve()


def test_same_directory_file_is_accepted(tmp_path):
    """A filename in the allowed directory itself must be accepted."""
    allowed = tmp_path
    result = _safe_output_path("output.json", allowed)
    assert result == (allowed / "output.json").resolve()


def test_deep_nested_in_repo_path_is_accepted(tmp_path):
    """A deep relative path inside allowed_parent must be accepted."""
    allowed = tmp_path
    result = _safe_output_path("a/b/c/report.md", allowed)
    assert result == (allowed / "a" / "b" / "c" / "report.md").resolve()
