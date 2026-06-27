"""Tests for siem_ir.validate_rules — Wazuh rule XML linter."""
import pathlib

import pytest

from siem_ir.validate_rules import RuleError, validate_rule_file, validate_rules_dir

FIXTURES = pathlib.Path("fixtures/rules")


# ---------------------------------------------------------------------------
# Happy path: valid rule passes with no errors
# ---------------------------------------------------------------------------


def test_valid_rule_passes():
    errors = validate_rule_file(FIXTURES / "rule_valid.xml")
    assert errors == [], f"Expected no errors, got: {errors}"


# ---------------------------------------------------------------------------
# Failure: rule id < 100000
# ---------------------------------------------------------------------------


def test_bad_id_fails():
    errors = validate_rule_file(FIXTURES / "rule_bad_id.xml")
    assert any("100000" in e or "id" in e.lower() for e in errors), (
        f"Expected rule-id error, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Failure: missing mitre/ATT&CK tag
# ---------------------------------------------------------------------------


def test_no_mitre_fails():
    errors = validate_rule_file(FIXTURES / "rule_no_mitre.xml")
    assert any(
        "mitre" in e.lower() or "att&ck" in e.lower() or "attack" in e.lower() for e in errors
    ), f"Expected mitre error, got: {errors}"


# ---------------------------------------------------------------------------
# Failure: missing group element
# ---------------------------------------------------------------------------


def test_no_group_fails():
    errors = validate_rule_file(FIXTURES / "rule_no_group.xml")
    assert any("group" in e.lower() for e in errors), (
        f"Expected group error, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Failure: malformed XML
# ---------------------------------------------------------------------------


def test_malformed_xml_fails():
    errors = validate_rule_file(FIXTURES / "rule_malformed.xml")
    assert any(
        "xml" in e.lower() or "parse" in e.lower() or "malformed" in e.lower() for e in errors
    ), f"Expected XML parse error, got: {errors}"


# ---------------------------------------------------------------------------
# Directory linter: aggregates errors across all files
# ---------------------------------------------------------------------------


def test_dir_lint_finds_valid_and_bad():
    results = validate_rules_dir(FIXTURES)
    # valid rule must have no errors
    assert any(k.endswith("rule_valid.xml") and v == [] for k, v in results.items()), (
        "Valid rule should have empty error list"
    )
    # bad_id must have errors
    assert any(k.endswith("rule_bad_id.xml") and v != [] for k, v in results.items()), (
        "rule_bad_id.xml should have errors"
    )


def test_dir_lint_returns_dict():
    results = validate_rules_dir(FIXTURES)
    assert isinstance(results, dict)


def test_missing_dir_raises():
    with pytest.raises((FileNotFoundError, NotADirectoryError)):
        validate_rules_dir(pathlib.Path("fixtures/nonexistent_dir/"))


# ---------------------------------------------------------------------------
# Ensure RuleError is importable (used for individual rule errors)
# ---------------------------------------------------------------------------


def test_rule_error_is_exception():
    assert issubclass(RuleError, Exception)
