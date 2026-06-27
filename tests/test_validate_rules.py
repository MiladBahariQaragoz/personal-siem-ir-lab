"""Tests for siem_ir.validate_rules — Wazuh rule XML linter."""
import pathlib

import defusedxml
import pytest

from siem_ir.validate_rules import validate_rule_file, validate_rules_dir

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
# Finding #5: non-integer rule id must produce exactly one error (not two)
# ---------------------------------------------------------------------------


def test_non_integer_rule_id_produces_exactly_one_error(tmp_path):
    """Rule id='abc' must yield only the 'not an integer' error, not a second
    'in built-in range' error caused by the sentinel value -1."""
    xml = tmp_path / "rule_abc_id.xml"
    xml.write_text(
        """<group name="test,">
  <rule id="abc" level="5">
    <description>Test</description>
    <mitre><id>T1110.001</id></mitre>
    <group>authentication_failed,</group>
  </rule>
</group>""",
        encoding="utf-8",
    )
    errors = validate_rule_file(xml)
    # Must have exactly one error about the id not being an integer
    id_errors = [e for e in errors if "not an integer" in e.lower()]
    range_errors = [e for e in errors if "built-in range" in e.lower()]
    assert len(id_errors) == 1, f"Expected 1 'not an integer' error, got: {errors}"
    assert len(range_errors) == 0, f"Expected 0 range errors, got: {errors}"


# ---------------------------------------------------------------------------
# Security: SECURITY#1 — XXE / entity-expansion DoS must be blocked
# ---------------------------------------------------------------------------


def test_billion_laughs_entity_expansion_is_blocked(tmp_path):
    """A billion-laughs XML payload must be safely rejected by defusedxml,
    not expanded into memory (SECURITY#1 — XXE / entity-expansion)."""
    # Minimal three-level entity expansion; defusedxml catches it at parse time.
    billion_laughs = tmp_path / "billion_laughs.xml"
    billion_laughs.write_text(
        """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<group name="evil,">
  <rule id="100001" level="5">
    <description>&lol3;</description>
    <mitre><id>T1110.001</id></mitre>
    <group>test,</group>
  </rule>
</group>""",
        encoding="utf-8",
    )
    # defusedxml raises EntitiesForbidden (a ValueError subclass) — it must NOT be
    # caught by validate_rule_file's ET.ParseError handler, so it propagates up.
    with pytest.raises((defusedxml.EntitiesForbidden, defusedxml.DTDForbidden)):
        validate_rule_file(billion_laughs)
