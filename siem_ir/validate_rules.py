"""Wazuh custom rule XML linter for siem_ir.

Validates that each rule XML file:
  1. Is well-formed XML.
  2. Contains at least one <rule> element with id >= 100000 (custom user range).
  3. Each <rule> has a <mitre><id> child (ATT&CK technique tag).
  4. Each <rule> has a <group> child element.

The CLI entry point is `siem-ir validate-rules <rules-dir>`.
"""

from __future__ import annotations

import pathlib

# defusedxml replaces stdlib ET — blocks XXE and entity-expansion DoS (SECURITY#1)
import defusedxml.ElementTree as ET


def validate_rule_file(path: pathlib.Path) -> list[str]:
    """Lint a single Wazuh rule XML file.

    Args:
        path: Absolute or relative path to the rule XML file.

    Returns:
        List of error strings. Empty list means the file is valid.
    """
    errors: list[str] = []

    # 1. Well-formed XML
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        errors.append(f"XML parse error: {exc}")
        return errors  # can't do further checks on broken XML

    root = tree.getroot()

    # Find all <rule> elements (may be direct children or grandchildren)
    rules = root.findall(".//rule")

    if not rules:
        errors.append("No <rule> elements found in file.")
        return errors

    for rule_elem in rules:
        rule_id_str = rule_elem.get("id", "")
        # 2. Rule id >= 100000
        try:
            rule_id = int(rule_id_str)
        except ValueError:
            errors.append(
                f"Rule id {rule_id_str!r} is not an integer (must be >= 100000)."
            )
            rule_id = -1
            # Skip range check — -1 is a sentinel, not the actual id.
            # Remaining attribute checks still apply.
        else:
            if rule_id < 100000:
                errors.append(
                    f"Rule id {rule_id} is in the built-in range (< 100000). "
                    "Custom rules must use id >= 100000."
                )

        # 3. <mitre><id> present
        mitre_elem = rule_elem.find("mitre")
        if mitre_elem is None:
            errors.append(
                f"Rule id {rule_id_str}: missing <mitre> element — "
                "every custom rule must map to an ATT&CK technique."
            )
        else:
            mitre_id_elem = mitre_elem.find("id")
            if mitre_id_elem is None or not (mitre_id_elem.text or "").strip():
                errors.append(
                    f"Rule id {rule_id_str}: <mitre><id> is empty or missing — "
                    "ATT&CK technique ID required (e.g. T1110.001)."
                )

        # 4. <group> child element present
        group_elem = rule_elem.find("group")
        if group_elem is None:
            errors.append(
                f"Rule id {rule_id_str}: missing <group> child element — "
                "group is required for rule classification."
            )

    return errors


def validate_rules_dir(rules_dir: pathlib.Path) -> dict[str, list[str]]:
    """Lint all *.xml files in a directory.

    Args:
        rules_dir: Directory containing Wazuh rule XML files.

    Returns:
        Dict mapping file path strings -> list of error strings.
        Files with no errors have an empty list.

    Raises:
        FileNotFoundError: If the directory does not exist.
        NotADirectoryError: If the path is not a directory.
    """
    if not rules_dir.exists():
        raise FileNotFoundError(f"Rules directory not found: {rules_dir}")
    if not rules_dir.is_dir():
        raise NotADirectoryError(f"Not a directory: {rules_dir}")

    results: dict[str, list[str]] = {}
    for xml_file in sorted(rules_dir.glob("*.xml")):
        results[str(xml_file)] = validate_rule_file(xml_file)
    return results
