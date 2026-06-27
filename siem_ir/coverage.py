"""ATT&CK coverage matrix generator for siem_ir.

Reads exported Wazuh alert JSON fixtures and produces:
  - A list of detected ATT&CK technique IDs (hits)
  - A list of planned-but-undetected technique IDs (gaps)
  - A Markdown coverage matrix
  - A JSON summary

The CLI entry point is `siem-ir coverage --alerts <path>`.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

from siem_ir.attack_map import PLANNED_TTPS, RULE_MAP, TECHNIQUES


@dataclass
class CoverageResult:
    """Output of coverage_matrix()."""

    hits: list[str] = field(default_factory=list)
    """ATT&CK technique IDs observed in at least one alert."""
    gaps: list[str] = field(default_factory=list)
    """Planned ATT&CK technique IDs with no matching alert."""
    markdown: str = ""
    """Human-readable Markdown coverage matrix."""
    json_output: str = ""
    """JSON summary (hits + gaps)."""


def _load_alerts(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Alert fixture not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _extract_detected_ttps(alerts: list[dict]) -> set[str]:
    """Map fired rule IDs → ATT&CK T-IDs via RULE_MAP."""
    detected: set[str] = set()
    for alert in alerts:
        source = alert.get("_source", alert)  # support both wrapped and flat
        rule = source.get("rule", {})
        try:
            rule_id = int(rule.get("id", -1))
        except (ValueError, TypeError):
            continue
        if rule_id in RULE_MAP:
            detected.add(RULE_MAP[rule_id])
    return detected


def _build_markdown(hits: list[str], gaps: list[str]) -> str:
    lines = [
        "# ATT&CK Coverage Matrix",
        "",
        "| ATT&CK ID | Name | Tactic | Status |",
        "|-----------|------|--------|--------|",
    ]
    for ttp in PLANNED_TTPS:
        info = TECHNIQUES.get(ttp)
        name = info.name if info else "Unknown"
        tactic = info.tactic if info else "—"
        status = "✓ DETECTED" if ttp in hits else "✗ GAP"
        lines.append(f"| {ttp} | {name} | {tactic} | {status} |")
    lines += [
        "",
        f"**Detected:** {len(hits)} / {len(PLANNED_TTPS)} planned TTPs",
        f"**Gaps:** {len(gaps)} undetected",
    ]
    if gaps:
        lines += ["", "## Detection Gaps", ""]
        for ttp in gaps:
            info = TECHNIQUES.get(ttp)
            name = info.name if info else "Unknown"
            lines.append(f"- **{ttp}** — {name}: no alert fired in this fixture.")
    return "\n".join(lines)


def coverage_matrix(alerts_path: pathlib.Path) -> CoverageResult:
    """Generate ATT&CK coverage matrix from a Wazuh alert fixture.

    Args:
        alerts_path: Path to the exported alerts JSON file.

    Returns:
        CoverageResult with hits, gaps, markdown, and json_output populated.
    """
    alerts = _load_alerts(alerts_path)
    detected = _extract_detected_ttps(alerts)

    hits = sorted(t for t in PLANNED_TTPS if t in detected)
    gaps = sorted(t for t in PLANNED_TTPS if t not in detected)

    md = _build_markdown(hits, gaps)
    js = json.dumps({"hits": hits, "gaps": gaps}, indent=2)

    return CoverageResult(hits=hits, gaps=gaps, markdown=md, json_output=js)
