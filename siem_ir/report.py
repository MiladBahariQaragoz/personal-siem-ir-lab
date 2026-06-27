"""NIST SP 800-61 IR report drafter for siem_ir.

Reads exported Wazuh alert JSON fixtures and drafts the key sections of a
NIST SP 800-61 incident-response report as a Markdown skeleton for the human
analyst to finalize.

The CLI entry point is `siem-ir report --alerts <path> --scenario <name>`.
"""

from __future__ import annotations

import pathlib
from datetime import datetime, timezone

from siem_ir.attack_map import TECHNIQUES
from siem_ir.coverage import _extract_detected_ttps, _load_alerts

_NIST_PHASES = [
    "Detection & Analysis",
    "Triage",
    "Containment",
    "Eradication",
    "Recovery",
    "Lessons Learned",
]


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse ISO 8601 timestamp from Wazuh alert."""
    # Wazuh uses millisecond precision: 2026-06-27T09:01:00.000Z
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse timestamp: {ts_str!r}")


def draft_report(alerts_path: pathlib.Path, scenario: str) -> str:
    """Draft a NIST SP 800-61 IR report skeleton from a Wazuh alert fixture.

    Args:
        alerts_path: Path to the exported alerts JSON file.
        scenario: Short name for this incident scenario (used in report title).

    Returns:
        Markdown string — the drafted IR report skeleton.
    """
    alerts = _load_alerts(alerts_path)
    detected_ttps = _extract_detected_ttps(alerts)

    # Sort alerts by timestamp (chronological)
    def _ts(alert: dict) -> datetime:
        source = alert.get("_source", alert)
        return _parse_timestamp(source.get("timestamp", "1970-01-01T00:00:00Z"))

    sorted_alerts = sorted(alerts, key=_ts)

    # Collect affected hosts and rule descriptions
    hosts: set[str] = set()
    rule_descriptions: list[tuple[datetime, str, str, str]] = []  # ts, host, rule_id, desc
    for alert in sorted_alerts:
        source = alert.get("_source", alert)
        agent = source.get("agent", {})
        host = agent.get("name", agent.get("ip", "unknown"))
        hosts.add(host)
        ts = _ts(alert)
        rule = source.get("rule", {})
        rule_id = rule.get("id", "?")
        desc = rule.get("description", "No description")
        rule_descriptions.append((ts, host, rule_id, desc))

    # Map detected TTPs to names
    ttp_lines = []
    for ttp in sorted(detected_ttps):
        info = TECHNIQUES.get(ttp)
        name = info.name if info else "Unknown technique"
        tactic = info.tactic if info else "—"
        url = info.url if info else ""
        ttp_lines.append(f"- **{ttp}** — {name} ({tactic}) — [{url}]({url})")

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

    lines = [
        f"# Incident Response Report — {scenario}",
        "",
        "> **DRAFT — human analyst must review, fill placeholders, and finalize.**",
        f"> Generated: {now} | Scenario: `{scenario}`",
        "> Framework: NIST SP 800-61r2",
        "",
        "---",
        "",
        "## Detection Summary",
        "",
        f"**Scenario:** {scenario}",
        f"**Total alerts in fixture:** {len(alerts)}",
        f"**ATT&CK techniques observed:** {len(detected_ttps)}",
        f"**Affected hosts:** {', '.join(sorted(hosts))}",
        "",
        "This incident represents a coordinated attack chain: SSH brute-force leading to "
        "successful authentication, followed by privilege escalation and persistence via "
        "local account creation.",
        "",
        "---",
        "",
        "## Timeline",
        "",
        "Events in chronological order (from Wazuh alert timestamps):",
        "",
    ]

    for ts, host, rule_id, desc in rule_descriptions:
        lines.append(
            f"- `{ts.strftime('%Y-%m-%dT%H:%M:%SZ')}` | host: `{host}` | "
            f"rule {rule_id} | {desc}"
        )

    lines += [
        "",
        "---",
        "",
        "## Affected Hosts",
        "",
    ]
    for host in sorted(hosts):
        lines.append(f"- `{host}`")

    lines += [
        "",
        "---",
        "",
        "## ATT&CK Techniques Observed",
        "",
    ]
    lines.extend(ttp_lines if ttp_lines else ["_No techniques mapped._"])

    lines += [
        "",
        "---",
        "",
    ]

    for phase in _NIST_PHASES:
        lines += [
            f"## {phase}",
            "",
            f"> **[TODO — analyst to complete]** Describe {phase.lower()} actions taken "
            f"for this incident.",
            "",
            "---",
            "",
        ]

    lines += [
        "## References",
        "",
        "- NIST SP 800-61r2 — Computer Security Incident Handling Guide: "
        "https://csrc.nist.gov/publications/detail/sp/800/61/rev-2/final",
        "- MITRE ATT&CK: https://attack.mitre.org/",
        f"- Alert fixture: `{alerts_path}`",
    ]

    return "\n".join(lines)
