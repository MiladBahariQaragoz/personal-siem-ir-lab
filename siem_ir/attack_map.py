"""ATT&CK technique catalogue and rule-ID → technique mapping for siem_ir.

This module defines:
  TECHNIQUES  — dict[str, TechniqueInfo]: T-ID → name, tactic, url
  RULE_MAP    — dict[int, str]: Wazuh rule ID → ATT&CK T-ID
  PLANNED_TTPS — list[str]: T-IDs planned for this lab (scope of coverage analysis)

Only the techniques relevant to this lab's detection scope are catalogued here.
Add rows as new detections are authored (M2+).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TechniqueInfo:
    """Minimal ATT&CK technique metadata."""

    technique_id: str
    name: str
    tactic: str
    url: str


# ---------------------------------------------------------------------------
# Technique catalogue (lab scope only)
# ---------------------------------------------------------------------------

TECHNIQUES: dict[str, TechniqueInfo] = {
    "T1110.001": TechniqueInfo(
        technique_id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/001/",
    ),
    "T1110.003": TechniqueInfo(
        technique_id="T1110.003",
        name="Brute Force: Password Spraying",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/003/",
    ),
    "T1078": TechniqueInfo(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        url="https://attack.mitre.org/techniques/T1078/",
    ),
    "T1548.003": TechniqueInfo(
        technique_id="T1548.003",
        name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        tactic="Privilege Escalation / Defense Evasion",
        url="https://attack.mitre.org/techniques/T1548/003/",
    ),
    "T1136.001": TechniqueInfo(
        technique_id="T1136.001",
        name="Create Account: Local Account",
        tactic="Persistence",
        url="https://attack.mitre.org/techniques/T1136/001/",
    ),
    "T1059.004": TechniqueInfo(
        technique_id="T1059.004",
        name="Command and Scripting Interpreter: Unix Shell",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/004/",
    ),
    "T1565.001": TechniqueInfo(
        technique_id="T1565.001",
        name="Data Manipulation: Stored Data Manipulation",
        tactic="Impact",
        url="https://attack.mitre.org/techniques/T1565/001/",
    ),
    "T1070": TechniqueInfo(
        technique_id="T1070",
        name="Indicator Removal",
        tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1070/",
    ),
}

# ---------------------------------------------------------------------------
# Rule-ID → ATT&CK T-ID mapping (populated as rules are authored in M2)
# ---------------------------------------------------------------------------
# Keys are Wazuh rule IDs (must be ≥ 100000 for custom rules).
# These correspond to the detections in detections/DETECTIONS.md.

RULE_MAP: dict[int, str] = {
    100001: "T1110.001",  # SSH brute-force
    100002: "T1548.003",  # sudo privilege escalation
    100003: "T1136.001",  # local account creation
    100004: "T1059.004",  # suspicious shell exec
    100005: "T1565.001",  # FIM — /etc or /usr/bin change
}

# ---------------------------------------------------------------------------
# Planned TTPs for this lab — the "full plan" column in the coverage matrix.
# A gap is a planned TTP that had no matching alert in the fixture.
# ---------------------------------------------------------------------------

PLANNED_TTPS: list[str] = [
    "T1110.001",  # Detection 1
    "T1548.003",  # Detection 2
    "T1136.001",  # Detection 3
    "T1059.004",  # Detection 4
    "T1565.001",  # Detection 5
]
