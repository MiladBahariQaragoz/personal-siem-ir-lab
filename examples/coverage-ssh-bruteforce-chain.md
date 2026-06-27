# ATT&CK Coverage Matrix

| ATT&CK ID | Name | Tactic | Status |
|-----------|------|--------|--------|
| T1110.001 | Brute Force: Password Guessing | Credential Access | ✓ DETECTED |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Privilege Escalation / Defense Evasion | ✓ DETECTED |
| T1136.001 | Create Account: Local Account | Persistence | ✓ DETECTED |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution | ✗ GAP |
| T1565.001 | Data Manipulation: Stored Data Manipulation | Impact | ✗ GAP |

**Detected:** 3 / 5 planned TTPs
**Gaps:** 2 undetected

## Detection Gaps

- **T1059.004** — Command and Scripting Interpreter: Unix Shell: no alert fired in this fixture.
- **T1565.001** — Data Manipulation: Stored Data Manipulation: no alert fired in this fixture.