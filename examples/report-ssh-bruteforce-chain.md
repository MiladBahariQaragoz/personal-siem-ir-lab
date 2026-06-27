# Incident Response Report — ssh-bruteforce-chain

> **DRAFT — human analyst must review, fill placeholders, and finalize.**
> Generated: 2026-06-27 | Scenario: `ssh-bruteforce-chain`
> Framework: NIST SP 800-61r2

---

## Detection Summary

**Scenario:** ssh-bruteforce-chain
**Total alerts in fixture:** 3
**ATT&CK techniques observed:** 3
**Affected hosts:** victim

> **[TODO — analyst to complete]** Describe the incident scenario and attack narrative here. Detected ATT&CK techniques: T1110.001, T1136.001, T1548.003.

---

## Timeline

Events in chronological order (from Wazuh alert timestamps):

- `2026-06-27T09:01:00Z` | host: `victim` | rule 100001 | SSH brute-force attack detected
- `2026-06-27T09:04:37Z` | host: `victim` | rule 100002 | Privilege escalation via sudo detected
- `2026-06-27T09:06:15Z` | host: `victim` | rule 100003 | Local account creation detected

---

## Affected Hosts

- `victim`

---

## ATT&CK Techniques Observed

- **T1110.001** — Brute Force: Password Guessing (Credential Access) — [https://attack.mitre.org/techniques/T1110/001/](https://attack.mitre.org/techniques/T1110/001/)
- **T1136.001** — Create Account: Local Account (Persistence) — [https://attack.mitre.org/techniques/T1136/001/](https://attack.mitre.org/techniques/T1136/001/)
- **T1548.003** — Abuse Elevation Control Mechanism: Sudo and Sudo Caching (Privilege Escalation / Defense Evasion) — [https://attack.mitre.org/techniques/T1548/003/](https://attack.mitre.org/techniques/T1548/003/)

---

## Detection & Analysis

> **[TODO — analyst to complete]** Describe detection & analysis actions taken for this incident.

---

## Triage

> **[TODO — analyst to complete]** Describe triage actions taken for this incident.

---

## Containment

> **[TODO — analyst to complete]** Describe containment actions taken for this incident.

---

## Eradication

> **[TODO — analyst to complete]** Describe eradication actions taken for this incident.

---

## Recovery

> **[TODO — analyst to complete]** Describe recovery actions taken for this incident.

---

## Lessons Learned

> **[TODO — analyst to complete]** Describe lessons learned actions taken for this incident.

---

## References

- NIST SP 800-61r2 — Computer Security Incident Handling Guide: https://csrc.nist.gov/publications/detail/sp/800/61/rev-2/final
- MITRE ATT&CK: https://attack.mitre.org/
- Alert fixture: `fixtures\ssh-bruteforce-chain.json`