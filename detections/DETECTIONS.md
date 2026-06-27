# Detections Catalogue

> **Status:** Stub — populated in M2 (live lab required).

Each row carries the traceability chain: CV claim → ATT&CK ID → rule → rationale → validation evidence.

| # | Detection | ATT&CK ID | Rule file | Rationale | Validation trigger | Evidence |
|---|-----------|-----------|-----------|-----------|-------------------|---------|
| 1 | SSH brute-force | T1110.001 / T1110.003 | `rules/100001-ssh-bruteforce.xml` | N auth failures in window | `hydra` against victim SSH | Pending M3 |
| 2 | Privilege escalation via sudo | T1548.003 | `rules/100002-sudo-privesc.xml` | PAM sudo event from non-admin | Atomic T1548.003 | Pending M3 |
| 3 | Local account creation | T1136.001 | `rules/100003-account-creation.xml` | `useradd` exec event | Atomic T1136.001 | Pending M3 |
| 4 | Suspicious shell exec | T1059.004 | `rules/100004-shell-exec.xml` | `curl\|bash`, `nc -e` patterns | Atomic T1059.004 | Pending M3 |
| 5 | FIM — /etc or /usr/bin change | T1565.001 / T1070 | `rules/100005-fim-etc.xml` | Wazuh syscheck alert | Modify monitored file | Pending M3 |
