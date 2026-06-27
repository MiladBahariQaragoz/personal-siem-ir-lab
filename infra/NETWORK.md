# Network Architecture

> **Status:** Stub — populated in M1 (live lab required).

## Lab topology

```
Oracle Cloud — one VCN, one private subnet (10.0.0.0/24)
┌────────────────────────────────────────────────────────┐
│  siem   (~3 OCPU / 18 GB ARM64)                        │
│   • Wazuh all-in-one: manager + indexer + dashboard    │
│   • local Wazuh agent (self-monitoring)                │
│                                                        │
│  victim (~1 OCPU / 6 GB ARM64)                         │
│   • Ubuntu + Wazuh agent                              │
│   • SSH exposed (brute-force target), auditd, FIM dirs │
│   • Atomic Red Team runner                             │
└────────────────────────────────────────────────────────┘
 agent→manager 1514/1515 stays PRIVATE inside the VCN
 dashboard 443 reachable only from owner IP or SSH tunnel
```

## Security controls
- Agent↔manager traffic (1514/1515) never leaves the VCN.
- Dashboard (443) locked to owner IP via security list.
- No Wazuh port exposed to the public internet.

## Provisioning notes
See `docs/RUNBOOK.md` and `infra/bootstrap-siem.sh` / `infra/bootstrap-victim.sh` (M1).
