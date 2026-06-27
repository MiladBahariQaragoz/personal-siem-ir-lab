# Threat Model

> **Status:** Stub — expand after live lab is operational (M1+).

## Assets
- Oracle Cloud VCN (private subnet, siem + victim instances)
- Wazuh dashboard (443, locked to owner IP)
- Lab credentials (SSH keys, Wazuh admin password)

## Attack surface
- Victim SSH port (intentionally exposed for brute-force simulation, in-VCN only)
- Wazuh dashboard (443, locked by security list)
- Agent↔manager channel (private subnet, not internet-routable)

## Scope guard as a control
`siem_ir.safety.check(target)` ensures no attack script runs outside `lab.subnets`.
Fail-closed: malformed or missing input is refused, never default-allowed.

## Out of scope
- External attackers (no public attack surface by design)
- Data exfiltration (lab contains no real PII)
