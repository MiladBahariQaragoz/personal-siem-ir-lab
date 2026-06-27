# Attack Plan

> **Status:** Stub — executed in M3 (live lab required).

## Attack chain: SSH brute-force → privilege escalation → account creation

This single coherent chain exercises detections 1–3 and produces the IR report scenario.

| Step | Action | Tool | Expected detection | ATT&CK |
|------|--------|------|-------------------|--------|
| 1 | SSH brute-force against victim:22 | `hydra` (scope-guarded) | D1: SSH brute-force | T1110.001 |
| 2 | Successful SSH login | hydra credential | — | T1078 |
| 3 | `sudo -l` / privilege escalation | Atomic T1548.003 | D2: sudo privesc | T1548.003 |
| 4 | `useradd attacker` persistence | Atomic T1136.001 | D3: account creation | T1136.001 |

## Scope guard

All attack scripts call `siem_ir.safety.check(target)` before execution.
The target IP must be within `lab.subnets` in `lab.toml`. Execution is refused otherwise.

## Execution (M3)

```bash
# Verify scope guard is operational first
python -m siem_ir.safety check <victim-ip>

# Then run the scoped attack scripts
bash attack/ssh-bruteforce.sh <victim-ip>
# followed by Atomic Red Team steps on victim
```
