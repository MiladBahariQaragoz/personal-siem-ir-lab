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

### Scope guard configuration (SECURITY#3)
The guard loads `lab.toml` in this order:
1. `SIEM_IR_LAB_CONFIG` environment variable (highest priority).
2. `<repo-root>/lab.toml` (one level above the `siem_ir/` package).

The resolved path is always emitted via `warnings.warn` so operators can verify the
correct config was loaded. Do **not** rely on ancestor-directory discovery — set
`SIEM_IR_LAB_CONFIG` explicitly in CI/CD pipelines.

### Scope guard notes
- `_ALLOWED_SUBNETS` is a module-level **cache** (not a security boundary by itself —
  Python code can always rebind module attributes). Security comes from using only the
  `check()` function as the single gating point in attack scripts.
- Call `siem_ir.safety.reload()` if `lab.toml` is updated while the process is running.

## Input size limits (SECURITY#4)
`siem_ir/coverage._load_alerts()` enforces:
- `MAX_FIXTURE_BYTES = 100 MB` — fixture files larger than this are rejected.
- `MAX_ALERTS = 50 000` — alert lists longer than this are rejected.

These limits protect against memory exhaustion from raw SIEM exports.

## Output path validation (SECURITY#5)
`siem-ir coverage --output-json` and `siem-ir report --output` paths are validated against
the current working directory via `_safe_output_path()`. Paths that resolve outside `cwd`
are refused. In CI pipelines, ensure `--output*` arguments are not attacker-influenced.

## Out of scope
- External attackers (no public attack surface by design)
- Data exfiltration (lab contains no real PII)
