# Lab Runbook

> **Status:** Stub — populated during M1 (live lab provisioning).

## Configuration — scope guard (`SIEM_IR_LAB_CONFIG`)

The `siem_ir` scope guard reads `lab.toml` to load authorized subnets.
Discovery order:

1. **Explicit env var (recommended for CI/CD):**
   ```bash
   export SIEM_IR_LAB_CONFIG=/path/to/lab.toml
   ```
2. **Default:** `<repo-root>/lab.toml` (one level above `siem_ir/`).

If neither is found, `_ALLOWED_SUBNETS` is empty and all `check()` calls raise `ScopeError`
(fail-closed). The resolved path is always logged to stderr via `warnings.warn`.

To refresh subnets without restarting (e.g., after editing `lab.toml`):
```python
import siem_ir.safety as safety
safety.reload()
```

## Pre-flight checklist
- [ ] Oracle Cloud account with Always-Free Ampere quota available
- [ ] SSH key pair generated and uploaded to OCI console
- [ ] `lab.toml` updated with actual private IPs after provisioning

## Provisioning steps (M1)

### 1. Create VCN + subnet
- One VCN, one private subnet `10.0.0.0/24`
- Security list: ingress 443 from owner IP only; 1514-1515 intra-VCN only; 22 from owner IP

### 2. Launch instances
- `siem`: Ampere A1 shape, ~3 OCPU / 18 GB, Ubuntu 22.04 ARM
- `victim`: Ampere A1 shape, ~1 OCPU / 6 GB, Ubuntu 22.04 ARM

### 3. Bootstrap
```bash
# On siem instance
bash infra/bootstrap-siem.sh

# On victim instance
bash infra/bootstrap-victim.sh <siem-private-ip>
```

### 4. Verify
- Dashboard at `https://<siem-ip>` (or via SSH tunnel)
- Both agents appear green in Wazuh dashboard

## Known issues / workarounds
- Oracle "out of host capacity": retry across availability domains AD-1 / AD-2 / AD-3.
- Wazuh indexer OOM: tune JVM heap in bootstrap script (`-Xms4g -Xmx4g` for 18 GB host).
