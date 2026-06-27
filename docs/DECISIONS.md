# Architecture Decision Records

## ADR-001: Cloud-free lab substrate

**Date:** 2026-06-27
**Status:** Accepted

**Context:** This learning lab needs a real SIEM without paid infrastructure.

**Decision:** Oracle Cloud Always-Free Ampere (4 OCPU / 24 GB, ARM64), two instances in one VCN.

**Consequences:** x86-only tooling (Metasploitable2) won't run; Atomic Red Team (script-based) is used instead.

---

## ADR-002: Approach B (scripted lab, not Terraform IaC)

**Date:** 2026-06-27
**Status:** Accepted

**Context:** Terraform adds complexity for a solo learning project on a free tier.

**Decision:** Bootstrap scripts + documented runbook. Terraform deferred as a stretch goal.

---

## ADR-003: Native Wazuh rules (not Sigma)

**Date:** 2026-06-27
**Status:** Accepted

**Context:** Sigma engineering is a separate later project (#08).

**Decision:** This project authors native Wazuh XML rules only. No Sigma conversion in v1.

---

## ADR-004: CLI reads fixtures only (no live SIEM API)

**Date:** 2026-06-27
**Status:** Accepted

**Context:** The CLI must be fully testable offline (CI, no cloud).

**Decision:** `siem_ir` CLI reads exported `alerts.json` fixtures. It never calls the Wazuh API or reads live state.
