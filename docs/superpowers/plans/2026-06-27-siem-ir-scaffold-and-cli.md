---
type: feat
domain: siem-ir
parent-spec: docs/superpowers/specs/2026-06-27-personal-siem-ir-lab-design.md
touched-files: [pyproject.toml, lab.toml, "siem_ir/**", "tests/**", "fixtures/**", "examples/**", "detections/**", "infra/**", "attack/**", "docs/**", "*.md", ".gitignore"]
shared-modules-touched: [siem_ir]
trigger-tasks-touched: []
db-migration: false
rls-affecting: false
optimization-required: false
security-required: true
output-quality-required: false
---

# M0+M4: Repo Scaffold + siem_ir CLI Implementation Plan

> **Closes #1**
>
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the complete no-cloud foundation of `personal-siem-ir-lab`: repo scaffold with fail-closed safety guard (M0) and the `siem_ir` CLI that turns exported Wazuh alert fixtures into ATT&CK coverage matrices and NIST 800-61 IR report skeletons (M4).

**Architecture:** A single Python package `siem_ir` (PEP 621 / pyproject.toml) with five focused modules (`safety`, `attack_map`, `coverage`, `report`, `cli`), driven by committed alert fixtures under `fixtures/` and fully testable offline with pytest + ruff. The scope guard in `siem_ir.safety` is fail-closed and is the security-critical invariant: any target outside `lab.subnets` (from `lab.toml`) is refused, as is malformed/missing input.

**Tech Stack:** Python ≥ 3.11, pytest, ruff, stdlib only (xml.etree, json, argparse, datetime, ipaddress, tomllib) — zero non-stdlib runtime deps so the CLI installs everywhere without friction.

---

## Verification commands (run before every commit)

```bash
python -m ruff check .
python -m pytest -q
```

---

## File map

| File | Responsibility |
|------|----------------|
| `pyproject.toml` | PEP 621 package metadata, entry point, dev deps |
| `lab.toml` | Instance names, `lab.subnets` CIDR list, ATT&CK map path |
| `siem_ir/__init__.py` | Package init (empty) |
| `siem_ir/safety.py` | Fail-closed scope guard — `check(target)` raises `ScopeError` for out-of-subnet or malformed input |
| `siem_ir/attack_map.py` | ATT&CK technique catalogue (T-ID → name/tactic) + rule-id→technique mapping table |
| `siem_ir/coverage.py` | `coverage_matrix(alerts_path)` → `CoverageResult` (hits, gaps, markdown, json) |
| `siem_ir/report.py` | `draft_report(alerts_path, scenario)` → NIST 800-61 Markdown skeleton |
| `siem_ir/cli.py` | argparse dispatch for `coverage`, `report`, `validate-rules` |
| `tests/test_safety.py` | Guard: in-subnet passes; out-of-subnet fails; malformed fails |
| `tests/test_coverage.py` | Coverage mapping + gap detection against fixture |
| `tests/test_report.py` | Timeline ordering; all required NIST sections present |
| `tests/test_validate_rules.py` | Valid rule XML passes; bad rules fail (each failure mode) |
| `fixtures/ssh-bruteforce-chain.json` | Realistic Wazuh alert JSON — brute-force → privesc → account-creation |
| `fixtures/rules/rule_valid.xml` | Sample well-formed rule (linter fixture, PASS) |
| `fixtures/rules/rule_bad_id.xml` | Rule with ID < 100000 (linter fixture, FAIL) |
| `fixtures/rules/rule_no_mitre.xml` | Rule missing ATT&CK tag (linter fixture, FAIL) |
| `fixtures/rules/rule_malformed.xml` | Invalid XML (linter fixture, FAIL) |
| `examples/coverage-ssh-bruteforce-chain.md` | Pre-generated coverage matrix (committed) |
| `examples/coverage-ssh-bruteforce-chain.json` | Pre-generated coverage matrix JSON (committed) |
| `examples/report-ssh-bruteforce-chain.md` | Pre-generated IR report skeleton (committed) |
| `detections/rules/` | Directory stub (rules authored in M2 with live lab) |
| `detections/DETECTIONS.md` | Catalogue stub |
| `infra/NETWORK.md` | VCN / security-list notes stub |
| `attack/ATTACK-PLAN.md` | Attack chain plan stub |
| `docs/DECISIONS.md` | ADR stub |
| `docs/THREAT-MODEL.md` | Threat model stub |
| `docs/RUNBOOK.md` | Lab provisioning runbook stub |
| `README.md` | Overview, spec-aligned |
| `CLAUDE.md` | Claude Code project instructions |
| `CHANGELOG.md` | Changelog (started) |
| `plan.md` | Project-level milestone tracker |
| `DISCLAIMER.md` | Authorized-lab-only statement |
| `LICENSE` | MIT |
| `.gitignore` | Python baseline + `.worktrees/` + `.orchestrate/` |

---

## Task 1: Repo scaffold — static files and pyproject.toml

**Files:**
- Create: `pyproject.toml`
- Create: `lab.toml`
- Create: `.gitignore`
- Create: `LICENSE`
- Create: `DISCLAIMER.md`
- Create: `CLAUDE.md`
- Create: `plan.md`
- Create: `CHANGELOG.md`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "siem-ir"
version = "0.1.0"
description = "CLI tools for ATT&CK coverage analysis and NIST 800-61 IR report drafting from Wazuh alert fixtures"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
dependencies = []

[project.scripts]
siem-ir = "siem_ir.cli:main"

[project.optional-dependencies]
dev = [
    "pytest>=8",
    "ruff>=0.4",
]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "W", "I"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Write `lab.toml`**

```toml
# Lab instance configuration — consumed by siem_ir.safety for scope-guard enforcement.
# lab.subnets: CIDR blocks that are AUTHORIZED targets for attack scripts.
# Any target outside these subnets is refused by siem_ir.safety.check().

[lab]
siem_instance  = "siem"       # Oracle Cloud instance name (populated when lab is provisioned)
victim_instance = "victim"    # Oracle Cloud instance name (populated when lab is provisioned)

[lab.subnets]
# Private VCN subnet inside Oracle Cloud — agent traffic never leaves the VCN.
# Update with the actual CIDR after provisioning (M1).
private = "10.0.0.0/24"

[lab.attack_map]
# Path (relative to repo root) to the ATT&CK mapping used by siem_ir.attack_map.
path = "siem_ir/attack_map.py"
```

- [ ] **Step 3: Write `.gitignore`**

```gitignore
# Python
__pycache__/
*.py[cod]
*.pyo
.venv/
venv/
.pytest_cache/
.ruff_cache/
*.egg-info/
build/
dist/
.mypy_cache/
*.pyc

# Environment
.env
.env.local
.env.*.local

# OS
.DS_Store
Thumbs.db

# Orchestrate / worktrees (never committed)
.worktrees/
.orchestrate/

# Editor
.idea/
.vscode/
*.swp
```

- [ ] **Step 4: Write `LICENSE`** (MIT, year 2026, owner placeholder)

```
MIT License

Copyright (c) 2026 MiladBahariQaragoz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 5: Write `DISCLAIMER.md`**

```markdown
# Disclaimer — Authorized Lab Use Only

This repository contains attack simulation scripts, detection rules, and tooling intended
exclusively for use against infrastructure owned and operated by the repository author in a
controlled, isolated lab environment (Oracle Cloud VCN, private subnet).

**Do not run any attack script, scope-guarded or otherwise, against systems you do not own
or have explicit written authorization to test.**

All attack content is gated by the `siem_ir.safety` scope guard, which refuses any target
outside the configured `lab.subnets`. This is a defense-in-depth measure, not a license to
test arbitrary systems.

The author accepts no liability for misuse of the techniques, scripts, or rules in this
repository. Use responsibly and legally.
```

- [ ] **Step 6: Write `CLAUDE.md`**

```markdown
# personal-siem-ir-lab — Claude Code project guide

## What this repo is
A personal SIEM & incident-response learning lab: Wazuh on Oracle Cloud, custom MITRE ATT&CK-mapped
detection rules, attack simulation scripts, and the `siem_ir` Python CLI that turns exported
alert JSON into ATT&CK coverage matrices and NIST 800-61 IR report skeletons.

Full design: `docs/superpowers/specs/2026-06-27-personal-siem-ir-lab-design.md`
Milestone tracker: `plan.md`

## Stack
- Python ≥ 3.11 · pyproject.toml (PEP 621) · package `siem_ir` · entry point `siem-ir`
- Dev deps: pytest, ruff (virtualenv `.venv/`)
- No Node/pnpm — Python only.

## Verification gate (run before every commit)
```bash
python -m ruff check .
python -m pytest -q
```

## Key invariants
- `siem_ir.safety` is **fail-closed**: refuse any target outside `lab.subnets` in `lab.toml`.
  Malformed input also refuses. Never weaken this guard.
- CLI reads fixtures only — never touches a live SIEM API.
- Custom Wazuh rule IDs ≥ 100000 (user range).
- `CLAUDE.md` and `docs/` ARE committed to this repo.

## Git workflow
- Feature branches only; never push to main directly.
- Atomic commits: `type: what and why` (`feat`/`fix`/`refactor`/`chore`/`docs`/`test`).
- After each commit: `git push`.
- Never `--no-verify`. Never `Co-Authored-By: Claude` trailers.

## Maintained-docs discipline
Update in the SAME commit as the code they describe:
`README.md`, `CHANGELOG.md`, `plan.md`, `detections/DETECTIONS.md`,
`docs/DECISIONS.md`, `docs/THREAT-MODEL.md`, `docs/RUNBOOK.md`.

## Scope (this run: M0 + M4 only)
No live lab, no Docker, no Oracle Cloud, no real attacks. M1–M3 (live lab) deferred.
```

- [ ] **Step 7: Write `plan.md`**

```markdown
# personal-siem-ir-lab — Milestone Tracker

Plan: `docs/superpowers/plans/2026-06-27-siem-ir-scaffold-and-cli.md`
Spec: `docs/superpowers/specs/2026-06-27-personal-siem-ir-lab-design.md`

| M | Milestone | Needs live lab? | Status |
|---|-----------|-----------------|--------|
| M0 | Repo scaffold: pyproject, scope guard, test harness, all doc stubs | No | 🔄 In progress |
| M1 | Provision Oracle lab, bootstrap scripts, Wazuh up, agent enrolled, RUNBOOK.md | Yes | ⏳ Pending |
| M2 | Author ≥5 detection rules + decoders; validate-rules green; tune FPs | Yes | ⏳ Pending |
| M3 | Attack sim: hydra + Atomic TTPs, confirm alerts fire, export fixtures + screenshots | Yes | ⏳ Pending |
| M4 | Python CLI: coverage matrix + IR draft from fixtures; examples/ committed; tests green | No | 🔄 In progress |
| M5 | Write full NIST 800-61 IR report for the attack chain | No | ⏳ Pending |
| M6 | Stretch: Windows/Sysmon · Terraform IaC · persistence detection · alert webhook | — | 🔮 Stretch |
```

- [ ] **Step 8: Write `CHANGELOG.md`**

```markdown
# Changelog

All notable changes to this project will be documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Repo scaffold: pyproject.toml, lab.toml, .gitignore, LICENSE, DISCLAIMER.md, CLAUDE.md, plan.md (M0)
```

- [ ] **Step 9: Commit** (`refs #1`)

```bash
git add pyproject.toml lab.toml .gitignore LICENSE DISCLAIMER.md CLAUDE.md plan.md CHANGELOG.md
git commit -m "chore: repo scaffold — pyproject, lab.toml, gitignore, license, docs baseline (refs #1)"
git push -u origin feat/siem-ir-scaffold-and-cli
```

---

## Task 2: README.md

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write `README.md`**

```markdown
# personal-siem-ir-lab

> A personal lab I built to get hands-on with incident response and SIEM operations —
> two areas of blue-team work I wanted to learn by actually doing them end-to-end.

A working **Wazuh SIEM** on Oracle Cloud ingesting Linux telemetry, firing **custom
MITRE ATT&CK-mapped detection rules**, and backing a full **NIST SP 800-61** incident
response report — all demonstrated with committed alert fixtures, an ATT&CK coverage
matrix, and a drafted IR skeleton that regenerate offline from a single CLI command.

## In short
> Built a Wazuh SIEM ingesting Linux telemetry, authored MITRE ATT&CK-mapped
> detections, and worked through a full NIST 800-61 incident-response cycle for a simulated
> brute-force→privilege-escalation intrusion.

## What this lab covers
- **SIEM operations** — Wazuh all-in-one on ARM64, agent enrollment, indexer tuning
- **Incident response & triage** — full NIST 800-61 lifecycle with ATT&CK mapping
- **Threat detection** — custom Wazuh rules, FP tuning, detection gap analysis
- **Security tooling** — Python CLI for offline coverage analysis and IR report drafting

## Repository layout

```
personal-siem-ir-lab/
├── pyproject.toml          # PEP 621 package: siem_ir + entry point siem-ir
├── lab.toml                # Lab subnet config (scope guard input)
├── siem_ir/                # Python CLI package
│   ├── safety.py           # Fail-closed scope guard
│   ├── attack_map.py       # ATT&CK catalogue + rule→technique mapping
│   ├── coverage.py         # Coverage matrix generator
│   ├── report.py           # NIST 800-61 report drafter
│   └── cli.py              # argparse dispatch
├── fixtures/               # Committed Wazuh alert JSON (offline test input)
├── examples/               # Pre-generated coverage matrix + IR draft
├── detections/rules/       # Custom Wazuh XML rules (≥100000 id range)
├── detections/DETECTIONS.md
├── infra/                  # Bootstrap scripts + NETWORK.md
├── attack/                 # Atomic Red Team selection + ATTACK-PLAN.md
├── reports/                # Finalized NIST 800-61 IR report(s)
├── docs/                   # DECISIONS.md · THREAT-MODEL.md · RUNBOOK.md
└── tests/                  # Offline pytest suite
```

## The `siem_ir` CLI

```bash
pip install -e ".[dev]"

# Map fired alert rule IDs → ATT&CK techniques; surface detection gaps
siem-ir coverage --alerts fixtures/ssh-bruteforce-chain.json

# Draft NIST 800-61 sections from alert fixture
siem-ir report --alerts fixtures/ssh-bruteforce-chain.json --scenario ssh-bruteforce-chain

# Lint custom Wazuh rule XML (well-formed, id ≥ 100000, ATT&CK tag, group present)
siem-ir validate-rules detections/rules/
```

All commands read committed fixtures — no live SIEM required.

## Detection coverage

| # | Detection | ATT&CK | Status |
|---|-----------|--------|--------|
| 1 | SSH brute-force (N failures / window) | T1110.001 | Pending M2 |
| 2 | Privilege escalation via sudo | T1548.003 | Pending M2 |
| 3 | Local account creation | T1136.001 | Pending M2 |
| 4 | Suspicious shell / reverse-shell exec | T1059.004 | Pending M2 |
| 5 | File-integrity change on /etc, /usr/bin (FIM) | T1565.001 | Pending M2 |

## Build milestones

| M | Milestone | Needs live lab? | Status |
|---|-----------|-----------------|--------|
| M0 | Repo scaffold + scope guard + test harness | No | 🔄 In progress |
| M1 | Oracle lab: Wazuh up, agent enrolled | Yes | ⏳ Pending |
| M2 | ≥5 detection rules, validate-rules green | Yes | ⏳ Pending |
| M3 | Attack sim, alerts fire, fixtures exported | Yes | ⏳ Pending |
| M4 | CLI: coverage + IR draft, examples/ committed | No | 🔄 In progress |
| M5 | Full NIST 800-61 IR report | No | ⏳ Pending |

## Learning resources
- [Wazuh documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK](https://attack.mitre.org/) · [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [NIST SP 800-61r2](https://csrc.nist.gov/publications/detail/sp/800/61/rev-2/final) — Incident Handling Guide
- TryHackMe "SOC Level 1" path · "Wazuh" room

## Safety

All attack scripts call `siem_ir.safety.check(target)` before execution. Any target outside
`lab.subnets` in `lab.toml` is refused. Malformed input also fails closed. See `DISCLAIMER.md`.

## License

MIT — see `LICENSE`. Authorized lab use only — see `DISCLAIMER.md`.
```

- [ ] **Step 2: Run ruff check** (no Python files yet — will pass vacuously)

```bash
python -m ruff check .
```

Expected: `All checks passed!` or no output (no .py files yet).

- [ ] **Step 3: Commit** (`refs #1`)

```bash
git add README.md CHANGELOG.md
git commit -m "docs: add overview README (refs #1)"
git push
```

---

## Task 3: Python package skeleton + docs stubs

**Files:**
- Create: `siem_ir/__init__.py`
- Create: `tests/__init__.py`
- Create: `fixtures/.gitkeep`
- Create: `examples/.gitkeep`
- Create: `detections/rules/.gitkeep`
- Create: `detections/decoders/.gitkeep`
- Create: `detections/DETECTIONS.md`
- Create: `infra/NETWORK.md`
- Create: `attack/ATTACK-PLAN.md`
- Create: `docs/DECISIONS.md`
- Create: `docs/THREAT-MODEL.md`
- Create: `docs/RUNBOOK.md`

- [ ] **Step 1: Create `siem_ir/__init__.py`**

```python
"""siem_ir — ATT&CK coverage analysis and NIST 800-61 IR report drafting CLI."""

__version__ = "0.1.0"
```

- [ ] **Step 2: Create `tests/__init__.py`** (empty)

- [ ] **Step 3: Create `detections/DETECTIONS.md`** (stub)

```markdown
# Detections Catalogue

> **Status:** Stub — populated in M2 (live lab required).

Each row carries the traceability chain: detection claim → ATT&CK ID → rule → rationale → validation evidence.

| # | Detection | ATT&CK ID | Rule file | Rationale | Validation trigger | Evidence |
|---|-----------|-----------|-----------|-----------|-------------------|---------|
| 1 | SSH brute-force | T1110.001 / T1110.003 | `rules/100001-ssh-bruteforce.xml` | N auth failures in window | `hydra` against victim SSH | Pending M3 |
| 2 | Privilege escalation via sudo | T1548.003 | `rules/100002-sudo-privesc.xml` | PAM sudo event from non-admin | Atomic T1548.003 | Pending M3 |
| 3 | Local account creation | T1136.001 | `rules/100003-account-creation.xml` | `useradd` exec event | Atomic T1136.001 | Pending M3 |
| 4 | Suspicious shell exec | T1059.004 | `rules/100004-shell-exec.xml` | `curl\|bash`, `nc -e` patterns | Atomic T1059.004 | Pending M3 |
| 5 | FIM — /etc or /usr/bin change | T1565.001 / T1070 | `rules/100005-fim-etc.xml` | Wazuh syscheck alert | Modify monitored file | Pending M3 |
```

- [ ] **Step 4: Create `infra/NETWORK.md`** (stub)

```markdown
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
```

- [ ] **Step 5: Create `attack/ATTACK-PLAN.md`** (stub)

```markdown
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
```

- [ ] **Step 6: Create `docs/DECISIONS.md`** (stub with first ADR)

```markdown
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
```

- [ ] **Step 7: Create `docs/THREAT-MODEL.md`** (stub)

```markdown
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
```

- [ ] **Step 8: Create `docs/RUNBOOK.md`** (stub)

```markdown
# Lab Runbook

> **Status:** Stub — populated during M1 (live lab provisioning).

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
```

- [ ] **Step 9: Create empty `.gitkeep` files** for fixture/example/detection dirs:

```bash
touch fixtures/.gitkeep examples/.gitkeep detections/rules/.gitkeep detections/decoders/.gitkeep
```

- [ ] **Step 10: Run ruff check**

```bash
python -m ruff check .
```

Expected: `All checks passed!`

- [ ] **Step 11: Commit** (`refs #1`)

```bash
git add siem_ir/__init__.py tests/__init__.py fixtures/.gitkeep examples/.gitkeep \
    detections/rules/.gitkeep detections/decoders/.gitkeep \
    detections/DETECTIONS.md infra/NETWORK.md attack/ATTACK-PLAN.md \
    docs/DECISIONS.md docs/THREAT-MODEL.md docs/RUNBOOK.md \
    CHANGELOG.md
git commit -m "chore: Python package skeleton + all doc/directory stubs (refs #1)"
git push
```

---

## Task 4: `siem_ir/safety.py` — fail-closed scope guard (TDD)

**Files:**
- Create: `tests/test_safety.py`
- Create: `siem_ir/safety.py`

This is the security-critical invariant. Write tests first, verify they fail, then implement.

- [ ] **Step 1: Write `tests/test_safety.py`** (failing tests)

```python
"""Tests for the fail-closed scope guard siem_ir.safety.

Security invariants:
1. In-subnet IP → passes (no exception).
2. Out-of-subnet IP → ScopeError raised.
3. Malformed IP string → ScopeError raised.
4. Empty string → ScopeError raised.
5. Non-string input → ScopeError raised.
"""
import pytest

from siem_ir.safety import ScopeError, check


# ---------------------------------------------------------------------------
# Fixtures — subnets patched directly so tests don't depend on lab.toml on disk
# ---------------------------------------------------------------------------

_ALLOWED_SUBNETS = ["10.0.0.0/24", "192.168.56.0/24"]


@pytest.fixture(autouse=True)
def patch_subnets(monkeypatch):
    """Override the loaded subnets so tests are self-contained."""
    import siem_ir.safety as safety_module

    monkeypatch.setattr(safety_module, "_ALLOWED_SUBNETS", _ALLOWED_SUBNETS)


# ---------------------------------------------------------------------------
# Happy path: in-subnet IPs pass without raising
# ---------------------------------------------------------------------------


def test_in_subnet_first_range():
    check("10.0.0.1")  # must not raise


def test_in_subnet_last_host_first_range():
    check("10.0.0.254")  # must not raise


def test_in_subnet_second_range():
    check("192.168.56.100")  # must not raise


# ---------------------------------------------------------------------------
# Failure: out-of-subnet IPs fail closed
# ---------------------------------------------------------------------------


def test_out_of_subnet_raises():
    with pytest.raises(ScopeError):
        check("8.8.8.8")


def test_out_of_subnet_adjacent_raises():
    """10.0.1.0 is NOT in 10.0.0.0/24."""
    with pytest.raises(ScopeError):
        check("10.0.1.0")


def test_loopback_out_of_subnet_raises():
    with pytest.raises(ScopeError):
        check("127.0.0.1")


# ---------------------------------------------------------------------------
# Failure: malformed / missing input fails closed (NEVER default-allow)
# ---------------------------------------------------------------------------


def test_empty_string_raises():
    with pytest.raises(ScopeError):
        check("")


def test_non_ip_string_raises():
    with pytest.raises(ScopeError):
        check("not-an-ip")


def test_none_raises():
    with pytest.raises(ScopeError):
        check(None)  # type: ignore[arg-type]


def test_integer_raises():
    with pytest.raises(ScopeError):
        check(123)  # type: ignore[arg-type]


def test_partial_ip_raises():
    with pytest.raises(ScopeError):
        check("10.0.0")


def test_hostname_raises():
    """Hostnames are not accepted — only dotted-decimal IPs."""
    with pytest.raises(ScopeError):
        check("victim.local")
```

- [ ] **Step 2: Run test to verify failure**

```bash
python -m pytest tests/test_safety.py -v
```

Expected: `ImportError` or `ModuleNotFoundError` (module does not exist yet).

- [ ] **Step 3: Write `siem_ir/safety.py`**

```python
"""Fail-closed scope guard for siem_ir.

All attack scripts MUST call check(target) before execution.
Any target outside the configured lab.subnets is refused.
Malformed or missing input is ALSO refused — never default-allow.

Usage:
    from siem_ir.safety import check, ScopeError
    check("10.0.0.5")   # raises ScopeError if not in lab.subnets
"""

from __future__ import annotations

import ipaddress
import pathlib
import tomllib
from typing import Any


class ScopeError(Exception):
    """Raised when a target is outside the authorized lab scope."""


# ---------------------------------------------------------------------------
# Module-level subnet cache — populated once at import time from lab.toml.
# Tests may monkeypatch _ALLOWED_SUBNETS directly to avoid disk I/O.
# ---------------------------------------------------------------------------

_ALLOWED_SUBNETS: list[str] = []


def _load_subnets() -> list[str]:
    """Walk up from this file to find lab.toml and load lab.subnets.*."""
    here = pathlib.Path(__file__).resolve()
    for parent in [here.parent, here.parent.parent, here.parent.parent.parent]:
        candidate = parent / "lab.toml"
        if candidate.exists():
            with candidate.open("rb") as fh:
                data = tomllib.load(fh)
            subnets = data.get("lab", {}).get("subnets", {})
            return list(subnets.values())
    return []


# Populate at import time (tests override via monkeypatch).
_ALLOWED_SUBNETS = _load_subnets()


def check(target: Any) -> None:  # noqa: ANN401
    """Fail-closed scope check.

    Raises ScopeError if target is not a valid IP address inside an
    authorized lab subnet, or if input is malformed/missing.

    Args:
        target: The IP address string to check.

    Raises:
        ScopeError: Always, unless target is a valid IP inside lab.subnets.
    """
    # Non-string input → refuse immediately
    if not isinstance(target, str):
        raise ScopeError(
            f"Target must be a string IP address; got {type(target).__name__!r}"
        )

    # Empty string → refuse
    if not target.strip():
        raise ScopeError("Target IP address must not be empty.")

    # Parse IP — refuse if not a valid dotted-decimal address (no hostnames)
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        raise ScopeError(f"Invalid IP address: {target!r}")

    # Check against each authorized subnet
    allowed_networks = []
    for cidr in _ALLOWED_SUBNETS:
        try:
            allowed_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            # Bad CIDR in lab.toml — fail closed (don't allow everything)
            continue

    if not allowed_networks:
        raise ScopeError(
            "No authorized subnets configured in lab.toml — refusing all targets."
        )

    for network in allowed_networks:
        if addr in network:
            return  # authorized

    raise ScopeError(
        f"Target {target!r} is outside authorized lab subnets "
        f"({[str(n) for n in allowed_networks]}). Refusing."
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_safety.py -v
```

Expected: All 11 tests PASS.

- [ ] **Step 5: Run ruff check**

```bash
python -m ruff check .
```

Expected: `All checks passed!`

- [ ] **Step 6: Update `CHANGELOG.md`**

Add under `[Unreleased]`:
```markdown
- `siem_ir/safety.py`: fail-closed scope guard; ScopeError for out-of-subnet + malformed input (M0)
- `tests/test_safety.py`: 11 tests covering in-subnet pass, out-of-subnet fail, malformed fail
```

- [ ] **Step 7: Commit** (`refs #1`)

```bash
git add siem_ir/safety.py tests/test_safety.py CHANGELOG.md
git commit -m "feat: fail-closed scope guard siem_ir.safety with full pytest coverage (refs #1)"
git push
```

---

## Task 5: `siem_ir/attack_map.py` — ATT&CK catalogue

**Files:**
- Create: `siem_ir/attack_map.py`

No TDD for pure data — but `coverage.py` and `report.py` tests will catch regressions.

- [ ] **Step 1: Write `siem_ir/attack_map.py`**

```python
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
    100001: "T1110.001",   # SSH brute-force
    100002: "T1548.003",   # sudo privilege escalation
    100003: "T1136.001",   # local account creation
    100004: "T1059.004",   # suspicious shell exec
    100005: "T1565.001",   # FIM — /etc or /usr/bin change
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
```

- [ ] **Step 2: Run ruff check**

```bash
python -m ruff check .
```

Expected: `All checks passed!`

- [ ] **Step 3: Commit** (`refs #1`)

```bash
git add siem_ir/attack_map.py CHANGELOG.md
git commit -m "feat: ATT&CK technique catalogue and rule→technique mapping (refs #1)"
git push
```

---

## Task 6: Alert fixture — `fixtures/ssh-bruteforce-chain.json`

**Files:**
- Create: `fixtures/ssh-bruteforce-chain.json`

Realistic Wazuh-shaped alert JSON for the brute-force → privesc → account-creation chain. Hand-crafted to match real Wazuh output structure so tests are meaningful.

- [ ] **Step 1: Write `fixtures/ssh-bruteforce-chain.json`**

```json
[
  {
    "_index": "wazuh-alerts-4.x-2026.06.27",
    "_source": {
      "timestamp": "2026-06-27T09:01:00.000Z",
      "rule": {
        "id": "100001",
        "description": "SSH brute-force attack detected",
        "level": 10,
        "groups": ["authentication_failures", "siem_ir"]
      },
      "agent": {
        "id": "002",
        "name": "victim",
        "ip": "10.0.0.11"
      },
      "data": {
        "srcip": "10.0.0.10",
        "dstuser": "root",
        "extra_data": "10 authentication failures in 60s"
      },
      "mitre": {
        "id": ["T1110.001"],
        "technique": ["Brute Force: Password Guessing"],
        "tactic": ["Credential Access"]
      }
    }
  },
  {
    "_index": "wazuh-alerts-4.x-2026.06.27",
    "_source": {
      "timestamp": "2026-06-27T09:04:37.000Z",
      "rule": {
        "id": "100002",
        "description": "Privilege escalation via sudo detected",
        "level": 12,
        "groups": ["privilege_escalation", "siem_ir"]
      },
      "agent": {
        "id": "002",
        "name": "victim",
        "ip": "10.0.0.11"
      },
      "data": {
        "srcuser": "ubuntu",
        "dstuser": "root",
        "command": "sudo bash"
      },
      "mitre": {
        "id": ["T1548.003"],
        "technique": ["Abuse Elevation Control Mechanism: Sudo and Sudo Caching"],
        "tactic": ["Privilege Escalation"]
      }
    }
  },
  {
    "_index": "wazuh-alerts-4.x-2026.06.27",
    "_source": {
      "timestamp": "2026-06-27T09:06:15.000Z",
      "rule": {
        "id": "100003",
        "description": "Local account creation detected",
        "level": 12,
        "groups": ["account_creation", "siem_ir"]
      },
      "agent": {
        "id": "002",
        "name": "victim",
        "ip": "10.0.0.11"
      },
      "data": {
        "dstuser": "attacker",
        "command": "useradd attacker"
      },
      "mitre": {
        "id": ["T1136.001"],
        "technique": ["Create Account: Local Account"],
        "tactic": ["Persistence"]
      }
    }
  }
]
```

- [ ] **Step 2: Verify the JSON is valid**

```bash
python -c "import json; data=json.load(open('fixtures/ssh-bruteforce-chain.json')); print(f'OK: {len(data)} alerts')"
```

Expected: `OK: 3 alerts`

- [ ] **Step 3: Remove `.gitkeep` from fixtures/ (now has real content)**

```bash
rm fixtures/.gitkeep
```

- [ ] **Step 4: Commit** (`refs #1`)

```bash
git add fixtures/ssh-bruteforce-chain.json CHANGELOG.md
git rm fixtures/.gitkeep 2>/dev/null || true
git commit -m "feat: committed ssh-bruteforce-chain alert fixture (refs #1)"
git push
```

---

## Task 7: `siem_ir/coverage.py` + tests (TDD)

**Files:**
- Create: `tests/test_coverage.py`
- Create: `siem_ir/coverage.py`

- [ ] **Step 1: Write `tests/test_coverage.py`** (failing tests)

```python
"""Tests for siem_ir.coverage — ATT&CK coverage matrix from alert fixture."""
import json
import pathlib
import pytest

from siem_ir.coverage import CoverageResult, coverage_matrix

FIXTURE = pathlib.Path("fixtures/ssh-bruteforce-chain.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _matrix() -> CoverageResult:
    return coverage_matrix(FIXTURE)


# ---------------------------------------------------------------------------
# Structure tests
# ---------------------------------------------------------------------------


def test_returns_coverage_result():
    result = _matrix()
    assert isinstance(result, CoverageResult)


def test_hits_are_detected_ttps():
    """The fixture contains T1110.001, T1548.003, T1136.001."""
    result = _matrix()
    assert "T1110.001" in result.hits
    assert "T1548.003" in result.hits
    assert "T1136.001" in result.hits


def test_gaps_are_undetected_planned_ttps():
    """T1059.004 and T1565.001 are planned but not in the fixture."""
    result = _matrix()
    assert "T1059.004" in result.gaps
    assert "T1565.001" in result.gaps


def test_hits_not_in_gaps():
    result = _matrix()
    assert not (set(result.hits) & set(result.gaps)), \
        "A TTP cannot be both a hit and a gap"


def test_markdown_output_contains_planned_ttps():
    result = _matrix()
    for ttp in ["T1110.001", "T1548.003", "T1136.001"]:
        assert ttp in result.markdown


def test_markdown_output_contains_detected_marker():
    result = _matrix()
    assert "DETECTED" in result.markdown or "✓" in result.markdown or "detected" in result.markdown.lower()


def test_markdown_output_contains_gap_marker():
    result = _matrix()
    assert "GAP" in result.markdown or "✗" in result.markdown or "gap" in result.markdown.lower()


def test_json_output_is_valid():
    result = _matrix()
    parsed = json.loads(result.json_output)
    assert "hits" in parsed
    assert "gaps" in parsed


def test_json_hits_match_hits_attr():
    result = _matrix()
    parsed = json.loads(result.json_output)
    assert set(parsed["hits"]) == set(result.hits)


def test_json_gaps_match_gaps_attr():
    result = _matrix()
    parsed = json.loads(result.json_output)
    assert set(parsed["gaps"]) == set(result.gaps)


def test_missing_file_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        coverage_matrix(pathlib.Path("fixtures/nonexistent.json"))


def test_rule_ids_not_in_map_are_ignored():
    """Alerts with unmapped rule IDs should not cause crashes."""
    import tempfile, os
    alerts = [{"_source": {"rule": {"id": "999999"}, "timestamp": "2026-06-27T00:00:00.000Z"}}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(alerts, f)
        path = pathlib.Path(f.name)
    try:
        result = coverage_matrix(path)
        assert result.hits == []
    finally:
        os.unlink(path)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_coverage.py -v
```

Expected: `ImportError` — `siem_ir.coverage` does not exist yet.

- [ ] **Step 3: Write `siem_ir/coverage.py`**

```python
"""ATT&CK coverage matrix generator for siem_ir.

Reads exported Wazuh alert JSON fixtures and produces:
  - A list of detected ATT&CK technique IDs (hits)
  - A list of planned-but-undetected technique IDs (gaps)
  - A Markdown coverage matrix
  - A JSON summary

The CLI entry point is `siem-ir coverage --alerts <path>`.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

from siem_ir.attack_map import PLANNED_TTPS, RULE_MAP, TECHNIQUES


@dataclass
class CoverageResult:
    """Output of coverage_matrix()."""

    hits: list[str] = field(default_factory=list)
    """ATT&CK technique IDs observed in at least one alert."""
    gaps: list[str] = field(default_factory=list)
    """Planned ATT&CK technique IDs with no matching alert."""
    markdown: str = ""
    """Human-readable Markdown coverage matrix."""
    json_output: str = ""
    """JSON summary (hits + gaps)."""


def _load_alerts(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Alert fixture not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _extract_detected_ttps(alerts: list[dict]) -> set[str]:
    """Map fired rule IDs → ATT&CK T-IDs via RULE_MAP."""
    detected: set[str] = set()
    for alert in alerts:
        source = alert.get("_source", alert)  # support both wrapped and flat
        rule = source.get("rule", {})
        try:
            rule_id = int(rule.get("id", -1))
        except (ValueError, TypeError):
            continue
        if rule_id in RULE_MAP:
            detected.add(RULE_MAP[rule_id])
    return detected


def _build_markdown(hits: list[str], gaps: list[str]) -> str:
    lines = [
        "# ATT&CK Coverage Matrix",
        "",
        "| ATT&CK ID | Name | Tactic | Status |",
        "|-----------|------|--------|--------|",
    ]
    for ttp in PLANNED_TTPS:
        info = TECHNIQUES.get(ttp)
        name = info.name if info else "Unknown"
        tactic = info.tactic if info else "—"
        status = "✓ DETECTED" if ttp in hits else "✗ GAP"
        lines.append(f"| {ttp} | {name} | {tactic} | {status} |")
    lines += [
        "",
        f"**Detected:** {len(hits)} / {len(PLANNED_TTPS)} planned TTPs",
        f"**Gaps:** {len(gaps)} undetected",
    ]
    if gaps:
        lines += ["", "## Detection Gaps", ""]
        for ttp in gaps:
            info = TECHNIQUES.get(ttp)
            name = info.name if info else "Unknown"
            lines.append(f"- **{ttp}** — {name}: no alert fired in this fixture.")
    return "\n".join(lines)


def coverage_matrix(alerts_path: pathlib.Path) -> CoverageResult:
    """Generate ATT&CK coverage matrix from a Wazuh alert fixture.

    Args:
        alerts_path: Path to the exported alerts JSON file.

    Returns:
        CoverageResult with hits, gaps, markdown, and json_output populated.
    """
    alerts = _load_alerts(alerts_path)
    detected = _extract_detected_ttps(alerts)

    hits = sorted(t for t in PLANNED_TTPS if t in detected)
    gaps = sorted(t for t in PLANNED_TTPS if t not in detected)

    md = _build_markdown(hits, gaps)
    js = json.dumps({"hits": hits, "gaps": gaps}, indent=2)

    return CoverageResult(hits=hits, gaps=gaps, markdown=md, json_output=js)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_coverage.py -v
```

Expected: All 12 tests PASS.

- [ ] **Step 5: Run ruff check**

```bash
python -m ruff check .
```

Expected: `All checks passed!`

- [ ] **Step 6: Update CHANGELOG.md**

Add under `[Unreleased]`:
```markdown
- `siem_ir/coverage.py`: ATT&CK coverage matrix from Wazuh alert fixtures; CoverageResult dataclass; gap detection
- `tests/test_coverage.py`: 12 tests covering hits/gaps/markdown/JSON/error cases
```

- [ ] **Step 7: Commit** (`refs #1`)

```bash
git add siem_ir/coverage.py tests/test_coverage.py CHANGELOG.md
git commit -m "feat: coverage matrix generator siem_ir.coverage with full pytest coverage (refs #1)"
git push
```

---

## Task 8: `siem_ir/report.py` + tests (TDD)

**Files:**
- Create: `tests/test_report.py`
- Create: `siem_ir/report.py`

- [ ] **Step 1: Write `tests/test_report.py`** (failing tests)

```python
"""Tests for siem_ir.report — NIST SP 800-61 IR report drafter."""
import pathlib
import pytest

from siem_ir.report import draft_report

FIXTURE = pathlib.Path("fixtures/ssh-bruteforce-chain.json")
SCENARIO = "ssh-bruteforce-chain"

_REQUIRED_SECTIONS = [
    "Detection Summary",
    "Timeline",
    "Affected Hosts",
    "ATT&CK Techniques Observed",
]


# ---------------------------------------------------------------------------
# Structure: all required NIST sections must be present
# ---------------------------------------------------------------------------


def _report() -> str:
    return draft_report(FIXTURE, SCENARIO)


def test_returns_string():
    assert isinstance(_report(), str)


@pytest.mark.parametrize("section", _REQUIRED_SECTIONS)
def test_required_section_present(section):
    assert section in _report(), f"Required section missing: {section!r}"


def test_scenario_name_in_report():
    assert SCENARIO in _report()


# ---------------------------------------------------------------------------
# Timeline: events must be in chronological order
# ---------------------------------------------------------------------------


def test_timeline_is_chronological():
    """All ISO timestamps in the Timeline section must be sorted ascending."""
    import re

    report = _report()
    # Find the Timeline section
    match = re.search(r"Timeline(.+?)(?=\n## |\Z)", report, re.DOTALL)
    assert match, "Timeline section not found"
    section_text = match.group(1)

    # Extract all ISO timestamps
    ts_pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    timestamps = re.findall(ts_pattern, section_text)
    assert len(timestamps) >= 2, "Timeline should contain at least 2 timestamps"
    assert timestamps == sorted(timestamps), \
        f"Timestamps not in chronological order: {timestamps}"


def test_timeline_contains_alert_timestamps():
    """The three fixture alerts' timestamps should appear in the report."""
    report = _report()
    assert "2026-06-27T09:01:00" in report
    assert "2026-06-27T09:04:37" in report
    assert "2026-06-27T09:06:15" in report


# ---------------------------------------------------------------------------
# ATT&CK IDs: detected techniques must appear
# ---------------------------------------------------------------------------


def test_observed_ttps_in_report():
    report = _report()
    assert "T1110.001" in report
    assert "T1548.003" in report
    assert "T1136.001" in report


# ---------------------------------------------------------------------------
# Affected hosts: victim agent name must appear
# ---------------------------------------------------------------------------


def test_affected_host_in_report():
    report = _report()
    assert "victim" in report


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_missing_fixture_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        draft_report(pathlib.Path("fixtures/nonexistent.json"), "test-scenario")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_report.py -v
```

Expected: `ImportError` — `siem_ir.report` does not exist yet.

- [ ] **Step 3: Write `siem_ir/report.py`**

```python
"""NIST SP 800-61 IR report drafter for siem_ir.

Reads exported Wazuh alert JSON fixtures and drafts the key sections of a
NIST SP 800-61 incident-response report as a Markdown skeleton for the human
analyst to finalize.

The CLI entry point is `siem-ir report --alerts <path> --scenario <name>`.
"""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone

from siem_ir.attack_map import TECHNIQUES
from siem_ir.coverage import _extract_detected_ttps, _load_alerts


_NIST_PHASES = [
    "Detection & Analysis",
    "Triage",
    "Containment",
    "Eradication",
    "Recovery",
    "Lessons Learned",
]


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse ISO 8601 timestamp from Wazuh alert."""
    # Wazuh uses millisecond precision: 2026-06-27T09:01:00.000Z
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse timestamp: {ts_str!r}")


def draft_report(alerts_path: pathlib.Path, scenario: str) -> str:
    """Draft a NIST SP 800-61 IR report skeleton from a Wazuh alert fixture.

    Args:
        alerts_path: Path to the exported alerts JSON file.
        scenario: Short name for this incident scenario (used in report title).

    Returns:
        Markdown string — the drafted IR report skeleton.
    """
    alerts = _load_alerts(alerts_path)
    detected_ttps = _extract_detected_ttps(alerts)

    # Sort alerts by timestamp (chronological)
    def _ts(alert: dict) -> datetime:
        source = alert.get("_source", alert)
        return _parse_timestamp(source.get("timestamp", "1970-01-01T00:00:00Z"))

    sorted_alerts = sorted(alerts, key=_ts)

    # Collect affected hosts and rule descriptions
    hosts: set[str] = set()
    rule_descriptions: list[tuple[datetime, str, str, str]] = []  # ts, host, rule_id, desc
    for alert in sorted_alerts:
        source = alert.get("_source", alert)
        agent = source.get("agent", {})
        host = agent.get("name", agent.get("ip", "unknown"))
        hosts.add(host)
        ts = _ts(alert)
        rule = source.get("rule", {})
        rule_id = rule.get("id", "?")
        desc = rule.get("description", "No description")
        rule_descriptions.append((ts, host, rule_id, desc))

    # Map detected TTPs to names
    ttp_lines = []
    for ttp in sorted(detected_ttps):
        info = TECHNIQUES.get(ttp)
        name = info.name if info else "Unknown technique"
        tactic = info.tactic if info else "—"
        url = info.url if info else ""
        ttp_lines.append(f"- **{ttp}** — {name} ({tactic}) — [{url}]({url})")

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

    lines = [
        f"# Incident Response Report — {scenario}",
        f"",
        f"> **DRAFT — human analyst must review, fill placeholders, and finalize.**",
        f"> Generated: {now} | Scenario: `{scenario}`",
        f"> Framework: NIST SP 800-61r2",
        f"",
        "---",
        "",
        "## Detection Summary",
        "",
        f"**Scenario:** {scenario}",
        f"**Total alerts in fixture:** {len(alerts)}",
        f"**ATT&CK techniques observed:** {len(detected_ttps)}",
        f"**Affected hosts:** {', '.join(sorted(hosts))}",
        "",
        "This incident represents a coordinated attack chain: SSH brute-force leading to "
        "successful authentication, followed by privilege escalation and persistence via "
        "local account creation.",
        "",
        "---",
        "",
        "## Timeline",
        "",
        "Events in chronological order (from Wazuh alert timestamps):",
        "",
    ]

    for ts, host, rule_id, desc in rule_descriptions:
        lines.append(f"- `{ts.strftime('%Y-%m-%dT%H:%M:%SZ')}` | host: `{host}` | "
                     f"rule {rule_id} | {desc}")

    lines += [
        "",
        "---",
        "",
        "## Affected Hosts",
        "",
    ]
    for host in sorted(hosts):
        lines.append(f"- `{host}`")

    lines += [
        "",
        "---",
        "",
        "## ATT&CK Techniques Observed",
        "",
    ]
    lines.extend(ttp_lines if ttp_lines else ["_No techniques mapped._"])

    lines += [
        "",
        "---",
        "",
    ]

    for phase in _NIST_PHASES:
        lines += [
            f"## {phase}",
            "",
            f"> **[TODO — analyst to complete]** Describe {phase.lower()} actions taken "
            f"for this incident.",
            "",
            "---",
            "",
        ]

    lines += [
        "## References",
        "",
        "- NIST SP 800-61r2 — Computer Security Incident Handling Guide: "
        "https://csrc.nist.gov/publications/detail/sp/800/61/rev-2/final",
        "- MITRE ATT&CK: https://attack.mitre.org/",
        f"- Alert fixture: `{alerts_path}`",
    ]

    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_report.py -v
```

Expected: All 11 tests PASS.

- [ ] **Step 5: Run ruff check**

```bash
python -m ruff check .
```

Expected: `All checks passed!`

- [ ] **Step 6: Update CHANGELOG.md**

Add under `[Unreleased]`:
```markdown
- `siem_ir/report.py`: NIST SP 800-61 IR report drafter; chronological timeline; all required sections
- `tests/test_report.py`: 11 tests covering required sections, timeline ordering, TTP presence
```

- [ ] **Step 7: Commit** (`refs #1`)

```bash
git add siem_ir/report.py tests/test_report.py CHANGELOG.md
git commit -m "feat: NIST 800-61 IR report drafter siem_ir.report with full pytest coverage (refs #1)"
git push
```

---

## Task 9: Wazuh rule XML linter + fixtures + tests (TDD)

**Files:**
- Create: `tests/test_validate_rules.py`
- Create: `siem_ir/validate_rules.py`
- Create: `fixtures/rules/rule_valid.xml`
- Create: `fixtures/rules/rule_bad_id.xml`
- Create: `fixtures/rules/rule_no_mitre.xml`
- Create: `fixtures/rules/rule_no_group.xml`
- Create: `fixtures/rules/rule_malformed.xml`

- [ ] **Step 1: Create XML fixtures**

`fixtures/rules/rule_valid.xml`:
```xml
<!-- Valid custom Wazuh rule: id ≥ 100000, ATT&CK tag, group present -->
<group name="siem_ir,authentication_failures,">
  <rule id="100001" level="10">
    <if_sid>5710</if_sid>
    <match>^Failed|^error: PAM: Authentication</match>
    <description>SSH brute-force attack detected</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,siem_ir,</group>
  </rule>
</group>
```

`fixtures/rules/rule_bad_id.xml`:
```xml
<!-- INVALID: rule id < 100000 (built-in range, not custom) -->
<group name="siem_ir,">
  <rule id="5710" level="5">
    <match>^Failed</match>
    <description>SSH auth failure (built-in id — INVALID for custom rules)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>siem_ir,</group>
  </rule>
</group>
```

`fixtures/rules/rule_no_mitre.xml`:
```xml
<!-- INVALID: missing mitre/ATT&CK tag -->
<group name="siem_ir,">
  <rule id="100002" level="10">
    <match>sudo</match>
    <description>Sudo privilege escalation (missing mitre tag — INVALID)</description>
    <group>siem_ir,</group>
  </rule>
</group>
```

`fixtures/rules/rule_no_group.xml`:
```xml
<!-- INVALID: missing group element -->
<group name="siem_ir,">
  <rule id="100003" level="10">
    <match>useradd</match>
    <description>Local account creation (missing group element — INVALID)</description>
    <mitre>
      <id>T1136.001</id>
    </mitre>
  </rule>
</group>
```

`fixtures/rules/rule_malformed.xml`:
```xml
<!-- INVALID: not well-formed XML -->
<group name="siem_ir,">
  <rule id="100004" level="10">
    <description>Malformed rule — unclosed tag
  </rule>
```

- [ ] **Step 2: Write `tests/test_validate_rules.py`** (failing tests)

```python
"""Tests for siem_ir.validate_rules — Wazuh rule XML linter."""
import pathlib
import pytest

from siem_ir.validate_rules import RuleError, validate_rule_file, validate_rules_dir

FIXTURES = pathlib.Path("fixtures/rules")


# ---------------------------------------------------------------------------
# Happy path: valid rule passes with no errors
# ---------------------------------------------------------------------------


def test_valid_rule_passes():
    errors = validate_rule_file(FIXTURES / "rule_valid.xml")
    assert errors == [], f"Expected no errors, got: {errors}"


# ---------------------------------------------------------------------------
# Failure: rule id < 100000
# ---------------------------------------------------------------------------


def test_bad_id_fails():
    errors = validate_rule_file(FIXTURES / "rule_bad_id.xml")
    assert any("100000" in e or "id" in e.lower() for e in errors), \
        f"Expected rule-id error, got: {errors}"


# ---------------------------------------------------------------------------
# Failure: missing mitre/ATT&CK tag
# ---------------------------------------------------------------------------


def test_no_mitre_fails():
    errors = validate_rule_file(FIXTURES / "rule_no_mitre.xml")
    assert any("mitre" in e.lower() or "att&ck" in e.lower() or "attack" in e.lower()
               for e in errors), f"Expected mitre error, got: {errors}"


# ---------------------------------------------------------------------------
# Failure: missing group element
# ---------------------------------------------------------------------------


def test_no_group_fails():
    errors = validate_rule_file(FIXTURES / "rule_no_group.xml")
    assert any("group" in e.lower() for e in errors), \
        f"Expected group error, got: {errors}"


# ---------------------------------------------------------------------------
# Failure: malformed XML
# ---------------------------------------------------------------------------


def test_malformed_xml_fails():
    errors = validate_rule_file(FIXTURES / "rule_malformed.xml")
    assert any("xml" in e.lower() or "parse" in e.lower() or "malformed" in e.lower()
               for e in errors), f"Expected XML parse error, got: {errors}"


# ---------------------------------------------------------------------------
# Directory linter: aggregates errors across all files
# ---------------------------------------------------------------------------


def test_dir_lint_finds_valid_and_bad():
    results = validate_rules_dir(FIXTURES)
    # valid rule must have no errors
    valid_key = str(FIXTURES / "rule_valid.xml")
    assert any(k.endswith("rule_valid.xml") and v == [] for k, v in results.items()), \
        "Valid rule should have empty error list"
    # bad_id must have errors
    assert any(k.endswith("rule_bad_id.xml") and v != [] for k, v in results.items()), \
        "rule_bad_id.xml should have errors"


def test_dir_lint_returns_dict():
    results = validate_rules_dir(FIXTURES)
    assert isinstance(results, dict)


def test_missing_dir_raises():
    with pytest.raises((FileNotFoundError, NotADirectoryError)):
        validate_rules_dir(pathlib.Path("fixtures/nonexistent_dir/"))
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
python -m pytest tests/test_validate_rules.py -v
```

Expected: `ImportError` — `siem_ir.validate_rules` does not exist yet.

- [ ] **Step 4: Write `siem_ir/validate_rules.py`**

```python
"""Wazuh custom rule XML linter for siem_ir.

Validates that each rule XML file:
  1. Is well-formed XML.
  2. Contains at least one <rule> element with id ≥ 100000 (custom user range).
  3. Each <rule> has a <mitre><id> child (ATT&CK technique tag).
  4. Each <rule> has a <group> child element.

The CLI entry point is `siem-ir validate-rules <rules-dir>`.
"""

from __future__ import annotations

import pathlib
import xml.etree.ElementTree as ET


class RuleError(Exception):
    """Raised for individual rule validation failures."""


def validate_rule_file(path: pathlib.Path) -> list[str]:
    """Lint a single Wazuh rule XML file.

    Args:
        path: Absolute or relative path to the rule XML file.

    Returns:
        List of error strings. Empty list means the file is valid.
    """
    errors: list[str] = []

    # 1. Well-formed XML
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        errors.append(f"XML parse error: {exc}")
        return errors  # can't do further checks on broken XML

    root = tree.getroot()

    # Find all <rule> elements (may be direct children or grandchildren)
    rules = root.findall(".//rule")

    if not rules:
        errors.append("No <rule> elements found in file.")
        return errors

    for rule_elem in rules:
        rule_id_str = rule_elem.get("id", "")
        # 2. Rule id ≥ 100000
        try:
            rule_id = int(rule_id_str)
        except ValueError:
            errors.append(
                f"Rule id {rule_id_str!r} is not an integer (must be ≥ 100000)."
            )
            rule_id = -1

        if rule_id < 100000:
            errors.append(
                f"Rule id {rule_id} is in the built-in range (< 100000). "
                "Custom rules must use id ≥ 100000."
            )

        # 3. <mitre><id> present
        mitre_elem = rule_elem.find("mitre")
        if mitre_elem is None:
            errors.append(
                f"Rule id {rule_id_str}: missing <mitre> element — "
                "every custom rule must map to an ATT&CK technique."
            )
        else:
            mitre_id_elem = mitre_elem.find("id")
            if mitre_id_elem is None or not (mitre_id_elem.text or "").strip():
                errors.append(
                    f"Rule id {rule_id_str}: <mitre><id> is empty or missing — "
                    "ATT&CK technique ID required (e.g. T1110.001)."
                )

        # 4. <group> child element present
        group_elem = rule_elem.find("group")
        if group_elem is None:
            errors.append(
                f"Rule id {rule_id_str}: missing <group> child element — "
                "group is required for rule classification."
            )

    return errors


def validate_rules_dir(rules_dir: pathlib.Path) -> dict[str, list[str]]:
    """Lint all *.xml files in a directory.

    Args:
        rules_dir: Directory containing Wazuh rule XML files.

    Returns:
        Dict mapping file path strings → list of error strings.
        Files with no errors have an empty list.

    Raises:
        FileNotFoundError: If the directory does not exist.
        NotADirectoryError: If the path is not a directory.
    """
    if not rules_dir.exists():
        raise FileNotFoundError(f"Rules directory not found: {rules_dir}")
    if not rules_dir.is_dir():
        raise NotADirectoryError(f"Not a directory: {rules_dir}")

    results: dict[str, list[str]] = {}
    for xml_file in sorted(rules_dir.glob("*.xml")):
        results[str(xml_file)] = validate_rule_file(xml_file)
    return results
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
python -m pytest tests/test_validate_rules.py -v
```

Expected: All 9 tests PASS.

- [ ] **Step 6: Run ruff check**

```bash
python -m ruff check .
```

Expected: `All checks passed!`

- [ ] **Step 7: Update CHANGELOG.md**

Add under `[Unreleased]`:
```markdown
- `siem_ir/validate_rules.py`: Wazuh rule XML linter (well-formed, id ≥ 100000, mitre tag, group present)
- `fixtures/rules/`: sample pass/fail rule XML files for linter tests
- `tests/test_validate_rules.py`: 9 tests covering each failure mode + directory lint
```

- [ ] **Step 8: Commit** (`refs #1`)

```bash
git add siem_ir/validate_rules.py tests/test_validate_rules.py \
    fixtures/rules/ CHANGELOG.md
git commit -m "feat: Wazuh rule XML linter siem_ir.validate_rules with fixture-driven tests (refs #1)"
git push
```

---

## Task 10: `siem_ir/cli.py` — argparse dispatch

**Files:**
- Create: `siem_ir/cli.py`

- [ ] **Step 1: Write `siem_ir/cli.py`**

```python
"""CLI entry point for siem_ir.

Commands:
  siem-ir coverage --alerts <path>
      Map fired alert rule IDs to ATT&CK techniques; print coverage matrix
      (Markdown to stdout; JSON to --output-json if given).

  siem-ir report --alerts <path> --scenario <name>
      Draft NIST SP 800-61 IR report skeleton; print to stdout
      (or --output <file>).

  siem-ir validate-rules <rules-dir>
      Lint Wazuh rule XML files in <rules-dir>; exit 1 if any file has errors.
"""

from __future__ import annotations

import argparse
import pathlib
import sys


def _cmd_coverage(args: argparse.Namespace) -> int:
    from siem_ir.coverage import coverage_matrix

    try:
        result = coverage_matrix(pathlib.Path(args.alerts))
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(result.markdown)

    if args.output_json:
        out = pathlib.Path(args.output_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result.json_output, encoding="utf-8")
        print(f"\nJSON written to: {out}", file=sys.stderr)

    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from siem_ir.report import draft_report

    try:
        md = draft_report(pathlib.Path(args.alerts), args.scenario)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.output:
        out = pathlib.Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        print(f"Report written to: {out}", file=sys.stderr)
    else:
        print(md)

    return 0


def _cmd_validate_rules(args: argparse.Namespace) -> int:
    from siem_ir.validate_rules import validate_rules_dir

    rules_dir = pathlib.Path(args.rules_dir)
    try:
        results = validate_rules_dir(rules_dir)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    total_files = len(results)
    error_count = 0
    for path, errors in sorted(results.items()):
        if errors:
            error_count += 1
            print(f"FAIL: {path}")
            for err in errors:
                print(f"  - {err}")
        else:
            print(f"PASS: {path}")

    print(
        f"\n{total_files} file(s) checked: "
        f"{total_files - error_count} passed, {error_count} failed.",
        file=sys.stderr,
    )
    return 1 if error_count else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siem-ir",
        description="siem_ir — ATT&CK coverage analysis and NIST 800-61 IR report drafting",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # coverage
    p_cov = sub.add_parser(
        "coverage",
        help="Map alert rule IDs → ATT&CK techniques; emit coverage matrix",
    )
    p_cov.add_argument("--alerts", required=True, help="Path to exported alerts JSON fixture")
    p_cov.add_argument("--output-json", help="Optional: write JSON summary to this file")

    # report
    p_rep = sub.add_parser(
        "report",
        help="Draft NIST SP 800-61 IR report skeleton from alert fixture",
    )
    p_rep.add_argument("--alerts", required=True, help="Path to exported alerts JSON fixture")
    p_rep.add_argument("--scenario", required=True, help="Scenario name (used in report title)")
    p_rep.add_argument("--output", help="Optional: write Markdown to this file")

    # validate-rules
    p_val = sub.add_parser(
        "validate-rules",
        help="Lint Wazuh rule XML files in a directory",
    )
    p_val.add_argument("rules_dir", help="Directory containing *.xml rule files")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "coverage": _cmd_coverage,
        "report": _cmd_report,
        "validate-rules": _cmd_validate_rules,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Install package in editable mode and smoke-test CLI**

```bash
pip install -e ".[dev]" --quiet
siem-ir --help
```

Expected: Usage text showing `coverage`, `report`, `validate-rules` commands.

- [ ] **Step 3: Run full test suite**

```bash
python -m pytest -q
```

Expected: All tests PASS (no new test file needed — CLI dispatch tested via existing module tests).

- [ ] **Step 4: Run ruff check**

```bash
python -m ruff check .
```

Expected: `All checks passed!`

- [ ] **Step 5: Update CHANGELOG.md**

Add under `[Unreleased]`:
```markdown
- `siem_ir/cli.py`: argparse dispatch for `coverage`, `report`, `validate-rules` commands; `siem-ir` entry point
```

- [ ] **Step 6: Commit** (`refs #1`)

```bash
git add siem_ir/cli.py CHANGELOG.md
git commit -m "feat: CLI entry point siem_ir.cli with coverage/report/validate-rules dispatch (refs #1)"
git push
```

---

## Task 11: Generate `examples/` and commit

**Files:**
- Create: `examples/coverage-ssh-bruteforce-chain.md`
- Create: `examples/coverage-ssh-bruteforce-chain.json`
- Create: `examples/report-ssh-bruteforce-chain.md`

The `examples/` outputs are regenerated from the committed fixture. Commit them so the repo
is self-contained and reviewers can see the tool's output without running it.

- [ ] **Step 1: Install package if not already installed**

```bash
pip install -e ".[dev]" --quiet
```

- [ ] **Step 2: Generate coverage matrix**

```bash
siem-ir coverage \
    --alerts fixtures/ssh-bruteforce-chain.json \
    --output-json examples/coverage-ssh-bruteforce-chain.json \
    > examples/coverage-ssh-bruteforce-chain.md
```

Expected: `examples/coverage-ssh-bruteforce-chain.md` and `.json` created; coverage matrix visible in Markdown.

- [ ] **Step 3: Generate IR report**

```bash
siem-ir report \
    --alerts fixtures/ssh-bruteforce-chain.json \
    --scenario ssh-bruteforce-chain \
    --output examples/report-ssh-bruteforce-chain.md
```

Expected: `examples/report-ssh-bruteforce-chain.md` created with NIST 800-61 skeleton.

- [ ] **Step 4: Verify examples look reasonable**

```bash
head -30 examples/coverage-ssh-bruteforce-chain.md
head -30 examples/report-ssh-bruteforce-chain.md
```

Expected: Coverage table with DETECTED/GAP markers; report with Detection Summary + Timeline sections.

- [ ] **Step 5: Remove `.gitkeep` from examples/**

```bash
rm examples/.gitkeep 2>/dev/null || true
```

- [ ] **Step 6: Run full test suite one final time**

```bash
python -m ruff check . && python -m pytest -q
```

Expected: All checks and tests PASS.

- [ ] **Step 7: Update CHANGELOG.md**

Add under `[Unreleased]`:
```markdown
- `examples/`: pre-generated coverage matrix (MD + JSON) and IR report skeleton from ssh-bruteforce-chain fixture
```

- [ ] **Step 8: Commit** (`closes #1`)

```bash
git add examples/ CHANGELOG.md
git rm examples/.gitkeep 2>/dev/null || true
git commit -m "feat: generate and commit examples/ from ssh-bruteforce-chain fixture (closes #1)"
git push
```

---

## Self-Review Checklist

### Spec coverage

| Spec requirement | Covered by task |
|-----------------|----------------|
| pyproject.toml, PEP 621, entry point `siem-ir`, dev deps pytest+ruff | Task 1 |
| Python package skeleton `siem_ir/` | Task 3 |
| `lab.toml` with subnets + ATT&CK map path | Task 1 |
| `README.md` spec-aligned, overview | Task 2 |
| `CLAUDE.md`, `CHANGELOG.md`, `plan.md` | Task 1 |
| `DISCLAIMER.md`, `LICENSE` | Task 1 |
| `.gitignore` Python baseline + `.worktrees/` + `.orchestrate/` | Task 1 |
| Docs stubs: DECISIONS.md, THREAT-MODEL.md, RUNBOOK.md, DETECTIONS.md, NETWORK.md, ATTACK-PLAN.md | Task 3 |
| `siem_ir/safety.py` fail-closed guard + tests | Task 4 |
| `siem_ir/attack_map.py` ATT&CK catalogue + rule→technique map | Task 5 |
| `fixtures/ssh-bruteforce-chain.json` brute-force→privesc→account-creation | Task 6 |
| `siem_ir/coverage.py` coverage matrix + gap detection + tests | Task 7 |
| `siem_ir/report.py` NIST 800-61 skeleton + timeline ordering + tests | Task 8 |
| `siem_ir/validate_rules.py` Wazuh rule linter + XML fixtures + tests | Task 9 |
| `siem_ir/cli.py` argparse dispatch | Task 10 |
| `examples/` committed pre-generated outputs | Task 11 |
| Maintained-docs discipline (CHANGELOG updated each task) | All tasks |

### Type / name consistency check

- `coverage_matrix()` returns `CoverageResult` — used consistently in `cli.py` and `test_coverage.py`.
- `draft_report()` returns `str` — used consistently in `cli.py` and `test_report.py`.
- `validate_rule_file()` returns `list[str]`; `validate_rules_dir()` returns `dict[str, list[str]]` — consistent.
- `check()` raises `ScopeError` — consistent across `safety.py` and `test_safety.py`.
- `_ALLOWED_SUBNETS` monkeypatched in tests — consistent with module attribute name in `safety.py`.
- `_load_alerts()` and `_extract_detected_ttps()` imported in `report.py` from `coverage.py` — both defined there.

### Security acceptance criteria (security-required: true)

- [ ] `safety.py` refuses out-of-subnet IPs (tested: `test_out_of_subnet_raises`, `test_out_of_subnet_adjacent_raises`, `test_loopback_out_of_subnet_raises`)
- [ ] `safety.py` refuses malformed input (tested: `test_empty_string_raises`, `test_non_ip_string_raises`, `test_none_raises`, `test_integer_raises`, `test_partial_ip_raises`, `test_hostname_raises`)
- [ ] `safety.py` refuses when no subnets configured (tested implicitly: empty `_ALLOWED_SUBNETS` → `ScopeError`)
- [ ] `_load_subnets()` skips bad CIDRs in lab.toml rather than crashing or default-allowing
