# Design — Personal SIEM & Incident Response Lab (`personal-siem-ir-lab`)

- **Date:** 2026-06-27
- **Status:** Approved (brainstorming)
- **Project:** 03 of the Sec-CV portfolio (own git repo → GitHub `personal-siem-ir-lab`)
- **Sibling projects:** 01 `linux-hardening-auditor`, 02 `netrecon` (network recon/vuln scanner)
- **Estimated effort:** 3–4 weeks (per portfolio README)

## 1. Summary

A working **Wazuh SIEM** running on a free cloud lab that ingests Linux telemetry, fires
custom detection rules mapped to **MITRE ATT&CK**, and supports a full written incident
response report following **NIST SP 800-61**. The committed repository centres on the
*security content* — detection rules, attack→evidence pipeline, and the IR report — plus a
small, testable Python CLI (`siem_ir`) that turns exported alerts into an ATT&CK coverage
matrix and a drafted IR report skeleton.

The CV signal this fills (from the portfolio analysis): **Incident Response (39% of jobs)**
and **SIEM tooling (16%)** — i.e. "I stood up a SIEM, tuned detections, and handled an
incident," demonstrated with verifiable artifacts.

## 2. Goal & non-goals

**Goal.** Produce a public, reproducible repository proving hands-on SIEM operations and the
full IR lifecycle, backed by real evidence (firing alerts + screenshots + timeline) and
replayable offline artifacts (committed alert fixtures → coverage matrix → IR draft).

**Non-goals (YAGNI / scope guards).**
- Not a heavy automation orchestrator that scripts around the hands-on SOC work — the
  hands-on operation *is* the deliverable.
- Not a Sigma rule-engineering platform — that is a separate later project (08
  `detection-engineering-sigma`). This project authors **native Wazuh rules** only.
- Not multi-cloud / production-grade IaC in v1 — provisioning is a documented, scripted
  runbook (Approach B), with Terraform deferred to a stretch goal.
- No Windows host in v1 (Oracle free tier is Linux/ARM only) — Windows/Sysmon onboarding is
  a documented stretch goal.

## 3. Decisions locked during brainstorming

| # | Decision | Choice |
|---|----------|--------|
| Q1 | Lab substrate | **Cloud free-tier** (not local VMs / Docker) |
| Q2 | Repo centre | **Lab-as-code + detections + IR docs, PLUS a small testable Python CLI** |
| Q3 | Cloud + lifecycle | **Oracle Cloud Always-Free Ampere, persistent** (ARM64) |
| Q4 | Windows telemetry | **Linux-only v1; Windows/Sysmon as documented stretch** |
| A  | Build structure | **Approach B** — scripted lab + content-as-code (Terraform is a stretch, not v1) |

**Consequence of ARM64:** x86-only target images (e.g. Metasploitable2) will not run.
Targets are ARM Ubuntu hosts exercised by Atomic Red Team + a brute-forcer, which triggers
the exact detections the README lists without needing a pre-built vulnerable VM.

## 4. Architecture

### 4.1 Lab topology

All compute comes from the single Always-Free Ampere allocation (4 OCPU / 24 GB, ARM64),
split into two instances inside one VCN / private subnet:

```
            Oracle Cloud — one VCN, one private subnet
  ┌─────────────────────────────────────────────────────────┐
  │  siem        (ARM, ~3 OCPU / 18 GB)                       │
  │   • Wazuh all-in-one: manager + indexer + dashboard       │
  │   • local Wazuh agent (self-monitoring)                   │
  │                                                           │
  │  victim      (ARM, ~1 OCPU / 6 GB)                        │
  │   • Ubuntu + Wazuh agent                                  │
  │   • exposed SSH (brute-force target), auditd, FIM dirs    │
  │   • Atomic Red Team runner (Linux TTPs)                   │
  └─────────────────────────────────────────────────────────┘
   agent→manager 1514/1515 stays PRIVATE inside the VCN
   dashboard 443 reachable only from the owner's IP (or via SSH tunnel)
```

**Network security.** Agent↔manager traffic (1514/1515) never leaves the VCN — both hosts
use private IPs. The Wazuh dashboard (443) is reachable only from the owner's IP via the
security list, or through an SSH tunnel. No Wazuh port is exposed to the public internet.

### 4.2 Data flow (detection → evidence → artifact)

```
attack (Atomic Red Team on victim; hydra SSH brute-force, all in-VCN)
   → victim logs (auth.log, auditd, syscheck/FIM, exec)
   → Wazuh agent ships → manager decoders + rules
   → alert fires → dashboard + alerts.json
   → export incident-window alerts.json  ──►  committed FIXTURE in repo
                                              │
   Python CLI reads fixture ───────────────►─┘
   → ATT&CK coverage matrix + auto-drafted IR report sections
   → human finalizes the NIST 800-61 report (human in the loop)
```

The live lab produces proof **once**; everything downstream replays in CI from committed
fixtures with no SIEM running (mirrors project 02's offline, fixture-driven philosophy).

### 4.3 Safety invariants (carried from netrecon)

- **Scope guard, fail-closed:** attacks only ever target the owner's own lab instances. The
  guard lives in Python (`siem_ir.safety`) and the bash attack scripts shell out to it; any
  target outside `lab.subnets` is refused. One tested guard, reused.
- **Authorized-lab-only** use is stated in `DISCLAIMER.md`.

## 5. Repository structure

Own git repo (like 01/02), GitHub `personal-siem-ir-lab`. Layout follows established conventions
(Python package + `pyproject.toml` + `tests/` + `docs/` + maintained markdown).

```
personal-siem-ir-lab/
├── README.md  CLAUDE.md  CHANGELOG.md  plan.md  DISCLAIMER.md  LICENSE
├── pyproject.toml
├── lab.toml                  # instance names + lab subnet (scope guard) + ATT&CK map path
├── infra/                    # Approach B: scripted lab
│   ├── bootstrap-siem.sh     # install Wazuh all-in-one
│   ├── bootstrap-victim.sh   # agent + auditd + FIM dirs + exposed SSH
│   └── NETWORK.md            # VCN / security-list / dashboard-access notes
├── detections/
│   ├── rules/                # custom Wazuh rules XML (one file per detection)
│   ├── decoders/
│   └── DETECTIONS.md         # catalogue: rule → ATT&CK ID → rationale → trigger → validation
├── attack/
│   ├── atomic/               # Atomic Red Team test selection + invoke notes
│   ├── ssh-bruteforce.sh     # scope-guarded
│   └── ATTACK-PLAN.md        # which TTP fires which detection
├── dashboards/               # saved-objects JSON + screenshots/
├── siem_ir/                  # the small Python CLI
│   ├── cli.py  coverage.py  report.py  attack_map.py  safety.py
├── fixtures/                 # committed exported alerts.json per scenario (offline tests)
├── examples/                 # generated coverage matrix + draft report
├── reports/                  # the finalized NIST 800-61 IR report(s)
├── docs/                     # DECISIONS.md (ADRs)  THREAT-MODEL.md  RUNBOOK.md
└── tests/                    # pytest: tool logic + rule lint
```

## 6. Detection content

≥5 custom Wazuh detections, each mapped to ATT&CK with a concrete validation trigger.
Custom rule IDs use the user range (≥100000).

| # | Detection | ATT&CK | Trigger to validate |
|---|-----------|--------|---------------------|
| 1 | SSH brute-force (N failures / window) | T1110.001 / .003 | `hydra` against victim SSH |
| 2 | Privilege escalation via sudo | T1548.003 | Atomic T1548.003 |
| 3 | Local account creation | T1136.001 | Atomic T1136.001 (`useradd`) |
| 4 | Suspicious shell / reverse-shell exec | T1059.004 | Atomic T1059.004 (`curl\|bash`, `nc`) |
| 5 | File-integrity change on /etc, /usr/bin (FIM) | T1565.001 / T1070 | modify a monitored file |
| 6 *(stretch)* | Cron / authorized_keys persistence | T1053.003 / T1098.004 | Atomic persistence test |

Every `DETECTIONS.md` row carries the hardening-auditor traceability chain:
**CV claim → ATT&CK ID → rule → rationale → validation evidence.**

Tuning: generate benign noise first, then tune out false positives before declaring a
detection done.

## 7. Attack → evidence pipeline

1. Run the attack against `victim` (scope-guarded scripts + Atomic Red Team).
2. In Wazuh, filter to the incident window → export matching alerts → `alerts.json`.
3. Sanitize + commit to `fixtures/<scenario>.json`. Screenshot the dashboard alert →
   `dashboards/screenshots/`.
4. Python CLI runs against the fixture → outputs land in `examples/`.
5. Author the final `reports/IR-<date>-<scenario>.md` from the drafted skeleton + screenshots.

## 8. The Python CLI (`siem_ir`)

Analysis/reporting only — it reads exported alert JSON and never touches the live SIEM API.
This keeps it decoupled and fully testable offline.

| Command | Behaviour |
|---------|-----------|
| `siem-ir coverage --alerts fixtures/x.json` | Map fired rule IDs → ATT&CK techniques; emit a **coverage matrix** (planned TTPs vs. actually-detected) as MD + JSON; surface detection **gaps**. |
| `siem-ir report --alerts fixtures/x.json --scenario x` | Draft NIST 800-61 sections: detection summary, **timeline from alert timestamps**, affected hosts, observed ATT&CK IDs → markdown skeleton for the human to finalize. |
| `siem-ir validate-rules detections/rules/` | Lint custom Wazuh XML: well-formed, rule id in custom range (≥100000), has a `mitre`/ATT&CK id, group present. The **test for detection content**. |
| `python -m siem_ir.safety check <target>` | Fail-closed **scope guard**; attack scripts call this; refuses any target outside `lab.subnets`. |

**Modules:** `cli.py` (arg parsing / dispatch), `coverage.py`, `report.py`,
`attack_map.py` (ATT&CK technique catalogue + rule→technique mapping), `safety.py`.

## 9. Incident response report (NIST SP 800-61)

**The incident is one coherent attack chain** (not a lone alert), so the report has a real
narrative exercising multiple detections:

> SSH brute-force (T1110) → successful login → sudo privilege escalation (T1548.003) →
> local account creation for persistence (T1136.001).

`reports/IR-<date>-ssh-bruteforce-chain.md` follows the full lifecycle, each phase tagged
with ATT&CK IDs and linked to the firing alert + screenshot:
**Detection & Analysis → Triage → Containment → Eradication → Recovery → Lessons Learned.**

## 10. Testing

Offline pytest suite (parity with 01/02), all driven by committed fixtures:

- `coverage.py`: rule→ATT&CK mapping + gap detection against a known fixture.
- `report.py`: timeline ordering; all required NIST sections present.
- `safety.py`: in-subnet passes; out-of-subnet + malformed input **fail closed**.
- `validate-rules`: a good rule passes; a rule missing its ATT&CK id fails.

## 11. Build milestones (Approach B sequencing)

| M | Milestone | Needs live lab? |
|---|-----------|-----------------|
| M0 | Repo scaffold: git+GitHub, `CLAUDE.md`/docs skeleton, `pyproject`, scope guard + test harness | No |
| M1 | Provision Oracle lab (siem+victim), bootstrap scripts, Wazuh up, agent enrolled, `RUNBOOK.md` | Yes |
| M2 | Author ≥5 detection rules + decoders; `validate-rules` green; generate benign noise, tune FPs | Yes |
| M3 | Attack sim: hydra + Atomic TTPs, confirm alerts fire, export fixtures + screenshots | Yes |
| M4 | Python CLI: coverage matrix + IR draft from fixtures; `examples/` committed; tests green | No |
| M5 | Write the full NIST 800-61 IR report for the chain; map to ATT&CK | No |
| M6 *(stretch)* | Windows/Sysmon via laptop+Tailscale · Terraform IaC · persistence detection · alert webhook | — |

M0/M4/M5 need no cloud, so work and commits can begin immediately and continue when the lab
is down.

## 12. Conventions, docs discipline & git workflow

- **Own repo, own GitHub remote**, default branch `main` (like 01/02).
- **Commit + push every task** — small, single-purpose, conventional messages.
- **Maintained-docs discipline** (carried from the hardening-auditor): the following are
  updated **in the same commit** as the code/content they describe — a task is not done
  until its doc is current: `README.md`, `CHANGELOG.md`, `plan.md`, `detections/DETECTIONS.md`,
  `docs/DECISIONS.md` (ADRs), `docs/THREAT-MODEL.md`, `docs/RUNBOOK.md`.
- `.gitignore` includes the global baseline; `CLAUDE.md` and `docs/` **are committed**
  (consistent with 01/02).
- `DISCLAIMER.md` states authorized-lab-only use; attack content is scope-guarded.

## 13. Definition of done (from portfolio README)

- [ ] Public repo: deployment notes, custom detection rules, dashboards (screenshots).
- [ ] ≥5 working detections, each mapped to a MITRE ATT&CK ID.
- [ ] One full written **incident report** (NIST 800-61 lifecycle) for the simulated chain.
- [ ] Evidence the alert fired (SIEM screenshot + timeline).
- [ ] `siem_ir` CLI with green offline test suite; `examples/` regenerated from fixtures.

**Target CV bullet:** "Stood up a Wazuh SIEM ingesting Linux telemetry, authored MITRE
ATT&CK-mapped detections, and documented a full NIST 800-61 incident-response cycle for a
simulated brute-force→privilege-escalation intrusion."

## 14. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Oracle Always-Free Ampere capacity ("out of host capacity" errors are common) | Retry across availability domains; document the workaround in `RUNBOOK.md`; fall back to a smaller shape split if needed |
| ARM64 incompatibility of attack/target tooling | Use Atomic Red Team (script-based, ARM-friendly) + `hydra`; avoid x86-only images by design |
| Wazuh indexer memory pressure on the shared allocation | Give `siem` the larger share (~18 GB); single-node; tune JVM heap in bootstrap |
| Exposing the SIEM accidentally to the internet | Security list locks 443 to owner IP; agent ports stay private in-VCN; documented in `NETWORK.md` |
| Scope creep into Sigma engineering (project 08) | Spec explicitly limits this project to native Wazuh rules |

## 15. Future / stretch (explicitly out of v1 scope)

- Windows/Sysmon endpoint via the owner's laptop + Wazuh agent over Tailscale/WireGuard,
  with Windows ATT&CK detections (suspicious process / PowerShell).
- Terraform/OCI IaC to make the lab one-command reproducible (Approach A as an add-on).
- Detection #6 (cron / authorized_keys persistence).
- Alerting webhook (email/Slack) on high-severity alerts.

## 16. Open questions

None — Q1–Q4 and the build approach are resolved (see §3).
