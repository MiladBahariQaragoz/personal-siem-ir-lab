# personal-siem-ir-lab

> **Incident Response is the single most-demanded gap (39% of jobs)** and SIEM tools appear
> constantly (Splunk, Elastic, Wazuh). This project provides verifiable, hands-on proof.

A working **Wazuh SIEM** on Oracle Cloud ingesting Linux telemetry, firing **custom
MITRE ATT&CK-mapped detection rules**, and backing a full **NIST SP 800-61** incident
response report — all demonstrated with committed alert fixtures, an ATT&CK coverage
matrix, and a drafted IR skeleton that regenerate offline from a single CLI command.

## CV bullet (target)
> Stood up a Wazuh SIEM ingesting Linux telemetry, authored MITRE ATT&CK-mapped
> detections, and documented a full NIST 800-61 incident-response cycle for a simulated
> brute-force→privilege-escalation intrusion.

## Skills this proves
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

The scope guard locates `lab.toml` in this order:
1. `SIEM_IR_LAB_CONFIG` environment variable (recommended for CI/CD).
2. Repo root (one directory above `siem_ir/`).

Set `SIEM_IR_LAB_CONFIG=/absolute/path/to/lab.toml` in pipelines to ensure the correct
config is always loaded. The resolved path is always logged so operators can verify it.

## License

MIT — see `LICENSE`. Authorized lab use only — see `DISCLAIMER.md`.
