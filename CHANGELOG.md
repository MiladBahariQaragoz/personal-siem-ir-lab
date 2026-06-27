# Changelog

All notable changes to this project will be documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Repo scaffold: pyproject.toml, lab.toml, .gitignore, LICENSE, DISCLAIMER.md, CLAUDE.md, plan.md (M0)
- `README.md`: portfolio-grade README with CV bullet, skills, layout, CLI usage, milestones
- Python package skeleton: `siem_ir/__init__.py`, `tests/__init__.py`, dir stubs with .gitkeep
- Doc stubs: `detections/DETECTIONS.md`, `infra/NETWORK.md`, `attack/ATTACK-PLAN.md`, `docs/DECISIONS.md`, `docs/THREAT-MODEL.md`, `docs/RUNBOOK.md`
- `siem_ir/safety.py`: fail-closed scope guard; ScopeError for out-of-subnet + malformed input (M0)
- `tests/test_safety.py`: 12 tests covering in-subnet pass, out-of-subnet fail, malformed fail
- `siem_ir/attack_map.py`: ATT&CK technique catalogue (8 techniques) and rule→technique mapping for lab detections
- `fixtures/ssh-bruteforce-chain.json`: realistic Wazuh alert fixture — brute-force → privesc → account-creation (3 alerts)
- `siem_ir/coverage.py`: ATT&CK coverage matrix from Wazuh alert fixtures; CoverageResult dataclass; gap detection
- `tests/test_coverage.py`: 12 tests covering hits/gaps/markdown/JSON/error cases
- `siem_ir/report.py`: NIST SP 800-61 IR report drafter; chronological timeline; all required sections
- `tests/test_report.py`: 11 tests covering required sections, timeline ordering, TTP presence
