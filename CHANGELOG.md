# Changelog

All notable changes to this project will be documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Security (hardening — 2026-06-27)
- **SECURITY#1 (High):** Replaced `xml.etree.ElementTree` with `defusedxml.ElementTree` in
  `siem_ir/validate_rules.py` to block entity-expansion (billion-laughs) DoS.
  Added `defusedxml>=0.7` as a runtime dependency.
- **SECURITY#2 (Med):** Froze `_ALLOWED_SUBNETS` to a `tuple` in `siem_ir/safety.py`
  to make accidental in-place mutation visible as a `TypeError`. Added `reload()` so
  callers can refresh the cache without restarting the process.
- **SECURITY#3 (Med):** `_load_subnets()` now prefers an explicit `SIEM_IR_LAB_CONFIG`
  environment variable and only falls back to the package repo root (one level up), not
  three ancestor directories. The resolved config path is always logged via `warnings.warn`
  so operators can verify the correct file was loaded.
- **SECURITY#4 (Med):** Added `MAX_FIXTURE_BYTES` (100 MB) and `MAX_ALERTS` (50 000)
  guards in `siem_ir/coverage._load_alerts()` to prevent memory exhaustion from
  over-sized alert fixtures.
- **SECURITY#5 (Med):** Added `_safe_output_path()` in `siem_ir/cli.py` to validate that
  `--output` / `--output-json` paths do not escape the current working directory.
  Traversal attempts (e.g. `../../evil`) are refused with a `ValueError`.
- **SECURITY#6 (Low):** Sanitized the `--scenario` argument in `siem_ir/report.py` to
  `[A-Za-z0-9_-]` before embedding in the report to prevent Markdown/HTML injection.
- **SECURITY#7 (Low):** Added `_escape_md()` in `siem_ir/report.py`; alert-fixture field
  values (`rule.description`, `rule.id`, `agent.name`) are now escaped before embedding
  in the Markdown report to neutralize second-order injection payloads.
- **SECURITY#8 (Low):** `_load_subnets()` now also catches `OSError` (in addition to
  `TOMLDecodeError`), emits a warning, and returns `[]` (fail-closed) on I/O failures.
- Added 17 regression tests covering all 8 findings.

### Fixed (self-review — 2026-06-27)
- **Dead code:** removed redundant `_ALLOWED_SUBNETS: tuple[str, ...] = ()` placeholder
  in `siem_ir/safety.py` (it was immediately overwritten by the real initialisation on the
  next statement and served no purpose).
- **Unicode stdout:** `siem_ir/cli.py:main()` now calls `sys.stdout.reconfigure(encoding="utf-8")`
  on entry so the coverage matrix Unicode symbols (✓ ✗) do not crash on Windows terminals
  that default to a narrow code page (e.g. cp1252).

### Added
- Repo scaffold: pyproject.toml, lab.toml, .gitignore, LICENSE, DISCLAIMER.md, CLAUDE.md, plan.md (M0)
- `README.md`: overview README with summary, topics covered, layout, CLI usage, milestones
- Python package skeleton: `siem_ir/__init__.py`, `tests/__init__.py`, dir stubs with .gitkeep
- Doc stubs: `detections/DETECTIONS.md`, `infra/NETWORK.md`, `attack/ATTACK-PLAN.md`, `docs/DECISIONS.md`, `docs/THREAT-MODEL.md`, `docs/RUNBOOK.md`
- `siem_ir/safety.py`: fail-closed scope guard; ScopeError for out-of-subnet + malformed input (M0)
- `tests/test_safety.py`: 19 tests covering in-subnet pass, out-of-subnet fail, malformed fail, security regressions
- `siem_ir/attack_map.py`: ATT&CK technique catalogue (8 techniques) and rule→technique mapping for lab detections
- `fixtures/ssh-bruteforce-chain.json`: realistic Wazuh alert fixture — brute-force → privesc → account-creation (3 alerts)
- `siem_ir/coverage.py`: ATT&CK coverage matrix from Wazuh alert fixtures; CoverageResult dataclass; gap detection
- `tests/test_coverage.py`: 16 tests covering hits/gaps/markdown/JSON/error cases and security regressions
- `siem_ir/report.py`: NIST SP 800-61 IR report drafter; chronological timeline; all required sections
- `tests/test_report.py`: 20 tests covering required sections, timeline ordering, TTP presence, security regressions
- `siem_ir/validate_rules.py`: Wazuh rule XML linter (well-formed, id >= 100000, mitre tag, group present)
- `fixtures/rules/`: sample pass/fail rule XML files for linter tests (rule_valid, rule_bad_id, rule_no_mitre, rule_no_group, rule_malformed)
- `tests/test_validate_rules.py`: 11 tests covering each failure mode + directory lint + security regressions
- `siem_ir/cli.py`: argparse dispatch for `coverage`, `report`, `validate-rules` commands; `siem-ir` entry point
- `tests/test_cli_security.py`: 5 tests covering output path-traversal guard (SECURITY#5)
- `examples/`: pre-generated coverage matrix (MD + JSON) and IR report skeleton from ssh-bruteforce-chain fixture
- Total: 71 tests, all passing.
