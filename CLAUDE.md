# personal-siem-ir-lab — Claude Code project guide

## What this repo is
A portfolio SIEM & incident-response lab: Wazuh on Oracle Cloud, custom MITRE ATT&CK-mapped
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
