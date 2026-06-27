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
    except (FileNotFoundError, ValueError) as exc:
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
    except (FileNotFoundError, ValueError) as exc:
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
        description="siem_ir - ATT&CK coverage analysis and NIST 800-61 IR report drafting",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # coverage
    p_cov = sub.add_parser(
        "coverage",
        help="Map alert rule IDs to ATT&CK techniques; emit coverage matrix",
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
