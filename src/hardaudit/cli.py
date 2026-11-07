"""Command line: audit, fix, undo, backups, rules."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from hardaudit import __version__, fixes
from hardaudit import report as reports
from hardaudit import rules as rule_files
from hardaudit.engine import audit
from hardaudit.host import Host
from hardaudit.model import SEVERITIES

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hardaudit",
        description="Audit a Linux host against hardening rules, and apply the safe fixes.",
    )
    parser.add_argument("--version", action="version", version=f"hardaudit {__version__}")
    sub = parser.add_subparsers(dest="command")

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--root", default="/", help="audit this directory tree instead of the running system"
        )
        p.add_argument("--rules-dir", help="extra rule files (*.toml) to load")
        p.add_argument(
            "--only",
            action="append",
            default=[],
            metavar="ID",
            help="run only this rule (repeatable)",
        )
        p.add_argument(
            "--skip", action="append", default=[], metavar="ID", help="skip this rule (repeatable)"
        )

    audit_p = sub.add_parser("audit", help="check the host (the default command)")
    common(audit_p)
    audit_p.add_argument("--format", choices=("text", "json", "html"), default="text")
    audit_p.add_argument("-o", "--output", help="write the report to this file")
    audit_p.add_argument("-v", "--verbose", action="store_true", help="also list passed rules")
    audit_p.add_argument(
        "--fail-on",
        choices=(*SEVERITIES, "none"),
        default="high",
        help="exit 1 if a rule of this severity or worse fails (default: high)",
    )

    fix_p = sub.add_parser("fix", help="show, or with --apply make, the safe fixes")
    common(fix_p)
    fix_p.add_argument(
        "--apply", action="store_true", help="really change the system (default: dry run)"
    )

    undo_p = sub.add_parser("undo", help="restore the files changed by an earlier fix")
    undo_p.add_argument("backup_id")
    undo_p.add_argument("--root", default="/")

    back_p = sub.add_parser("backups", help="list the backups made by fix --apply")
    back_p.add_argument("--root", default="/")

    rules_p = sub.add_parser("rules", help="list the rules")
    rules_p.add_argument("--rules-dir")
    rules_p.add_argument(
        "--markdown", action="store_true", help="print the rules as a Markdown table"
    )
    return parser


def _load(args: argparse.Namespace) -> list:  # type: ignore[type-arg]
    return rule_files.load(getattr(args, "rules_dir", None))


def _cmd_audit(args: argparse.Namespace) -> int:
    rules = _load(args)
    result = audit(Host(args.root), rules, only=args.only, skip=args.skip)
    if args.format == "json":
        out = reports.to_json(result)
    elif args.format == "html":
        out = reports.to_html(result)
    else:
        out = reports.text(result, verbose=args.verbose)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")
    if args.fail_on != "none":
        limit = SEVERITIES.index(args.fail_on)
        if any(
            r.status == "fail" and SEVERITIES.index(r.rule.severity) <= limit
            for r in result.results
        ):
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_fix(args: argparse.Namespace) -> int:
    rules = _load(args)
    host = Host(args.root)
    before = audit(host, rules, only=args.only, skip=args.skip)
    changes = fixes.plan(host, before, rules, only=args.only)
    if not changes:
        print("Nothing to fix automatically. Run 'hardaudit audit' for the rest.")
        return EXIT_OK
    verb = "Will change" if args.apply else "Dry run - would change"
    print(f"{verb}:")
    for change in changes:
        print(f"  - {change.summary}")
    if not args.apply:
        print("\nNothing was changed. Add --apply to make these changes (a backup is kept).")
        return EXIT_OK
    if args.root == "/" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("error: --apply on the running system needs root", file=sys.stderr)
        return EXIT_USAGE
    notes: list[str] = []
    backup_id = fixes.apply(host, changes, notes)
    after = audit(host, rules, only=args.only, skip=args.skip)
    print(f"\nDone. Backup: {backup_id}   (undo: hardaudit undo {backup_id})")
    for note in notes:
        print(f"warning: {note}")
    old, new = before.score, after.score
    print(f"Score: {old} -> {new}")
    still = [r.rule.id for r in after.results if r.status == "fail" and r.rule.apply]
    if still:
        print(f"Still failing after the fix: {', '.join(still)}")
    return EXIT_OK


def _cmd_undo(args: argparse.Namespace) -> int:
    count = fixes.undo(Host(args.root), args.backup_id)
    print(f"Restored {count} item(s) from backup {args.backup_id}.")
    return EXIT_OK


def _cmd_backups(args: argparse.Namespace) -> int:
    found = fixes.list_backups(Host(args.root))
    print("\n".join(found) if found else "No backups.")
    return EXIT_OK


def rules_markdown(rules: list) -> str:  # type: ignore[type-arg]
    """One table per section: id, severity, what it checks, how it is fixed."""
    lines: list[str] = []
    for section in dict.fromkeys(r.section for r in rules):
        lines += [
            f"### {section}",
            "",
            "| Id | Severity | Rule | Automatic fix |",
            "|---|---|---|---|",
        ]
        for r in (x for x in rules if x.section == section):
            fix = {"sysctl": "kernel setting", "chmod": "removes permissions",
                   "config_line": "edits one line", "module_block": "blocks the module"}.get(
                r.apply["type"] if r.apply else "", "no (suggested command only)")  # fmt: skip
            lines.append(f"| `{r.id}` | {r.severity} | {r.title} | {fix} |")
        lines.append("")
    return "\n".join(lines)


def _cmd_rules(args: argparse.Namespace) -> int:
    if args.markdown:
        print(rules_markdown(rule_files.load(args.rules_dir)))
        return EXIT_OK
    for rule in rule_files.load(args.rules_dir):
        marker = "fix" if rule.apply else "   "
        families = ",".join(rule.families) or "all"
        print(f"{rule.id}  {rule.severity:<6} {marker}  {families:<12} {rule.title}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list or (
        args_list[0].startswith("-") and args_list[0] not in ("-h", "--help", "--version")
    ):
        args_list.insert(0, "audit")  # `hardaudit -v` means `hardaudit audit -v`
    parser = _parser()
    args = parser.parse_args(args_list)
    if args.command is None:
        parser.print_help()
        return EXIT_USAGE
    handlers = {"audit": _cmd_audit, "fix": _cmd_fix, "undo": _cmd_undo,
                "backups": _cmd_backups, "rules": _cmd_rules}  # fmt: skip
    try:
        return handlers[args.command](args)
    except (rule_files.RuleError, fixes.FixError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
