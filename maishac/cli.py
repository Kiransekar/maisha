"""Maisha command line interface.

    maishac scan src/                     scan + sync memory
    maishac findings --limit 20           list open findings
    maishac rule "MISRA 21.3"             explain a rule
    maishac session begin src/            start an engineered fix session
    maishac session batch <id>            next prioritized batch (JSON)
    maishac session verify <id>           rescan + converge check
    maishac deviate "MISRA 21.6" -s "src/debug/*" -j "..."
    maishac suppress <fingerprint> -r "false positive because ..."
    maishac note "Use pool_alloc() instead of malloc" -t allocator
    maishac report [--format markdown|json|sarif] [-o file]
    maishac import findings.sarif         ingest an external engine's SARIF
    maishac approve <fingerprint> --by me  human sign-off on a verified fix
    maishac serve                         run the MCP server (stdio)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .engine import LoopEngine
from .rules import REGISTRY
from . import report as report_mod


def _engine(args) -> LoopEngine:
    return LoopEngine(getattr(args, "project", None) or os.getcwd())


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_scan(args):
    eng = _engine(args)
    _print(eng.scan(args.paths, args.analyzers.split(",") if args.analyzers else None))


def cmd_findings(args):
    eng = _engine(args)
    rows = eng.mem.open_findings(limit=args.limit)
    if args.json:
        _print(eng._brief_many(rows))
        return
    if not rows:
        print("No open findings.")
        return
    for f in rows:
        flag = "↩REGRESSED " if f["status"] == "regressed" else ""
        print(f"[{f['severity']:>8}] {flag}{f['rule_id']:<28} {f['file']}:{f['line']}"
              f"  {f['message'][:80]}  ({f['fingerprint']})")


def cmd_rule(args):
    meta = REGISTRY.resolve(args.rule)
    if not meta:
        print(f"Rule '{args.rule}' not found. Closest:", file=sys.stderr)
        for h in REGISTRY.search(args.rule):
            print(f"  {h['id']}", file=sys.stderr)
        sys.exit(1)
    out = dict(meta)
    out["equivalent_rules"] = REGISTRY.cross_refs(meta["id"])
    _print(out)


def cmd_session(args):
    eng = _engine(args)
    if args.action == "begin":
        # for 'begin', the first positional is a path, not a session id
        paths = ([args.session_id] if args.session_id else []) + list(args.paths or [])
        args.paths = paths or ["."]
        _print(eng.begin_session(args.paths, {
            "max_iterations": args.max_iterations, "batch_size": args.batch_size,
            "verification_policy": args.verification_policy,
            "test_command": args.test_command}, force=args.force))
    elif args.action == "batch":
        _print(eng.next_batch(args.session_id))
    elif args.action == "verify":
        _print(eng.verify(args.session_id))
    elif args.action == "status":
        _print(eng.session_status(args.session_id))


def cmd_approve(args):
    eng = _engine(args)
    _print(eng.approve(args.fingerprint, args.by))


def cmd_import(args):
    eng = _engine(args)
    if args.format != "sarif":
        print(f"Unsupported import format '{args.format}' (only 'sarif').", file=sys.stderr)
        sys.exit(1)
    _print(eng.import_sarif(args.file))


def cmd_deviate(args):
    eng = _engine(args)
    meta = REGISTRY.resolve(args.rule)
    if not meta:
        print(f"Unknown rule '{args.rule}'", file=sys.stderr)
        sys.exit(1)
    did = eng.mem.add_deviation(meta["id"], args.scope, args.justification,
                                args.approver, args.expires_days or None)
    _print({"deviation_id": did, "rule_id": meta["id"]})


def cmd_suppress(args):
    eng = _engine(args)
    eng.mem.suppress(args.fingerprint, args.reason)
    _print({"suppressed": args.fingerprint})


def cmd_note(args):
    eng = _engine(args)
    nid = eng.mem.add_note(args.content, args.topic, args.tags)
    _print({"note_id": nid})


def cmd_report(args):
    eng = _engine(args)
    if args.format == "sarif":
        text = json.dumps(report_mod.sarif(eng.mem), indent=2)
    elif args.format == "json":
        text = json.dumps(report_mod.compliance_matrix(eng.mem), indent=2)
    else:
        text = report_mod.markdown_report(eng.mem, project_name=eng.root.name)
    if args.output:
        Path(args.output).write_text(text, "utf-8")
        print(f"Wrote {args.output}")
    else:
        print(text)


def cmd_serve(args):
    if getattr(args, "project", None):
        os.environ["MAISHAC_PROJECT"] = str(Path(args.project).resolve())
    try:
        from .mcp_server import main as serve_main
    except ModuleNotFoundError as e:
        sys.exit(f"The MCP server needs the 'mcp' package (missing: {e.name}). Install it with: pip install mcp")
    serve_main()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="maishac",
                                description="Agent harness for MISRA C, BARR-C and CERT C.")
    p.add_argument("--project", "-p", help="Project root (default: cwd)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan paths and sync memory")
    s.add_argument("paths", nargs="+")
    s.add_argument("--analyzers", help="Comma list: native,cppcheck,clang-tidy")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("findings", help="List open findings")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_findings)

    s = sub.add_parser("rule", help="Explain a rule")
    s.add_argument("rule")
    s.set_defaults(fn=cmd_rule)

    s = sub.add_parser("session", help="Engineered fix-loop sessions")
    s.add_argument("action", choices=["begin", "batch", "verify", "status"])
    s.add_argument("session_id", nargs="?")
    s.add_argument("paths", nargs="*")
    s.add_argument("--max-iterations", type=int, default=10)
    s.add_argument("--batch-size", type=int, default=5)
    s.add_argument("--verification-policy",
                   choices=["analyzer_only", "test_gated", "human_gated"],
                   help="How a fix is confirmed resolved (default: test_gated if "
                        "--test-command is set, else human_gated).")
    s.add_argument("--test-command",
                   help="Shell command that must exit 0 to confirm fixes (e.g. 'make test').")
    s.add_argument("--force", action="store_true",
                   help="Start a new session even if one is already active on this project.")
    s.set_defaults(fn=cmd_session)

    s = sub.add_parser("approve", help="Approve a pending_verification finding as resolved")
    s.add_argument("fingerprint")
    s.add_argument("--by", required=True, help="Who is signing off (recorded in the audit trail).")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("import", help="Import findings from an external SARIF file")
    s.add_argument("file")
    s.add_argument("--format", choices=["sarif"], default="sarif")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("deviate", help="Record a formal rule deviation")
    s.add_argument("rule")
    s.add_argument("--scope", "-s", default="*")
    s.add_argument("--justification", "-j", required=True)
    s.add_argument("--approver", default="")
    s.add_argument("--expires-days", type=float, default=0)
    s.set_defaults(fn=cmd_deviate)

    s = sub.add_parser("suppress", help="Suppress a false positive")
    s.add_argument("fingerprint")
    s.add_argument("--reason", "-r", required=True)
    s.set_defaults(fn=cmd_suppress)

    s = sub.add_parser("note", help="Persist project knowledge")
    s.add_argument("content")
    s.add_argument("--topic", "-t", default="")
    s.add_argument("--tags", default="")
    s.set_defaults(fn=cmd_note)

    s = sub.add_parser("report", help="Compliance report")
    s.add_argument("--format", choices=["markdown", "json", "sarif"], default="markdown")
    s.add_argument("--output", "-o")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("serve", help="Run the MCP server (stdio)")
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
