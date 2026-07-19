#!/usr/bin/env python3
"""Measure a native check's false-positive profile against real firmware, fast.

Every native detector in this project has been wrong at least once in a way its
own unit tests could not catch. The reason is structural: fixtures written
alongside an implementation encode that implementation's model of C, so they are
blind to exactly the shapes the author did not think of -- multi-line macros,
directives between switch clauses, `case 1: {`, multi-line function signatures,
code and #include in opposite #if branches.

The benchmark corpus finds those in minutes. Minutes is too slow to sit in a
development loop, which is how detectors got written, tested and *then* found
broken. This tool makes the same question answerable in seconds by scoping it to
one rule and one project, so the corpus can be consulted BEFORE the tests are
written rather than after.

    # is Rule 16.6 clean on the project most likely to break it?
    python tools/fp_check.py --rule 16.6 --project mbedtls

    # everything a rule fires on, with source lines, ready to triage
    python tools/fp_check.py --rule 20.13 --show

    # full sweep of the rules this branch touches
    python tools/fp_check.py --rule 16.2,16.5,16.6

    # what does native find that it did not find before?
    python tools/fp_check.py --baseline before.json --rule 16.6

Exit status is 1 when a rule exceeds --max-findings, so this can gate CI.

Findings here are NOT automatically false positives. The corpus is real,
compliant-ish firmware, so some hits are true. The tool's job is to put the
sample in front of you cheaply; triage is still yours.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from maishac.analyzers.native import NativeAnalyzer   # noqa: E402
from maishac.rules import REGISTRY                    # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CORPORA = ROOT / "benchmark" / "corpora"
ALL_PROJECTS = ["littlefs", "lwip", "mbedtls", "zephyr-kernel"]


def _short(rule_id: str) -> str:
    return rule_id.rsplit(" ", 1)[-1]


def _sources(project: str, headers: bool) -> list[Path]:
    root = CORPORA / project
    files = sorted(root.rglob("*.c"))
    if headers:
        # Preprocessor and macro rules live mostly in headers, so excluding them
        # hides the shapes most likely to break those checks.
        files += sorted(root.rglob("*.h"))
    return files


def scan(projects: list[str], wanted: set[str] | None, headers: bool,
         show: int) -> dict:
    per_project: dict[str, Counter] = {}
    samples: dict[str, list[str]] = defaultdict(list)
    totals: Counter = Counter()
    files_seen = 0
    started = time.time()

    for project in projects:
        root = CORPORA / project
        if not root.exists():
            print(f"  skipping {project}: not cloned "
                  f"(see benchmark/corpora/CLONE.sh)", file=sys.stderr)
            continue
        files = _sources(project, headers)
        files_seen += len(files)
        counts: Counter = Counter()
        for finding in NativeAnalyzer().analyze(files, root):
            num = _short(finding.rule_id)
            if wanted and num not in wanted:
                continue
            counts[num] += 1
            if show and len(samples[num]) < show:
                samples[num].append(
                    f"{project}/{finding.file}:{finding.line}: "
                    f"{finding.line_content.strip()[:70]}")
        per_project[project] = counts
        totals += counts
        print(f"  {project:15} {len(files):5} files  "
              f"{dict(sorted(counts.items())) or 'clean'}", flush=True)

    return {
        "totals": dict(totals),
        "per_project": {p: dict(c) for p, c in per_project.items()},
        "samples": dict(samples),
        "files": files_seen,
        "seconds": round(time.time() - started, 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Measure native checks against the benchmark corpus.")
    ap.add_argument("--rule", help="rule number(s), comma separated, e.g. 16.6 "
                                   "or 20.2,20.3. Default: every native rule.")
    ap.add_argument("--project", help="corpus project(s), comma separated. "
                                      f"Default: all of {', '.join(ALL_PROJECTS)}.")
    ap.add_argument("--show", type=int, default=0, metavar="N",
                    help="print up to N source lines per rule, for triage")
    ap.add_argument("--no-headers", action="store_true",
                    help="scan only .c files (faster, but hides header-only shapes)")
    ap.add_argument("--max-findings", type=int, metavar="N",
                    help="exit 1 if any single rule exceeds N findings")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    ap.add_argument("--baseline", metavar="FILE",
                    help="compare against a previous --json run and show the delta")
    args = ap.parse_args()

    projects = args.project.split(",") if args.project else ALL_PROJECTS
    wanted = None
    if args.rule:
        wanted = {r.strip() for r in args.rule.split(",")}
        for num in sorted(wanted):
            if not REGISTRY.resolve(f"MISRA {num}") and not REGISTRY.resolve(num):
                print(f"warning: '{num}' does not resolve in the knowledge base",
                      file=sys.stderr)

    print(f"scanning {', '.join(projects)}"
          f"{' (.c only)' if args.no_headers else ' (.c and .h)'}"
          f"{' for ' + ', '.join(sorted(wanted)) if wanted else ''}")
    result = scan(projects, wanted, not args.no_headers, args.show)

    print(f"\nTOTAL over {result['files']} files in {result['seconds']}s: "
          f"{dict(sorted(result['totals'].items())) or 'clean'}")

    # A rule that fires nowhere is indistinguishable from one that is switched
    # off, and this project has shipped a disabled check reported as "clean"
    # more than once. Name them explicitly rather than letting silence pass.
    if wanted:
        silent = sorted(wanted - set(result["totals"]))
        if silent:
            print(f"\nNO FINDINGS for: {', '.join(silent)}")
            print("  Either genuinely rare, or the check is not running at all. "
                  "Confirm it fires on a crafted positive before believing this.")

    if args.show:
        for num in sorted(result["samples"]):
            print(f"\n--- {num}")
            for line in result["samples"][num]:
                print(f"    {line}")

    if args.baseline:
        try:
            before = json.loads(Path(args.baseline).read_text("utf-8"))["totals"]
        except (OSError, KeyError, json.JSONDecodeError) as e:
            print(f"cannot read baseline '{args.baseline}': {e}", file=sys.stderr)
            return 2
        after = result["totals"]
        print("\nDELTA vs baseline:")
        for num in sorted(set(before) | set(after)):
            b, a = before.get(num, 0), after.get(num, 0)
            if b != a:
                print(f"    {num}: {b} -> {a}  ({a - b:+d})")
        if before == after:
            print("    (no change)")

    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=1), "utf-8")
        print(f"\nwrote {args.json}")

    if args.max_findings is not None:
        over = {n: c for n, c in result["totals"].items() if c > args.max_findings}
        if over:
            print(f"\nFAIL: over the {args.max_findings}-finding budget: {over}",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
