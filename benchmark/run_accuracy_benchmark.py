#!/usr/bin/env python
"""Accuracy benchmark harness for Maisha.

Runs `maishac scan` (all available analyzers) against benchmark/fixtures/*.c
and reconciles the findings against benchmark/ground_truth.json to compute:

  - seeded recall     — of the deliberately-planted defects, how many did
                        at least one analyzer catch?
  - precision          — of everything reported, how much is a real defect
                        (seeded or a legitimate incidental true positive) vs
                        a confirmed or unclassified false positive?
  - a before/after comparison with and without --include, to quantify the
    include-path-forwarding fix from this cycle.

Usage (from repo root):
    python benchmark/run_accuracy_benchmark.py

Requires cppcheck and clang-tidy on PATH for full 3-analyzer coverage; falls
back to native-only (with a warning) if they're missing.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from maishac.analyzers import run_scan, available_analyzers  # noqa: E402

FIXTURES_DIR = ROOT / "benchmark" / "fixtures"
GROUND_TRUTH_PATH = ROOT / "benchmark" / "ground_truth.json"
RESULTS_DIR = ROOT / "benchmark" / "results"


def _norm_path(p: str) -> str:
    return p.replace("\\", "/")


def load_ground_truth() -> dict:
    return json.loads(GROUND_TRUTH_PATH.read_text("utf-8"))


def scan_fixtures(include_paths: list[str] | None) -> tuple[list, list[str], float]:
    files = sorted(FIXTURES_DIR.glob("*.c"))
    t0 = time.monotonic()
    findings, used = run_scan([str(f) for f in files], ROOT, include_paths=include_paths)
    elapsed = time.monotonic() - t0
    return findings, used, elapsed


def in_scope(finding, gt: dict) -> bool:
    f = _norm_path(finding.file)
    return not any(f.startswith(_norm_path(p)) for p in gt["exclude_path_prefixes"])


def reconcile(findings: list, gt: dict) -> dict:
    by_file: dict[str, list] = {}
    for f in findings:
        if not in_scope(f, gt):
            continue
        by_file.setdefault(Path(_norm_path(f.file)).name, []).append(f)

    report = {"fixtures": {}, "totals": {
        "seeded": 0, "seeded_detected": 0,
        "true_extra": 0, "confirmed_fp": 0, "unclassified": 0,
    }}

    known_extra_rules = set(gt["known_true_extra_rules"])

    for fname, spec in gt["fixtures"].items():
        actual = by_file.get(fname, [])
        actual_rules = [(a.rule_id, a.line) for a in actual]
        actual_rule_set = {a.rule_id for a in actual}

        seeded = spec["seeded"]
        seeded_hits, seeded_misses = [], []
        for s in seeded:
            if s["rule"] in actual_rule_set:
                seeded_hits.append(s)
            else:
                seeded_misses.append(s)

        known_fp = {(fp["rule"], fp["line"]) for fp in spec.get("known_false_positives", [])}

        true_extra, confirmed_fp, unclassified = [], [], []
        seeded_rule_set = {s["rule"] for s in seeded}
        for rule_id, line in actual_rules:
            if rule_id in seeded_rule_set:
                continue  # already counted as a seeded hit
            if (rule_id, line) in known_fp:
                confirmed_fp.append((rule_id, line))
            elif rule_id in known_extra_rules:
                true_extra.append((rule_id, line))
            else:
                unclassified.append((rule_id, line))

        report["fixtures"][fname] = {
            "seeded_total": len(seeded),
            "seeded_detected": len(seeded_hits),
            "seeded_missed": [f"{m['rule']} (line {m['line']}): {m['note']}" for m in seeded_misses],
            "true_extra_count": len(true_extra),
            "confirmed_fp": [f"{r} @ line {l}" for r, l in confirmed_fp],
            "unclassified": [f"{r} @ line {l}" for r, l in unclassified],
            "total_findings_in_scope": len(actual),
        }

        report["totals"]["seeded"] += len(seeded)
        report["totals"]["seeded_detected"] += len(seeded_hits)
        report["totals"]["true_extra"] += len(true_extra)
        report["totals"]["confirmed_fp"] += len(confirmed_fp)
        report["totals"]["unclassified"] += len(unclassified)

    return report


def print_report(report: dict, analyzers_used: list[str], elapsed: float) -> None:
    t = report["totals"]
    print(f"\nAnalyzers used: {analyzers_used}  (scan took {elapsed:.2f}s)")
    print("=" * 78)
    for fname, r in report["fixtures"].items():
        print(f"\n{fname}")
        print(f"  seeded defects:   {r['seeded_detected']}/{r['seeded_total']} detected")
        if r["seeded_missed"]:
            for m in r["seeded_missed"]:
                print(f"    MISSED: {m}")
        print(f"  incidental true-positive findings (structural, not seeded): {r['true_extra_count']}")
        if r["confirmed_fp"]:
            print(f"  CONFIRMED FALSE POSITIVES: {r['confirmed_fp']}")
        if r["unclassified"]:
            print(f"  UNCLASSIFIED (needs manual review): {r['unclassified']}")

    print("\n" + "=" * 78)
    seeded_recall = t["seeded_detected"] / t["seeded"] if t["seeded"] else float("nan")
    total_reported = t["seeded_detected"] + t["true_extra"] + t["confirmed_fp"] + t["unclassified"]
    precision = ((t["seeded_detected"] + t["true_extra"]) / total_reported) if total_reported else float("nan")
    print(f"TOTAL seeded defects: {t['seeded']}  detected: {t['seeded_detected']}  "
          f"(recall = {seeded_recall:.1%})")
    print(f"TOTAL incidental true positives: {t['true_extra']}")
    print(f"TOTAL confirmed false positives: {t['confirmed_fp']}")
    print(f"TOTAL unclassified findings: {t['unclassified']}")
    print(f"Precision on in-scope reported findings: {precision:.1%}")


def main() -> None:
    gt = load_ground_truth()
    RESULTS_DIR.mkdir(exist_ok=True)

    analyzers = available_analyzers()
    print(f"Available analyzers on this machine: {[a.name for a in analyzers]}")

    print("\n" + "#" * 78)
    print("# RUN 1: WITHOUT --include (reproduces the pre-fix configuration)")
    print("#" * 78)
    findings_no_inc, used_no_inc, t_no_inc = scan_fixtures(include_paths=None)
    report_no_inc = reconcile(findings_no_inc, gt)
    print_report(report_no_inc, used_no_inc, t_no_inc)

    print("\n" + "#" * 78)
    print("# RUN 2: WITH --include benchmark/stubs (this cycle's fix)")
    print("#" * 78)
    findings_inc, used_inc, t_inc = scan_fixtures(include_paths=["benchmark/stubs"])
    report_inc = reconcile(findings_inc, gt)
    print_report(report_inc, used_inc, t_inc)

    out = {
        "without_include_paths": {"report": report_no_inc, "analyzers_used": used_no_inc,
                                   "elapsed_s": t_no_inc, "total_findings": len(findings_no_inc)},
        "with_include_paths": {"report": report_inc, "analyzers_used": used_inc,
                               "elapsed_s": t_inc, "total_findings": len(findings_inc)},
    }
    (RESULTS_DIR / "accuracy_run.json").write_text(json.dumps(out, indent=2), "utf-8")
    print(f"\nWrote {RESULTS_DIR / 'accuracy_run.json'}")


if __name__ == "__main__":
    main()
