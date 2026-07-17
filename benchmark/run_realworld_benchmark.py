"""Real-world corpus benchmark.

BENCHMARKS.md documents ONE hand-analyzed real corpus (FreeRTOS). This runner
generalizes that to several real embedded-C codebases so the finding
distribution — and the false-positive-prone rule classes — can be measured
across projects, not just one. Unlike the fixture accuracy benchmark there is no
ground truth here, so this reports *distribution and density*, not
recall/precision, and explicitly buckets findings into the rule classes that
BENCHMARKS.md found to be configuration-driven false positives (so a reviewer
knows exactly where to sample).

Usage:
    python benchmark/run_realworld_benchmark.py            # scan every corpus in CORPORA present under benchmark/corpora/
    python benchmark/run_realworld_benchmark.py --name lwip

Corpora are expected to already be cloned under benchmark/corpora/<name>/ (see
benchmark/corpora/CLONE.sh). Nothing here clones or mutates a repo.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from maishac.analyzers import run_scan  # noqa: E402
from maishac.analyzers.base import collect_c_files  # noqa: E402

CORPORA_DIR = REPO / "benchmark" / "corpora"

# (name, subpath-to-scan relative to corpora/<name>, [include-dir subpaths])
CORPORA = [
    {"name": "littlefs", "scan": ".", "include": ["."]},
    {"name": "lwip", "scan": "src/core", "include": ["src/include"]},
    {"name": "mbedtls", "scan": "library", "include": ["include"]},
    {"name": "zephyr-kernel", "scan": "kernel", "include": ["include", "kernel/include"]},
]

# Rule classes BENCHMARKS.md confirmed are dominated by configuration/include-path
# false positives on an out-of-the-box run — surfaced separately so a reviewer
# samples them first rather than treating them as defects.
FP_PRONE = {
    "MISRA-C:2012 Rule 8.4", "MISRA-C:2012 Rule 20.9", "MISRA-C:2012 Rule 17.3",
    "MISRA-C:2012 Rule 15.6", "MISRA-C:2012 Rule 17.2",
}


def _count_loc(files: list[Path]) -> int:
    n = 0
    for f in files:
        try:
            n += sum(1 for _ in f.open("r", encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return n


def scan_corpus(cfg: dict, only: list[str] | None = None) -> dict | None:
    base = CORPORA_DIR / cfg["name"]
    scan_dir = base / cfg["scan"]
    if not scan_dir.exists():
        return None
    include = [str(base / p) for p in cfg.get("include", []) if (base / p).exists()]
    files = collect_c_files([str(scan_dir)], base)
    loc = _count_loc(files)

    t0 = time.time()
    findings, used = run_scan([str(scan_dir)], base, only, include or None)
    elapsed = round(time.time() - t0, 1)

    by_sev = Counter(f.severity for f in findings)
    by_std = Counter(f.standard for f in findings)
    by_analyzer = Counter(f.analyzer for f in findings)
    by_rule = Counter(f.rule_id for f in findings)
    fp_prone = {r: c for r, c in by_rule.items() if r in FP_PRONE}

    return {
        "name": cfg["name"],
        "analyzers_used": used,
        "files": len(files),
        "loc": loc,
        "findings_total": len(findings),
        "findings_per_kloc": round(len(findings) / (loc / 1000), 1) if loc else 0,
        "elapsed_s": elapsed,
        "by_severity": dict(by_sev),
        "by_standard": dict(by_std),
        "by_analyzer": dict(by_analyzer),
        "top_rules": by_rule.most_common(15),
        "fp_prone_classes": fp_prone,
        "fp_prone_total": sum(fp_prone.values()),
        "include_paths_used": include,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", help="scan only this corpus")
    ap.add_argument("--analyzers", help="comma list, e.g. 'native,cppcheck' (default: all available)")
    ap.add_argument("--out", default=str(REPO / "benchmark" / "results" / "realworld_run.json"))
    args = ap.parse_args()

    todo = [c for c in CORPORA if not args.name or c["name"] == args.name]
    if args.analyzers:
        only = args.analyzers.split(",")
    else:
        only = None
    results, missing = [], []

    def _flush(res, miss):
        payload = {"corpora": res, "missing": miss, "analyzers_requested": only,
                   "note": "No ground truth for real corpora; numbers are distribution/"
                           "density, not recall/precision. FP-prone classes per BENCHMARKS.md."}
        Path(args.out).write_text(json.dumps(payload, indent=2), "utf-8")

    for cfg in todo:
        print(f"[scan] {cfg['name']} ...", flush=True)
        r = scan_corpus(cfg, only)
        if r is None:
            missing.append(cfg["name"])
            print(f"[skip] {cfg['name']}: not cloned under benchmark/corpora/{cfg['name']}/", flush=True)
            _flush(results, missing)
            continue
        results.append(r)
        print(f"=== {r['name']}  ({r['analyzers_used']}) ===")
        print(f"  files={r['files']}  loc={r['loc']}  findings={r['findings_total']}"
              f"  ({r['findings_per_kloc']}/kLOC)  in {r['elapsed_s']}s")
        print(f"  by severity: {r['by_severity']}")
        print(f"  by standard: {r['by_standard']}")
        print(f"  by analyzer: {r['by_analyzer']}")
        print(f"  FP-prone (config-driven) classes total: {r['fp_prone_total']} -> {r['fp_prone_classes']}")
        print(f"  top rules: {r['top_rules'][:8]}", flush=True)
        _flush(results, missing)  # persist after every corpus so nothing is lost

    print(f"\nWrote {args.out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
