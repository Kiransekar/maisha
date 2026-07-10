#!/usr/bin/env python
"""CLI end-to-end (real subprocess, not direct engine calls — catches
argparse/wiring bugs unit tests miss) + edge cases + a performance timing
run against a large synthetic file.

Usage (from repo root): python benchmark/run_cli_and_edge_cases.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

WORK = ROOT / "benchmark" / "results" / "_cli_workdir"
RESULTS = ROOT / "benchmark" / "results"

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {label}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def run_cli(args: list[str], cwd: Path, timeout: int = 60) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-m", "maishac.cli", "--project", str(cwd)] + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))


# ============================================================ CLI E2E =======
def cli_end_to_end() -> None:
    print("\n" + "=" * 78)
    print("CLI END-TO-END (real subprocess invocations)")
    print("=" * 78)

    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "src").mkdir(parents=True)
    for f in (ROOT / "benchmark" / "firmware").glob("*"):
        shutil.copy(f, WORK / "src" / f.name)

    r = run_cli(["scan", "src"], WORK)
    check("scan exits 0", r.returncode == 0, r.stderr[-300:])
    scan_out = json.loads(r.stdout) if r.returncode == 0 else {}
    check("scan reports findings", scan_out.get("total_findings", 0) > 0)

    r = run_cli(["findings", "--limit", "5"], WORK)
    check("findings (human-readable) exits 0", r.returncode == 0, r.stderr[-300:])
    check("findings output looks like a table", "[" in r.stdout and "]" in r.stdout)

    r = run_cli(["findings", "--json", "--limit", "3"], WORK)
    check("findings --json exits 0 and parses", r.returncode == 0 and json_ok(r.stdout), r.stderr[-300:])

    r = run_cli(["rule", "MISRA 21.3"], WORK)
    check("rule lookup exits 0", r.returncode == 0, r.stderr[-300:])
    check("rule lookup finds cross refs", "equivalent_rules" in r.stdout)

    r = run_cli(["rule", "NOT-A-REAL-RULE-XYZ"], WORK)
    check("unknown rule exits nonzero", r.returncode != 0)
    check("unknown rule suggests closest matches on stderr", len(r.stderr.strip()) > 0)

    r = run_cli(["session", "begin", "src", "--verification-policy", "human_gated"], WORK)
    check("session begin exits 0", r.returncode == 0, r.stderr[-300:])
    begin_out = json.loads(r.stdout) if r.returncode == 0 else {}
    sid = begin_out.get("session_id")
    check("session begin returns a session_id", bool(sid))

    if sid:
        r = run_cli(["session", "begin", "src"], WORK)  # second begin, should be refused
        check("second concurrent session begin is refused", r.returncode == 0 and "error" in r.stdout)

        r = run_cli(["session", "batch", sid], WORK)
        check("session batch exits 0", r.returncode == 0, r.stderr[-300:])
        batch_out = json.loads(r.stdout) if r.returncode == 0 else {}
        check("session batch returns findings", len(batch_out.get("batch", [])) > 0)

        r = run_cli(["session", "status", sid], WORK)
        check("session status exits 0", r.returncode == 0, r.stderr[-300:])

        r = run_cli(["session", "verify", sid], WORK)
        check("session verify exits 0", r.returncode == 0, r.stderr[-300:])
        verify_out = json.loads(r.stdout) if r.returncode == 0 else {}
        check("session verify returns a state", verify_out.get("state") in
              ("active", "converged", "awaiting_verification", "stalled", "budget_exhausted"))

        fp = None
        rows = json.loads(run_cli(["findings", "--json", "--limit", "1"], WORK).stdout)
        if rows:
            fp = rows[0]["fingerprint"]
        if fp:
            r = run_cli(["approve", fp, "--by", "cli-test@example.com"], WORK)
            check("approve exits 0", r.returncode == 0, r.stderr[-300:])

            r = run_cli(["suppress", fp, "--reason", "cli end-to-end smoke test suppression"], WORK)
            check("suppress exits 0", r.returncode == 0, r.stderr[-300:])

    r = run_cli(["deviate", "MISRA 21.6", "--scope", "src/*",
                 "--justification", "printf routed to a UART logger shim in this build"], WORK)
    check("deviate exits 0", r.returncode == 0, r.stderr[-300:])

    r = run_cli(["deviate", "MISRA 21.6", "--scope", "src/*", "--justification", "too short"], WORK)
    check("deviate with a plausible justification still succeeds (no length gate on CLI path)",
          r.returncode == 0)

    r = run_cli(["note", "This project uses a UART logging shim instead of stdio", "--topic", "logging"], WORK)
    check("note exits 0", r.returncode == 0, r.stderr[-300:])

    for fmt in ("markdown", "json", "sarif"):
        r = run_cli(["report", "--format", fmt], WORK)
        check(f"report --format {fmt} exits 0", r.returncode == 0, r.stderr[-300:])
        if fmt == "sarif":
            check("sarif report is valid JSON", json_ok(r.stdout))

    r = run_cli(["import", str(ROOT / "benchmark" / "synthetic_qualified_engine.sarif.json")], WORK)
    check("import exits 0", r.returncode == 0, r.stderr[-300:])

    r = run_cli(["scan", "does/not/exist"], WORK)
    check("scan of a nonexistent path does not crash", r.returncode == 0, r.stderr[-300:])
    if r.returncode == 0:
        out = json.loads(r.stdout)
        check("scan of a nonexistent path reports 0 files scanned", out.get("files_scanned") == 0)


def json_ok(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except Exception:
        return False


# ============================================================ EDGE CASES ====
def edge_cases() -> None:
    print("\n" + "=" * 78)
    print("EDGE CASES")
    print("=" * 78)

    from maishac.analyzers.native import NativeAnalyzer

    d = RESULTS / "_edge_cases"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)

    empty = d / "empty.c"
    empty.write_text("", "utf-8")
    try:
        findings = NativeAnalyzer().analyze([empty], d)
        check("empty file does not crash", True)
        check("empty file yields no findings", len(findings) == 0)
    except Exception as e:
        check("empty file does not crash", False, repr(e))

    bom_file = d / "bom.c"
    bom_file.write_bytes(b"\xef\xbb\xbf" + b"void f(void) { int x = 010; }\n")
    try:
        findings = NativeAnalyzer().analyze([bom_file], d)
        check("UTF-8 BOM file does not crash", True)
    except Exception as e:
        check("UTF-8 BOM file does not crash", False, repr(e))

    latin1_file = d / "latin1.c"
    latin1_file.write_bytes(b"/* commentaire avec accents: \xe9\xe8\xe0 */\nvoid f(void) {}\n")
    try:
        findings = NativeAnalyzer().analyze([latin1_file], d)
        check("non-UTF-8 (Latin-1) bytes do not crash (errors='replace')", True)
    except Exception as e:
        check("non-UTF-8 (Latin-1) bytes do not crash", False, repr(e))

    crlf_file = d / "crlf.c"
    crlf_file.write_bytes(b"void f(void)\r\n{\r\n    int x = 010;\r\n}\r\n")
    try:
        findings = NativeAnalyzer().analyze([crlf_file], d)
        rules = {f.rule_id for f in findings}
        check("CRLF file does not crash", True)
        check("CRLF file still detects the octal literal (MISRA 7.1)",
              "MISRA-C:2012 Rule 7.1" in rules)
    except Exception as e:
        check("CRLF file does not crash", False, repr(e))

    long_line_file = d / "longline.c"
    long_line_file.write_text("void f(void) {\n    int x = " + "1" * 500 + ";\n}\n", "utf-8")
    try:
        findings = NativeAnalyzer().analyze([long_line_file], d)
        check("500-char single line does not crash", True)
    except Exception as e:
        check("500-char single line does not crash", False, repr(e))

    weird_name_dir = d / "path with spaces"
    weird_name_dir.mkdir()
    weird_file = weird_name_dir / "a b.c"
    weird_file.write_text("void f(void) { int x = 010; }\n", "utf-8")
    try:
        findings = NativeAnalyzer().analyze([weird_file], d)
        check("path containing spaces does not crash", True)
    except Exception as e:
        check("path containing spaces does not crash", False, repr(e))


# ============================================================ PERFORMANCE ===
def performance_timing() -> None:
    print("\n" + "=" * 78)
    print("PERFORMANCE — synthetic large file")
    print("=" * 78)

    from maishac.analyzers.native import NativeAnalyzer

    d = RESULTS / "_perf"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)

    big = d / "big.c"
    lines = ["#include <stdint.h>", ""]
    n_functions = 2000
    for i in range(n_functions):
        lines.append(f"int32_t fn_{i}(int32_t a, int32_t b)")
        lines.append("{")
        lines.append(f"    int32_t r = a + b;   /* line {i} */")
        if i % 7 == 0:
            lines.append("    int mode = 010;")  # seeded octal violation every 7th fn
        lines.append("    return r;")
        lines.append("}")
        lines.append("")
    big.write_text("\n".join(lines), "utf-8")
    total_lines = len(lines)
    size_kb = big.stat().st_size / 1024

    t0 = time.monotonic()
    findings = NativeAnalyzer().analyze([big], d)
    elapsed = time.monotonic() - t0

    print(f"  Synthetic file: {n_functions} functions, {total_lines} lines, {size_kb:.0f} KB")
    print(f"  Native analyzer time: {elapsed:.3f}s  ({len(findings)} findings)")
    expected_octal = (n_functions + 6) // 7
    check("native analyzer completes in well under 30s on a ~14k-line file",
          elapsed < 30, f"took {elapsed:.1f}s")
    check("finds the expected number of seeded octal violations",
          sum(1 for f in findings if f.rule_id == "MISRA-C:2012 Rule 7.1") == expected_octal)

    return {"lines": total_lines, "size_kb": size_kb, "elapsed_s": elapsed, "findings": len(findings)}


def main() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    cli_end_to_end()
    edge_cases()
    perf = performance_timing()

    print("\n" + "=" * 78)
    if FAILURES:
        print(f"FAILURES ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
    else:
        print("ALL CHECKS PASSED.")

    (RESULTS / "cli_edge_perf_summary.json").write_text(
        json.dumps({"failures": FAILURES, "performance": perf}, indent=2), "utf-8")


if __name__ == "__main__":
    main()
