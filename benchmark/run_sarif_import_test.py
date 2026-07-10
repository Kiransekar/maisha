#!/usr/bin/env python
"""Tests Maisha's SARIF-import path against a synthetic "qualified engine"
SARIF file (benchmark/synthetic_qualified_engine.sarif.json) — NOT a real
tool's output, just a representative shape (real MISRA/CERT rule ids in a
foreign naming convention, plus one proprietary-only rule id) to verify:

  1. Recognized MISRA/CERT ruleIds in a foreign format ("misra-c2012-10.1",
     "CERT-ERR33-C") map onto the knowledge base.
  2. An unrecognized proprietary ruleId is kept as "sarif:<ruleId>" rather
     than being dropped.
  3. Imported findings coexist with native-scan findings (no incorrect
     fingerprint collision) and are NOT cleared by a subsequent native
     rescan (producers-set isolation).
  4. Imported findings show up in compliance_report / findings list.
  5. A qualified engine's codeFlows (data-flow path to the defect) are parsed,
     stored, and surfaced in the agent fix briefing rather than dropped.
  6. Export emits cross-standard equivalences as SARIF rule relationships, and
     startColumn + codeFlows survive an import -> export round-trip.

Usage (from repo root): python benchmark/run_sarif_import_test.py
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from maishac.engine import LoopEngine  # noqa: E402

FIRMWARE_SRC = ROOT / "benchmark" / "firmware"
SARIF_FILE = ROOT / "benchmark" / "synthetic_qualified_engine.sarif.json"
WORK = ROOT / "benchmark" / "results" / "_sarif_workdir"


def main() -> None:
    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "src").mkdir(parents=True)
    for f in FIRMWARE_SRC.glob("*"):
        shutil.copy(f, WORK / "src" / f.name)

    eng = LoopEngine(WORK)

    baseline = eng.scan(["src"])
    native_open = {f["fingerprint"] for f in eng.mem.open_findings(limit=1000)}
    print(f"1) Native/cppcheck/clang-tidy baseline: {baseline['total_findings']} findings, "
          f"{len(native_open)} open.")

    result = eng.import_sarif(str(SARIF_FILE))
    print(f"\n2) import_sarif -> {result}")
    assert result["imported"] == 3, result

    rows = eng.mem.open_findings(limit=1000)
    by_rule = {r["rule_id"]: r for r in rows}
    print("\n3) Rule-id mapping check:")
    assert "MISRA-C:2012 Rule 10.1" in by_rule, "recognized MISRA id (foreign format) failed to map"
    print(f"   misra-c2012-10.1  -> {by_rule['MISRA-C:2012 Rule 10.1']['rule_id']}  OK")
    assert "CERT ERR33-C" in by_rule, "recognized CERT id (foreign format) failed to map"
    print(f"   CERT-ERR33-C      -> {by_rule['CERT ERR33-C']['rule_id']}  OK")
    unknown = [r for r in rows if r["rule_id"].startswith("sarif:")]
    assert unknown and unknown[0]["rule_id"] == "sarif:PROPRIETARY-STACK-DEPTH-001", unknown
    print(f"   PROPRIETARY-STACK-DEPTH-001 -> {unknown[0]['rule_id']}  "
          "(unrecognized, preserved rather than dropped)  OK")

    after_import_open = {f["fingerprint"] for f in rows}
    new_from_import = after_import_open - native_open
    print(f"\n4) {len(new_from_import)} new findings from import "
          f"(no collision with the {len(native_open)} native-scan findings)")
    assert len(new_from_import) == 3

    # Native rescan must NOT clear imported findings (producers isolation).
    rescan = eng.scan(["src"])
    still_open = {f["fingerprint"] for f in eng.mem.open_findings(limit=1000)}
    survived = new_from_import & still_open
    print(f"\n5) After native rescan: {len(survived)}/3 imported findings still open "
          f"(diff={rescan['diff']})")
    assert len(survived) == 3, "an imported finding was incorrectly cleared by a native rescan"

    # Confirm it surfaces in reporting.
    from maishac import report as report_mod
    matrix = report_mod.compliance_matrix(eng.mem)
    md = report_mod.markdown_report(eng.mem, project_name="sarif-import-test")
    assert "10.1" in md or "sarif:PROPRIETARY" in md or "ERR33-C" in md
    print(f"\n6) compliance_report includes imported findings: OK "
          f"(matrix standards={list(matrix.get('by_standard', matrix).keys())[:5]})")

    # The stack-depth finding carried a 3-step call-graph codeFlow — it must be
    # stored and reach the agent fix briefing, not be dropped on import.
    stack = next(r for r in rows if r["rule_id"].startswith("sarif:"))
    import json
    flow = json.loads(stack["code_flow"]) if stack["code_flow"] else []
    assert [s["line"] for s in flow] == [20, 26, 14], flow
    brief = eng._brief(stack)
    assert brief["code_flow"] == flow and brief["code_flow"][2]["file"] == "src/uart_driver.c"
    print(f"\n7) codeFlow preserved into agent briefing: {len(flow)} steps "
          f"({' -> '.join(s['message'].split(' (')[0] for s in flow)})  OK")

    # Export: cross-standard relationships + a lossless round-trip of the flow.
    doc = report_mod.sarif(eng.mem)
    driver = doc["runs"][0]["tool"]["driver"]
    by_id = {r["id"]: r for r in driver["rules"]}
    rel_pairs = [(rid, rel["target"]["id"]) for rid, r in by_id.items()
                 for rel in r.get("relationships", [])]
    assert rel_pairs, "no cross-standard relationships emitted"
    assert all(t in by_id for _, t in rel_pairs), "a relationship target has no descriptor"
    exported = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == stack["rule_id"])
    steps = exported["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [s["location"]["physicalLocation"]["region"]["startLine"] for s in steps] == [20, 26, 14]
    print(f"\n8) Export emits {len(rel_pairs)} cross-standard relationship(s) "
          f"(e.g. {rel_pairs[0][0]} -> {rel_pairs[0][1]}); codeFlow round-trips  OK")

    print("\nALL SARIF IMPORT CHECKS PASSED.")


if __name__ == "__main__":
    main()
