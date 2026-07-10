"""MISRA Compliance:2020 Guideline Compliance Summary — the auditor deliverable
built on the deviation register + finding lifecycle."""

import shutil
from pathlib import Path

from maishac.engine import LoopEngine
from maishac import report as report_mod

FIXTURE = Path(__file__).resolve().parent.parent / "examples" / "bad.c"


def _project(tmp_path):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    shutil.copy(FIXTURE, proj / "src" / "bad.c")
    eng = LoopEngine(proj)
    eng.scan(["src"], ["native"])
    return eng


def test_fresh_scan_is_non_compliant_with_coverage_disclosed(tmp_path):
    eng = _project(tmp_path)
    s = report_mod.misra_compliance_summary(eng.mem)
    assert s["verdict"].startswith("NON-COMPLIANT")
    assert s["counts"]["violations"] > 0
    # Coverage is disclosed honestly, never counted as compliant.
    assert s["enforced"] == 31 and s["not_checked"] > 0
    assert s["enforced"] + s["not_checked"] == s["universe"]


def test_deviation_moves_a_guideline_out_of_violation(tmp_path):
    eng = _project(tmp_path)
    violated = [g["guideline"] for g in report_mod.misra_compliance_summary(eng.mem)["guidelines"]
                if g["status"] == "Violations"]
    target = violated[0]

    eng.mem.add_deviation(target, "src/**", "reviewed by safety lead",
                          approver="lead@example.com", expires_days=365)
    s = report_mod.misra_compliance_summary(eng.mem)
    row = next(g for g in s["guidelines"] if g["guideline"] == target)
    # Retroactive re-bucket: no rescan needed for the report to reflect the permit.
    assert row["status"] == "Deviations" and row["open"] == 0 and row["deviated"] > 0
    assert any(d["rule_id"] == target for d in s["deviation_permits"])

    md = report_mod.misra_compliance_markdown(eng.mem, "demo")
    assert target in md and "lead@example.com" in md and "Deviation permits" in md


def test_all_violations_deviated_flips_verdict(tmp_path):
    eng = _project(tmp_path)
    for g in report_mod.misra_compliance_summary(eng.mem)["guidelines"]:
        if g["status"] == "Violations":
            eng.mem.add_deviation(g["guideline"], "*", "blanket demo deviation",
                                  approver="lead@example.com", expires_days=365)
    s = report_mod.misra_compliance_summary(eng.mem)
    assert s["counts"]["violations"] == 0
    assert s["verdict"] == "COMPLIANT WITH DEVIATIONS"


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
