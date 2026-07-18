"""GEP (Guideline Enforcement Plan) + GRP (Guideline Re-categorization Plan) —
the two MISRA Compliance:2020 evidence documents that join the GCS."""

import shutil
from pathlib import Path

from maishac.engine import LoopEngine
from maishac import report as report_mod
from maishac.rules import REGISTRY

FIXTURE = Path(__file__).resolve().parent.parent / "examples" / "bad.c"


def _scanned(tmp_path):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    shutil.copy(FIXTURE, proj / "src" / "bad.c")
    eng = LoopEngine(proj)
    eng.scan(["src"], ["native"])
    return eng


# ---- GEP --------------------------------------------------------------------

def test_gep_records_tool_inventory_and_coverage(tmp_path):
    eng = _scanned(tmp_path)
    gep = report_mod.guideline_enforcement_plan(eng.mem)
    tools = {t["tool"]: t for t in gep["tools"]}
    assert "native" in tools and tools["native"]["version"].startswith("maishac ")
    assert gep["enforced"] == len(REGISTRY.all_ids("MISRA-C:2012"))
    assert gep["not_checked"] > 0
    # every enforced guideline gets a method + at least one checking tool
    assert gep["guidelines"] and all(r["method"] == "Static analysis" for r in gep["guidelines"])
    assert all(r["checked_by"] for r in gep["guidelines"])
    # a guideline with an observed finding is marked as observed, not just configured
    observed = [r for r in gep["guidelines"] if r["evidence"].startswith("observed")]
    assert observed, "no guideline showed observed detection evidence"

    md = report_mod.guideline_enforcement_markdown(eng.mem, "demo")
    assert "Guideline Enforcement Plan" in md and "native" in md and "not covered by this plan" in md


# ---- GRP legality (MISRA Compliance:2020 §5.4) ------------------------------

def test_grp_rejects_illegal_recategorizations(tmp_path):
    eng = _scanned(tmp_path)
    # Required -> Advisory is forbidden (21.3 is Required)
    r = eng.recategorize("MISRA 21.3", "advisory", "because")
    assert "error" in r and "Required" in r["error"]
    # Required -> Disapplied is forbidden
    assert "error" in eng.recategorize("MISRA 21.3", "disapplied", "because")
    # unknown target category rejected
    assert "error" in eng.recategorize("MISRA 15.1", "banana", "because")
    # rationale required
    assert "error" in eng.recategorize("MISRA 15.1", "disapplied", "  ")
    # nothing was recorded
    assert eng.mem.recategorizations() == {}


def test_grp_allows_legal_recategorization_and_it_flows_into_gcs(tmp_path):
    eng = _scanned(tmp_path)
    # Advisory -> Disapplied is permitted (15.1 is Advisory) and it has a violation
    before = report_mod.misra_compliance_summary(eng.mem)
    v_before = before["counts"]["violations"]
    row_before = next(g for g in before["guidelines"] if g["guideline"] == "MISRA-C:2012 Rule 15.1")
    assert row_before["status"] == "Violations"

    out = eng.recategorize("MISRA 15.1", "disapplied", "no gotos; disapplied by agreement",
                           approver="lead@example.com")
    assert out["to_category"] == "disapplied"

    after = report_mod.misra_compliance_summary(eng.mem)
    row = next(g for g in after["guidelines"] if g["guideline"] == "MISRA-C:2012 Rule 15.1")
    assert row["status"] == "Disapplied" and row["recategorized"] is True
    assert after["counts"]["disapplied"] == 1
    assert after["counts"]["violations"] == v_before - 1  # no longer a violation

    grp_md = report_mod.guideline_recategorization_markdown(eng.mem, "demo")
    assert "15.1" in grp_md and "disapplied" in grp_md and "lead@example.com" in grp_md


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
