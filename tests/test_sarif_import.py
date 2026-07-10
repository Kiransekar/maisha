"""SARIF import: layer Maisha's memory/loop/gate on top of any SARIF-emitting
engine, including a qualified one (backlog §7)."""

import json
import shutil
from pathlib import Path

from maishac.engine import LoopEngine
from maishac import report as report_mod

FIXTURE = Path(__file__).resolve().parent.parent / "examples" / "bad.c"


def _sarif(results):
    return {"version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "ExternalQAC"}}, "results": results}]}


def _result(rule_id, uri, line, msg, level="warning"):
    return {"ruleId": rule_id, "level": level, "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line, "snippet": {"text": "p = malloc(10);"}}}}]}


def test_import_maps_known_rules_and_keeps_unknown(tmp_path):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    sf = proj / "ext.sarif"
    sf.write_text(json.dumps(_sarif([
        _result("misra-c2012-21.3", "src/a.c", 10, "dynamic memory"),
        _result("cert-err34-c", "src/a.c", 20, "unchecked atoi"),
        _result("someToolSpecificCheck", "src/a.c", 30, "tool-proprietary finding"),
    ])))

    eng = LoopEngine(proj)
    out = eng.import_sarif(str(sf))
    assert out["imported"] == 3
    assert out["tools"] == ["sarif:externalqac"]

    rules = {f["rule_id"] for f in eng.mem.open_findings()}
    assert "MISRA-C:2012 Rule 21.3" in rules   # misra-c2012-21.3 -> canonical
    assert "CERT ERR34-C" in rules             # cert-err34-c     -> canonical
    assert "sarif:someToolSpecificCheck" in rules  # unknown kept, not dropped


def test_imported_findings_survive_a_native_rescan(tmp_path):
    """A native scan that can't reproduce an imported (qualified-engine) finding
    must NOT mark it resolved — that would be silent data loss."""
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "a.c").write_text("#include <stdint.h>\nint32_t ok(void){ return 0; }\n")
    sf = proj / "ext.sarif"
    sf.write_text(json.dumps(_sarif([_result("misra-c2012-21.3", "src/a.c", 2, "dynamic memory")])))

    eng = LoopEngine(proj)
    eng.import_sarif(str(sf))
    fp = eng.mem.open_findings()[0]["fingerprint"]

    eng.scan(["src"], ["native"])   # native won't produce the imported finding
    f = eng.mem.get_finding(fp)
    assert f["status"] == "open", "imported finding was wrongly cleared by a native rescan"


def test_own_sarif_export_roundtrips(tmp_path):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    shutil.copy(FIXTURE, proj / "src" / "bad.c")
    eng = LoopEngine(proj)
    eng.scan(["src"], ["native"])
    exported = {f["fingerprint"] for f in eng.mem.open_findings(limit=10000)}

    doc = report_mod.sarif(eng.mem)
    reimport = tmp_path / "q"
    (reimport / "src").mkdir(parents=True)
    sf = reimport / "own.sarif"
    sf.write_text(json.dumps(doc))

    eng2 = LoopEngine(reimport)
    eng2.import_sarif(str(sf))
    got = {f["fingerprint"] for f in eng2.mem.open_findings(limit=10000)}
    # partialFingerprints carry Maisha identity across the round-trip
    assert exported and exported <= got


def test_code_flow_survives_import_and_reexport(tmp_path):
    """A qualified engine's data-flow path (codeFlows) must be preserved through
    import -> briefing -> re-export, not silently dropped (backlog §7 richer map)."""
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    res = _result("misra-c2012-21.3", "src/a.c", 30, "leak of allocated memory")
    res["codeFlows"] = [{"threadFlows": [{"locations": [
        {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/a.c"},
                                            "region": {"startLine": 10}},
                      "message": {"text": "allocated here"}}},
        {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/a.c"},
                                            "region": {"startLine": 30}},
                      "message": {"text": "leaked here"}}},
    ]}]}]
    sf = proj / "ext.sarif"
    sf.write_text(json.dumps(_sarif([res])))

    eng = LoopEngine(proj)
    eng.import_sarif(str(sf))
    f = eng.mem.open_findings()[0]
    flow = json.loads(f["code_flow"])
    assert [s["line"] for s in flow] == [10, 30]
    assert flow[0]["message"] == "allocated here"

    # the agent briefing exposes the flow, and it round-trips back out to SARIF
    doc = report_mod.sarif(eng.mem)
    r = next(x for x in doc["runs"][0]["results"] if x["ruleId"] == "MISRA-C:2012 Rule 21.3")
    steps = r["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [s["location"]["physicalLocation"]["region"]["startLine"] for s in steps] == [10, 30]


def test_export_emits_cross_standard_relationships(tmp_path):
    """Cross-standard equivalences are exported as SARIF rule relationships, and
    every relationship target resolves to a descriptor in the same run."""
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    sf = proj / "ext.sarif"
    sf.write_text(json.dumps(_sarif([_result("misra-c2012-21.3", "src/a.c", 10, "dynamic memory")])))
    eng = LoopEngine(proj)
    eng.import_sarif(str(sf))

    rules = report_mod.sarif(eng.mem)["runs"][0]["tool"]["driver"]["rules"]
    by_id = {r["id"]: r for r in rules}
    rel_owners = {rid: r for rid, r in by_id.items() if r.get("relationships")}
    assert rel_owners, "no cross-standard relationships emitted"
    for r in rel_owners.values():
        for rel in r["relationships"]:
            assert rel["target"]["id"] in by_id, "relationship target has no descriptor"


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
