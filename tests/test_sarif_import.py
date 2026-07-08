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


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
