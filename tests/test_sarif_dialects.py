"""SARIF importer robustness against real qualified-engine dialects.

Real engines don't put the MISRA/CERT number in `ruleId` — they use a
checker-specific id (e.g. `ABV.GENERAL`), reference the rule by `ruleIndex`,
and attach the guideline via `relationships` into a `taxonomies` component
(Helix QAC / Coverity). They also emit non-defect results (`kind: pass`),
baseline `absent` results, `defaultConfiguration` levels, and scheme-prefixed
URIs. A naive importer keyed on `ruleId` breaks on all of these."""

from pathlib import Path

from maishac import report as report_mod


def _find(results, root=".", **run_extra):
    run = {"tool": {"driver": {"name": "Engine"}}, "results": results, **run_extra}
    return report_mod.parse_sarif({"version": "2.1.0", "runs": [run]}, Path(root))


def _loc(uri="src/a.c", line=10):
    return [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                  "region": {"startLine": line}}}]


def test_helix_qac_style_taxonomy_and_ruleindex_mapping(tmp_path):
    """ruleId is a checker id; the MISRA number is reached via ruleIndex ->
    driver.rules[].relationships -> taxonomies[].taxa[]."""
    run = {
        "tool": {"driver": {"name": "Helix QAC", "rules": [
            {"id": "ABV.GENERAL", "name": "ArrayBoundsViolation",
             "relationships": [{"target": {"index": 0, "toolComponent": {"index": 0}},
                                "kinds": ["subset"]}]},
        ]}},
        "taxonomies": [{"name": "MISRA C:2012", "taxa": [{"id": "Rule 21.3", "name": "21.3"}]}],
        "results": [{"ruleId": "ABV.GENERAL", "ruleIndex": 0,
                     "message": {"text": "dynamic allocation"}, "locations": _loc()}],
    }
    findings = report_mod.parse_sarif({"version": "2.1.0", "runs": [run]}, tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "MISRA-C:2012 Rule 21.3", "taxonomy mapping failed"


def test_relationship_target_by_id(tmp_path):
    """Some tools put the guideline id directly on relationship.target.id."""
    run = {
        "tool": {"driver": {"name": "QAC", "rules": [
            {"id": "MC3R1.R15.6",
             "relationships": [{"target": {"id": "Rule 15.6"}, "kinds": ["equal"]}]},
        ]}},
        "results": [{"rule": {"index": 0}, "message": {"text": "unbraced"}, "locations": _loc()}],
    }
    f = report_mod.parse_sarif({"version": "2.1.0", "runs": [run]}, tmp_path)
    assert f[0].rule_id == "MISRA-C:2012 Rule 15.6"


def test_result_level_taxa_and_coverity_bare_number(tmp_path):
    """taxa attached to the result, guideline as a bare number."""
    f = _find([{"ruleId": "MISRA_C_2012_R_16_4", "taxa": [{"id": "16.4"}],
                "message": {"text": "no default"}, "locations": _loc()}], root=str(tmp_path))
    assert f[0].rule_id == "MISRA-C:2012 Rule 16.4"


def test_non_defect_kinds_are_skipped():
    f = _find([
        {"ruleId": "cert-err33-c", "kind": "pass", "message": {"text": "ok"}, "locations": _loc()},
        {"ruleId": "cert-err33-c", "kind": "notApplicable", "message": {"text": "n/a"}, "locations": _loc()},
        {"ruleId": "cert-err33-c", "message": {"text": "real defect"}, "locations": _loc()},  # kind defaults to fail
    ])
    assert len(f) == 1 and f[0].rule_id == "CERT ERR33-C"


def test_baseline_absent_is_skipped():
    f = _find([
        {"ruleId": "cert-err33-c", "baselineState": "absent", "message": {"text": "gone"}, "locations": _loc()},
        {"ruleId": "cert-err33-c", "baselineState": "new", "message": {"text": "here"}, "locations": _loc()},
    ])
    assert len(f) == 1


def test_default_configuration_level_drives_severity_for_unknown_rule():
    run = {
        "tool": {"driver": {"name": "E", "rules": [
            {"id": "PROPRIETARY-X", "defaultConfiguration": {"level": "error"}},
        ]}},
        "results": [{"ruleIndex": 0, "message": {"text": "x"}, "locations": _loc()}],
    }
    f = report_mod.parse_sarif({"version": "2.1.0", "runs": [run]}, Path("."))
    assert f[0].rule_id == "sarif:PROPRIETARY-X" and f[0].severity == "critical"  # error -> critical


def test_uri_scheme_and_missing_region_are_tolerated():
    f = _find([
        {"ruleId": "cert-err33-c", "message": {"text": "a"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///proj/src/a.c"}}}]},  # no region
        {"ruleId": "cert-err33-c", "message": {"text": "b"}, "locations": []},  # no location at all
    ])
    assert len(f) == 2
    assert not f[0].file.startswith("file://")  # scheme stripped
    assert f[0].line == 0                        # missing region tolerated


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
