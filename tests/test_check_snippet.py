"""Proactive authoring aid: lint a draft snippet in memory, before it is written
to a file, so an agent can rewrite non-compliant lines on the spot."""

from maishac.engine import LoopEngine


def test_flags_draft_with_fix_hints_and_persists_nothing(tmp_path):
    eng = LoopEngine(tmp_path)
    out = eng.check_snippet(
        "int32_t f(void){\n"
        "    int *p = malloc(10);\n"   # 21.3 dynamic memory + Dir 4.6 basic type
        "    if (x > 5)\n"             # 15.6 unbraced body
        "        return 1;\n"
        "    return 0;\n"
        "}\n")
    assert out["clean"] is False
    rules = {f["rule_id"] for f in out["findings"]}
    assert "MISRA-C:2012 Rule 21.3" in rules and "MISRA-C:2012 Rule 15.6" in rules
    # every finding hands the agent a concrete remediation
    assert all(f["fix_hint"] for f in out["findings"])
    # in-memory only: nothing was scanned or stored
    assert eng.mem.open_findings() == []


def test_clean_snippet_reports_clean(tmp_path):
    eng = LoopEngine(tmp_path)
    out = eng.check_snippet("#include <stdint.h>\n"
                            "int32_t add(int32_t a, int32_t b)\n"
                            "{\n"
                            "    return a + b;\n"
                            "}\n")
    assert out["clean"] is True and out["findings"] == []


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
