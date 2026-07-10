"""Author-time compliant-pattern library (Mode 1): proactive guidance + the
idiom attached to reactive check_snippet findings."""

from maishac import patterns
from maishac.rules import REGISTRY
from maishac.engine import LoopEngine


def test_every_pattern_rule_reference_resolves():
    """A dead cross-link would silently drop the idiom from a finding's briefing."""
    for p in patterns.PATTERNS:
        for ref in p["rules"]:
            assert REGISTRY.resolve(ref), f"{p['concern']}: unresolved rule '{ref}'"


def test_every_kb_rule_has_a_compliant_pattern():
    """Full coverage: each of the 81 KB rules maps to at least one authoring
    idiom, so guidance/check can teach a fix for anything the harness knows.
    If a rule is added to the KB without a pattern, this fails."""
    patterns._BY_RULE = None  # rebuild index
    covered = set(patterns._index())
    missing = [r for r in REGISTRY.all_ids() if r not in covered]
    assert not missing, f"KB rules with no authoring pattern: {missing}"


def test_guidance_finds_idioms_by_topic():
    g = patterns.guidance("dynamic memory")
    assert g and g[0]["concern"] == "dynamic memory allocation"
    top = g[0]
    assert "static" in top["prefer"] and "malloc" in top["avoid"]
    # returned rule ids are canonical (resolvable), not the fuzzy input forms
    assert "MISRA-C:2012 Rule 21.3" in top["rules"]
    assert all(REGISTRY.get(r) for r in top["rules"])


def test_guidance_matches_by_keyword_and_rule_id():
    assert any(p["concern"] == "string buffers and copying"
               for p in patterns.guidance("strcpy"))
    assert any(p["concern"] == "switch default case"
               for p in patterns.guidance("16.4"))
    assert patterns.guidance("") == []


def test_check_snippet_attaches_compliant_idiom(tmp_path):
    eng = LoopEngine(tmp_path)
    out = eng.check_snippet("void f(char *s){ char n[16]; strcpy(n, s); }\n")
    withpat = [f for f in out["findings"] if "compliant_pattern" in f]
    assert withpat, "no finding carried a compliant pattern"
    assert "snprintf" in withpat[0]["compliant_pattern"]["prefer"]


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
