"""Author-time compliant-pattern library (Mode 1): proactive guidance + the
idiom attached to reactive check_snippet findings."""

from maishac import patterns
from maishac.rules import REGISTRY
from maishac.coverage import enforced_ids, reference_ids
from maishac.engine import LoopEngine


def test_every_pattern_rule_reference_resolves():
    """A dead cross-link would silently drop the idiom from a finding's briefing."""
    for p in patterns.PATTERNS:
        for ref in p["rules"]:
            assert REGISTRY.resolve(ref), f"{p['concern']}: unresolved rule '{ref}'"


def test_every_enforced_rule_has_a_compliant_pattern():
    """Every rule an analyzer can actually raise must carry an authoring idiom,
    so guidance/check can teach a fix for anything the harness reports.

    Scoped to the *enforced* tier deliberately. Reference-tier rules (nothing
    detects them; they exist for cross-standard equivalence, deviation records,
    GEP rows and SARIF import mapping) may carry a pattern but don't have to —
    holding them to the same bar would make the knowledge base impossible to
    grow past a couple of hundred entries without inventing idioms for rules we
    never surface. If a *detectable* rule ships without a pattern, this fails.
    """
    patterns._BY_RULE = None  # rebuild index
    covered = set(patterns._index())
    missing = sorted(r for r in enforced_ids() if r not in covered)
    assert not missing, f"enforced rules with no authoring pattern: {missing}"


def test_reference_tier_rules_still_carry_fix_guidance():
    """A reference rule earns its place only if it can still explain itself —
    `maishac rule <id>` and the GEP row both read these fields."""
    thin = [r for r in reference_ids()
            if not (REGISTRY.get(r).get("summary") and REGISTRY.get(r).get("fix"))]
    assert not thin, f"reference rules missing summary/fix: {sorted(thin)}"


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
