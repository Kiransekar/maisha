"""MISRA Mandatory guidelines: detection, and the no-deviation guarantee.

Mandatory is the one MISRA category that admits no deviation at all
(MISRA Compliance:2020). Before this suite the knowledge base contained zero
mandatory rules, which meant the engine's mandatory-blocking paths were dead
code that had never had data flow through them.
"""

import pytest

from maishac.analyzers.native import NativeAnalyzer
from maishac.coverage import analyzers_for, NATIVE_PARTIAL
from maishac.memory import MemoryStore, MandatoryRuleError
from maishac.rules import REGISTRY

# MISRA C:2012 + Amendment 1/2. The AMD3/AMD4 mandatory guidelines (7.5, 9.7,
# 17.9, 18.10, 21.22, 22.12, 22.14, 22.20) are intentionally out of scope.
MANDATORY = {
    "Rule 9.1", "Rule 12.5", "Rule 13.6", "Rule 17.3", "Rule 17.4", "Rule 17.6",
    "Rule 19.1", "Rule 21.13", "Rule 21.17", "Rule 21.18", "Rule 21.19",
    "Rule 21.20", "Rule 22.2", "Rule 22.4", "Rule 22.5", "Rule 22.6",
}


def _scan(tmp_path, src: str, name: str = "m.c"):
    p = tmp_path / name
    p.write_text(src, "utf-8")
    return NativeAnalyzer().analyze([p], tmp_path)


def _rules(findings) -> set[str]:
    return {f.rule_id for f in findings}


# ------------------------------------------------------------------ knowledge
def test_mandatory_set_is_complete_and_categorised():
    got = {rid.split(" ", 1)[1] for rid in REGISTRY.all_ids("MISRA-C:2012")
           if REGISTRY.get(rid).get("category") == "mandatory"}
    assert got == MANDATORY


def test_mandatory_rules_are_blocker_severity():
    """Mandatory cannot be waived, so it must outrank everything in triage."""
    for num in MANDATORY:
        meta = REGISTRY.resolve(f"MISRA {num.split(' ', 1)[1]}")
        assert meta["severity"] == "blocker", f"{meta['id']} is {meta['severity']}"


def test_every_misra_rule_carries_decidability_and_scope():
    """Decidability is what tells an honest coverage table *why* a rule isn't
    natively detected. Directives are exempt from the classification."""
    for rid in REGISTRY.all_ids("MISRA-C:2012"):
        if not rid.startswith("MISRA-C:2012 Rule "):
            continue
        meta = REGISTRY.get(rid)
        assert isinstance(meta.get("decidable"), bool), f"{rid} has no decidable flag"
        assert meta.get("scope") in ("stu", "system"), f"{rid} has no scope"


def test_undecidable_rules_are_never_claimed_as_fully_detected_natively():
    """The native analyzer is lexical, so it can only ever implement a decidable
    slice of an Undecidable rule. Claiming such a rule outright is wrong by
    construction — it must be declared partial and explained, which is also what
    a MISRA Guideline Enforcement Plan requires."""
    bad = [rid for rid in REGISTRY.all_ids("MISRA-C:2012")
           if rid.startswith("MISRA-C:2012 Rule ")
           and REGISTRY.get(rid).get("decidable") is False
           and "native" in analyzers_for(rid)
           and rid not in NATIVE_PARTIAL]
    assert not bad, f"native claims undecidable rules without declaring partial: {bad}"


def test_declared_partial_rules_explain_the_residual():
    """A partial declaration is only useful if it says what is *not* covered."""
    for rid, note in NATIVE_PARTIAL.items():
        assert REGISTRY.get(rid), f"{rid} is not in the KB"
        assert len(note) > 30, f"{rid}: partial note is too thin to be a GEP entry"


# ------------------------------------------------------------------ detection
def test_rule_12_5_sizeof_on_array_parameter(tmp_path):
    f = _scan(tmp_path, "unsigned long n(int a[10])\n{\n    return sizeof(a);\n}\n")
    assert "MISRA-C:2012 Rule 12.5" in _rules(f)


def test_rule_12_5_ignores_sizeof_of_an_element(tmp_path):
    """sizeof(a[0]) is the element size — legitimate, and the usual idiom."""
    f = _scan(tmp_path, "unsigned long n(int a[10])\n{\n    return sizeof(a[0]);\n}\n")
    assert "MISRA-C:2012 Rule 12.5" not in _rules(f)


def test_rule_12_5_ignores_a_genuine_local_array(tmp_path):
    f = _scan(tmp_path, "unsigned long n(void)\n{\n    int a[10];\n    return sizeof(a);\n}\n")
    assert "MISRA-C:2012 Rule 12.5" not in _rules(f)


@pytest.mark.parametrize("operand", ["i++", "--i", "i = 2"])
def test_rule_13_6_side_effect_in_sizeof(tmp_path, operand):
    f = _scan(tmp_path, f"void g(int i)\n{{\n    unsigned long n = sizeof({operand});\n"
                        "    (void)n;\n}\n")
    assert "MISRA-C:2012 Rule 13.6" in _rules(f)


@pytest.mark.parametrize("operand", ["int", "i", "a[i]", "struct s"])
def test_rule_13_6_accepts_side_effect_free_operands(tmp_path, operand):
    f = _scan(tmp_path, f"void g(int i, int a[4])\n{{\n"
                        f"    unsigned long n = sizeof({operand});\n    (void)n;\n}}\n")
    assert "MISRA-C:2012 Rule 13.6" not in _rules(f)


def test_rule_13_6_does_not_flag_call_syntax(tmp_path):
    """Without preprocessing, `F(x)` inside sizeof may be a macro expanding to a
    pure cast — lwip's `sizeof(ip_2_ip6(&x)->addr)` idiom. Flagging call syntax
    produced only false positives on the benchmark corpus, so it is delegated to
    cppcheck, which has the expansion."""
    f = _scan(tmp_path, "void g(void)\n{\n    unsigned long n = sizeof(ip_2_ip6(&s)->addr);\n"
                        "    (void)n;\n}\n")
    assert "MISRA-C:2012 Rule 13.6" not in _rules(f)


@pytest.mark.parametrize("qual", ["static", "const", "volatile", "restrict"])
def test_rule_17_6_qualifier_in_array_parameter(tmp_path, qual):
    f = _scan(tmp_path, f"void g(int buf[{qual} 10])\n{{\n    (void)buf;\n}}\n")
    assert "MISRA-C:2012 Rule 17.6" in _rules(f)


def test_rule_17_6_ignores_an_identifier_merely_starting_with_static(tmp_path):
    """`buf[static_offset]` is a subscript, not a qualifier — the word boundary
    has to hold, since underscore is a word character."""
    f = _scan(tmp_path, "void g(int *buf)\n{\n    buf[static_offset] = 0;\n}\n")
    assert "MISRA-C:2012 Rule 17.6" not in _rules(f)


def test_rule_17_4_is_not_claimed_natively():
    """17.4 needs a control-flow graph: a lexical version produced 69 hits on
    the benchmark corpus, dominated by macro-wrapped returns. It stays in the KB
    for cppcheck and for deviation records, but native must not claim it."""
    assert "native" not in analyzers_for("MISRA-C:2012 Rule 17.4")


# ---------------------------------------------------------------- no deviation
def test_mandatory_rule_cannot_be_deviated(tmp_path):
    mem = MemoryStore(tmp_path)
    with pytest.raises(MandatoryRuleError):
        mem.add_deviation("MISRA-C:2012 Rule 17.6", "*",
                          "we would rather not fix this right now", "lead@example.com")
    assert mem.deviations() == []


def test_non_mandatory_rule_can_still_be_deviated(tmp_path):
    mem = MemoryStore(tmp_path)
    did = mem.add_deviation("MISRA-C:2012 Rule 19.2", "drivers/**",
                            "hardware register overlay requires a union",
                            "lead@example.com")
    assert did and len(mem.deviations()) == 1


def test_mandatory_guard_applies_to_fuzzy_rule_references(tmp_path):
    """The guard resolves the reference itself, so an informal id can't slip a
    mandatory deviation past it."""
    mem = MemoryStore(tmp_path)
    with pytest.raises(MandatoryRuleError):
        mem.add_deviation("MISRA 22.2", "*", "justified: legacy allocator", "lead@example.com")


def test_mandatory_cannot_be_recategorized_away(tmp_path):
    """Recategorisation is the other route to waiving a rule; MISRA permits no
    target category for Mandatory."""
    from maishac.engine import LoopEngine
    out = LoopEngine(tmp_path).recategorize(
        "MISRA 17.6", "advisory", "we want this to be optional", "lead@example.com")
    assert "error" in out


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
