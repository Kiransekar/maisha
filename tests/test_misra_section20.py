"""MISRA C:2012 section 20 — the preprocessor.

The densest block of Decidable / single-translation-unit rules in the standard,
and the one a lexical analyzer can implement most honestly: these rules are
*about* the token stream, so there is nothing semantic to miss.

Negative cases matter more than positives here. Real firmware is dense with
conditional compilation and macros, so a preprocessor check that misfires
produces noise on every file in the tree.
"""

import pytest

from maishac.analyzers.native import NativeAnalyzer, _logical_preproc
from maishac.coverage import analyzers_for
from maishac.rules import REGISTRY

SECTION_20 = [f"20.{n}" for n in
              (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)]


def _rules(tmp_path, src: str, name: str = "p.c") -> set[str]:
    p = tmp_path / name
    p.write_text(src, "utf-8")
    return {f.rule_id.split()[-1] for f in NativeAnalyzer().analyze([p], tmp_path)}


# ------------------------------------------------------------- knowledge base
def test_whole_of_section_20_is_carried():
    have = {r.split()[-1] for r in REGISTRY.all_ids("MISRA-C:2012")
            if r.startswith("MISRA-C:2012 Rule 20.")}
    assert have == set(SECTION_20)


def test_section_20_is_all_decidable_single_tu():
    """This is why the section is worth implementing natively at all."""
    for num in SECTION_20:
        meta = REGISTRY.resolve(f"MISRA {num}")
        assert meta["decidable"] is True and meta["scope"] == "stu", num


# --------------------------------------------------------- continuation lines
def test_logical_preproc_joins_backslash_continuations():
    """Most non-trivial embedded macros are multi-line; without joining, the
    body checks would only ever see the first line."""
    lines = ["#define WIDE(a, b) \\", "    do { (a); \\", "    (b); } while (0)", "int x;"]
    out = _logical_preproc(lines)
    assert len(out) == 1
    lineno, text = out[0]
    assert lineno == 1 and "while (0)" in text and "\\" not in text


# ----------------------------------------------------------- 20.2 header names
def test_rule_20_2_flags_a_backslash_in_a_header_name(tmp_path):
    assert "20.2" in _rules(tmp_path, '#include "driver\\uart.h"\n')


def test_rule_20_2_accepts_forward_slash_paths(tmp_path):
    """The compliant form of the same include, and overwhelmingly the common
    one -- a misfire here would hit almost every file in a real tree."""
    got = _rules(tmp_path, '#include "driver/uart.h"\n#include <sys/types.h>\n')
    assert "20.2" not in got


def test_rule_20_2_reads_the_raw_line_not_the_stripped_one(tmp_path):
    """strip_comments_strings blanks string *contents*, which is exactly where a
    header name lives. Reading the cleaned line would make this rule silently
    unable to ever fire."""
    assert "20.2" in _rules(tmp_path, '#include "a/*b.h"\n')


# ------------------------------------------------------- 20.3 well-formedness
def test_rule_20_3_flags_a_malformed_include(tmp_path):
    assert "20.3" in _rules(tmp_path, "#include\n")


@pytest.mark.parametrize("inc", ['#include <stdint.h>', '#include "local.h"',
                                 '#include HEADER_MACRO'])
def test_rule_20_3_accepts_every_well_formed_shape(tmp_path, inc):
    assert "20.3" not in _rules(tmp_path, inc + "\n")


# ------------------------------------------------------- 20.10 / 20.11 operators
def test_rule_20_10_flags_token_paste(tmp_path):
    assert "20.10" in _rules(tmp_path, "#define CAT(a, b) a ## b\n")


def test_rule_20_10_flags_stringize(tmp_path):
    assert "20.10" in _rules(tmp_path, "#define STR(x) #x\n")


def test_rule_20_10_ignores_a_hash_inside_a_string_literal(tmp_path):
    """Macro bodies are read from the cleaned line precisely so a '#' in a
    string is not mistaken for a stringize operator."""
    assert "20.10" not in _rules(tmp_path, '#define PROMPT "# "\n')


def test_rule_20_10_ignores_an_ordinary_object_like_macro(tmp_path):
    assert "20.10" not in _rules(tmp_path, "#define MAX_LEN 32u\n")


def test_rule_20_11_flags_hash_immediately_followed_by_paste(tmp_path):
    got = _rules(tmp_path, "#define BOTH(a) #a ## a\n")
    assert "20.11" in got


def test_rule_20_11_ignores_paste_alone(tmp_path):
    assert "20.11" not in _rules(tmp_path, "#define CAT(a, b) a ## b\n")


# ------------------------------------------------------- 20.13 valid directives
def test_rule_20_13_flags_an_unknown_directive(tmp_path):
    assert "20.13" in _rules(tmp_path, "#frobnicate 1\n")


@pytest.mark.parametrize("line", ["#include <a.h>", "#define A 1", "#undef A",
                                  "#if 1", "#ifdef A", "#ifndef A", "#else",
                                  "#elif 0", "#endif", "#pragma once",
                                  "#error nope", "#line 42"])
def test_rule_20_13_accepts_standard_directives(tmp_path, line):
    assert "20.13" not in _rules(tmp_path, f"{line}\n")


@pytest.mark.parametrize("line", ["#warning deprecated", "#include_next <a.h>",
                                  "#ident \"x\""])
def test_rule_20_13_tolerates_common_extensions(tmp_path, line):
    """Flagging these would bury real malformed-directive findings under noise
    in any real firmware tree. Reporting a language extension is Rule 1.2's
    job, not 20.13's."""
    assert "20.13" not in _rules(tmp_path, f"{line}\n")


def test_rule_20_13_accepts_the_null_directive(tmp_path):
    """A line containing only '#' is valid C."""
    assert "20.13" not in _rules(tmp_path, "#\n")


def test_rule_20_13_accepts_spaced_and_indented_directives(tmp_path):
    assert "20.13" not in _rules(tmp_path, "  #  define  A 1\n")


# ------------------------------------------------- rules left to cppcheck
@pytest.mark.parametrize("num", ["20.1", "20.6", "20.8", "20.9"])
def test_preprocessing_dependent_rules_are_not_claimed_natively(num):
    """None of these can be decided from one file's token stream.

    20.6 (directive inside macro arguments), 20.8 (condition essentially
    boolean) and 20.9 (every identifier a defined macro) need real
    preprocessing. 20.1 (#include before other code) needs to know which
    conditional branch is active: a branch-blind lexer counts code from the
    #if arm against an #include in the #else arm, and treats a C++-only
    `extern "C" {` as code in a C translation unit. That produced 820 corpus
    findings, all wrong. All four stay mapped to cppcheck."""
    assert "native" not in analyzers_for(f"MISRA-C:2012 Rule {num}")

# ------------------------------------- continuation lines are not directives
def test_a_stringize_opening_a_continuation_line_is_not_a_directive(tmp_path):
    """Inline-asm macros routinely begin a continuation line with a stringize
    operator, e.g. zephyr's `#CRm ", " #op2 : "=r" (val)`. Reading those as
    directives reported every one as an invalid directive name -- 5 findings on
    the benchmark corpus, all wrong."""
    src = (
        '#define READ_SYSREG(op1, CRn, CRm) \\\n'
        '    __asm__ volatile("mrc " #op1 ", " \\\n'
        '    #CRm : "=r" (val) :: "memory");\n'
    )
    assert "20.13" not in _rules(tmp_path, src)


def test_rule_20_11_ignores_a_two_step_paste(tmp_path):
    """`a ## NAME ## b` is a legal double paste. Matching the second character
    of the first ## as a stringize reported 109 corpus findings, all wrong."""
    assert "20.11" not in _rules(
        tmp_path, "#define FN(NAME) oid_ ## NAME ## _from_asn1\n")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
