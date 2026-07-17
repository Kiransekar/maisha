"""Property-based / fuzz tests for the native analyzer and fingerprinting.

BENCHMARK-SUITE-REPORT.md §9 lists "no fuzz-testing of the native analyzer
against malformed/adversarial C" as an uncovered area. These Hypothesis tests
close it: they assert the analyzer's *invariants* hold for arbitrary input
rather than checking specific findings —

  * the native analyzer never raises on any input (a lexer over untrusted source
    must degrade, not crash);
  * strip_comments_strings preserves total length and newline positions exactly
    (the code relies on this to keep (line, col) offsets valid);
  * enclosing_function never raises regardless of brace (im)balance;
  * a fingerprint is invariant under whitespace reflow (its whole purpose is to
    survive reformatting), and deterministic.
"""

from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")  # dev extra; skip cleanly if not installed
from hypothesis import given, settings, strategies as st  # noqa: E402

from maishac.analyzers.native import NativeAnalyzer, strip_comments_strings
from maishac.model import compute_fingerprint, enclosing_function

# Text biased toward C punctuation so the fuzzer actually reaches the checks,
# not just random letters.
c_ish = st.text(
    alphabet=st.sampled_from(list("{}()[];,/*\"'\\\n\t #ifdefngo01xX=<>!&|+-abcuint_ ")),
    max_size=400,
)


@settings(max_examples=300, deadline=None)
@given(src=c_ish)
def test_native_analyzer_never_crashes(src):
    findings = NativeAnalyzer().analyze_source(src, "fuzz.c", __import__("pathlib").Path("."))
    assert isinstance(findings, list)


@settings(max_examples=300, deadline=None)
@given(src=st.text(max_size=500))
def test_native_analyzer_never_crashes_on_arbitrary_unicode(src):
    findings = NativeAnalyzer().analyze_source(src, "fuzz.c", __import__("pathlib").Path("."))
    assert isinstance(findings, list)


def _nl_positions(s):
    return [i for i, c in enumerate(s) if c == "\n"]


def test_strip_backslash_escapes_preserve_length_and_newlines():
    """Two escape-handling bugs the fuzzer found in strip_comments_strings, pinned:
      #3  a trailing backslash at EOF escapes nothing — must not grow the output;
      #4  a backslash-escaped NEWLINE inside a literal (line continuation) must
          keep its newline in the stripped view, or every later line/column
          position shifts (CI falsifying example had a newline at index 2).
    The stripper must preserve BOTH total length and every newline position."""
    cases = [
        '"\\', "'\\", 'x = "abc\\', "c = '\\",        # #3 trailing backslash
        '"\\\n', "'\\\n'", 'a = "x\\\ny";\n', "'\\\n' + z",  # #4 escaped newline
    ]
    for src in cases:
        out = strip_comments_strings(src)
        assert len(out) == len(src), f"length changed for {src!r}"
        assert _nl_positions(out) == _nl_positions(src), f"newline moved for {src!r}"


@settings(max_examples=500, deadline=None)
@given(src=c_ish)
def test_strip_preserves_length_and_newlines(src):
    """The stripper blanks comment/string content but must keep every character
    position (and thus every newline) so line/column reporting stays correct."""
    out = strip_comments_strings(src)
    assert len(out) == len(src)
    assert [i for i, c in enumerate(out) if c == "\n"] == \
           [i for i, c in enumerate(src) if c == "\n"]


@settings(max_examples=200, deadline=None)
@given(lines=st.lists(st.text(max_size=40), max_size=30),
       idx=st.integers(min_value=0, max_value=29))
def test_enclosing_function_never_crashes(lines, idx):
    if not lines:
        return
    sym = enclosing_function(lines, min(idx, len(lines) - 1))
    assert isinstance(sym, str)


# non-whitespace tokens, joined below by arbitrary whitespace runs
token = st.text(alphabet=st.characters(blacklist_categories=("Cc", "Cs", "Zs"),
                                       blacklist_characters="\n\r\t "),
                min_size=1, max_size=8)
ws = st.text(alphabet=st.sampled_from([" ", "\t"]), min_size=1, max_size=4)


@settings(max_examples=300, deadline=None)
@given(tokens=st.lists(token, min_size=1, max_size=6),
       gaps=st.lists(ws, min_size=6, max_size=6),
       pad_l=st.text(alphabet=" \t", max_size=4),
       pad_r=st.text(alphabet=" \t", max_size=4))
def test_fingerprint_invariant_under_whitespace_reflow(tokens, gaps, pad_l, pad_r):
    """The fingerprint keys on whitespace-normalized content, so two spellings of
    the same line that differ only in whitespace must fingerprint identically —
    this is what lets a finding survive reformatting."""
    canonical = " ".join(tokens)
    reflowed = pad_l + gaps[0].join(tokens) + pad_r
    a = compute_fingerprint("R", "f.c", canonical, "fn")
    b = compute_fingerprint("R", "f.c", reflowed, "fn")
    assert a == b


@settings(max_examples=200, deadline=None)
@given(rule=token, path=token, line=st.text(max_size=60), sym=token)
def test_fingerprint_is_deterministic(rule, path, line, sym):
    assert compute_fingerprint(rule, path, line, sym) == \
           compute_fingerprint(rule, path, line, sym)
