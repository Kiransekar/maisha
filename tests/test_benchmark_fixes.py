"""Regression tests for the three tool bugs BENCHMARKS.md surfaced against the
FreeRTOS kernel run: missing include-path forwarding, the MISRA 17.2
(recursion) false positive from a context-fragile enclosing-function
heuristic, and the MISRA 15.6 (braceless body) false positive from
preprocessor-blindness. Also covers a Windows-specific clang-tidy parsing bug
found by the benchmark/ suite (see BENCHMARK-SUITE-REPORT.md).
"""

import time
from pathlib import Path

from maishac.analyzers.native import NativeAnalyzer
from maishac.analyzers.cppcheck import CppcheckAnalyzer
from maishac.analyzers.clang_tidy import ClangTidyAnalyzer
from maishac.model import enclosing_function


# --------------------------------------------------------------- include paths
def test_cppcheck_forwards_include_paths(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, timeout=300):
        calls.append(cmd)
        class R:
            stderr = "<results><cppcheck version=\"1\"/></results>"
            stdout = ""
        return R()

    monkeypatch.setattr(CppcheckAnalyzer, "_run", staticmethod(fake_run))
    src = tmp_path / "a.c"
    src.write_text("void f(void) {}\n")
    CppcheckAnalyzer().analyze([src], tmp_path, include_paths=["inc", "vendor/inc"])
    assert calls, "cppcheck was never invoked"
    assert "-Iinc" in calls[0]
    assert "-Ivendor/inc" in calls[0]


def test_cppcheck_with_no_include_paths_omits_flag(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, timeout=300):
        calls.append(cmd)
        class R:
            stderr = "<results><cppcheck version=\"1\"/></results>"
            stdout = ""
        return R()

    monkeypatch.setattr(CppcheckAnalyzer, "_run", staticmethod(fake_run))
    src = tmp_path / "a.c"
    src.write_text("void f(void) {}\n")
    CppcheckAnalyzer().analyze([src], tmp_path)
    assert not any(c.startswith("-I") for c in calls[0])


def test_clang_tidy_forwards_include_paths(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, timeout=300):
        calls.append(cmd)
        class R:
            stdout = ""
            stderr = ""
        return R()

    monkeypatch.setattr(ClangTidyAnalyzer, "_run", staticmethod(fake_run))
    src = tmp_path / "a.c"
    src.write_text("void f(void) {}\n")
    ClangTidyAnalyzer().analyze([src], tmp_path, include_paths=["inc"])
    assert calls, "clang-tidy was never invoked"
    assert "-Iinc" in calls[0]
    # include flags must come after the '--' compiler-args separator
    assert calls[0].index("-Iinc") > calls[0].index("--")


def test_clang_tidy_parses_windows_drive_letter_paths(tmp_path, monkeypatch):
    """benchmark/ suite finding: clang-tidy always emits absolute paths in its
    diagnostics on Windows, e.g. "D:\\proj\\src\\a.c:20:5: warning: ... [check]".
    The old file-path regex ([^:\\n]+) treats the drive-letter colon as the
    line:col separator and fails to match ANY Windows diagnostic, silently
    dropping nearly every clang-tidy finding on that platform — verified by
    running clang-tidy directly on a real fixture set and diffing against
    Maisha's parsed output (see BENCHMARK-SUITE-REPORT.md)."""
    windows_output = (
        r"D:\proj\src\a.c:20:5: warning: Call to function 'strcpy' is insecure "
        r"[clang-analyzer-security.insecureAPI.strcpy]" + "\n"
        r"D:\proj\src\a.c:71:21: warning: 'atoi' used to convert a string "
        r"[bugprone-unchecked-string-to-number-conversion,cert-err34-c]" + "\n"
    )

    def fake_run(cmd, timeout=300):
        class R:
            stdout = windows_output
            stderr = ""
        return R()

    monkeypatch.setattr(ClangTidyAnalyzer, "_run", staticmethod(fake_run))
    src = tmp_path / "a.c"
    src.write_text("void f(void) { strcpy(0, 0); }\n")
    findings = ClangTidyAnalyzer().analyze([src], tmp_path)
    assert len(findings) == 2, findings
    assert findings[0].line == 20
    assert findings[1].rule_id == "CERT ERR34-C"
    assert findings[1].line == 71


def test_native_analyzer_accepts_and_ignores_include_paths(tmp_path):
    src = tmp_path / "a.c"
    src.write_text('void f(void){ char b[4]; strcpy(b, "x"); }\n')
    # must not raise, and must find the same findings regardless of the arg
    a = NativeAnalyzer().analyze([src], tmp_path)
    b = NativeAnalyzer().analyze([src], tmp_path, include_paths=["some/inc"])
    assert {f.fingerprint for f in a} == {f.fingerprint for f in b}


# ------------------------------------------------------- MISRA 17.2 recursion
def test_enclosing_function_skips_unmatched_multiline_header():
    """Reproduces the FreeRTOS FP: a call to `processData` from inside a
    *different* function whose signature spans multiple lines used to be
    mis-attributed to `processData` itself (the old heuristic ignored brace
    nesting and just grabbed the nearest line anywhere above that looked like
    a header), producing a false "processData calls itself"."""
    src = (
        "void processData(void)\n"
        "{\n"
        "    doStuff();\n"
        "}\n"
        "\n"
        "void handleRequestWithVeryLongSignature( int argOne,\n"
        "                                          int argTwo )\n"
        "{\n"
        "    processData();\n"
        "}\n"
    )
    lines = src.splitlines()
    call_idx = lines.index("    processData();")
    assert enclosing_function(lines, call_idx) == "handleRequestWithVeryLongSignature"


def test_no_recursion_false_positive_across_multiline_header(tmp_path):
    src = tmp_path / "a.c"
    src.write_text(
        "void processData(void)\n"
        "{\n"
        "    doStuff();\n"
        "}\n"
        "\n"
        "void handleRequestWithVeryLongSignature( int argOne,\n"
        "                                          int argTwo )\n"
        "{\n"
        "    processData();\n"
        "}\n"
    )
    findings = NativeAnalyzer().analyze([src], tmp_path)
    assert not any(f.rule_id == "MISRA-C:2012 Rule 17.2" for f in findings), \
        [f.message for f in findings if "17.2" in f.rule_id]


def test_real_recursion_still_detected(tmp_path):
    src = tmp_path / "a.c"
    src.write_text(
        "unsigned long factorial(unsigned long n)\n"
        "{\n"
        "    if (n <= 1)\n"
        "    {\n"
        "        return 1ul;\n"
        "    }\n"
        "    return n * factorial(n - 1u);\n"
        "}\n"
    )
    findings = NativeAnalyzer().analyze([src], tmp_path)
    assert any(f.rule_id == "MISRA-C:2012 Rule 17.2" for f in findings)


# --------------------------------------------------- MISRA 15.6 preprocessor
def test_no_15_6_false_positive_across_preprocessor_conditional(tmp_path):
    """Reproduces the FreeRTOS FP: an #if/#else/#endif sitting between a
    control header and its (actually braced) body used to defeat the
    "is the next line a brace?" check, 16/16 confirmed cases in the benchmark
    run."""
    src = tmp_path / "a.c"
    src.write_text(
        "void checkStatus(void)\n"
        "{\n"
        "    if (getValue() != 0)\n"
        "#if defined(FEATURE_X)\n"
        "    {\n"
        "        doA();\n"
        "    }\n"
        "#else\n"
        "    {\n"
        "        doB();\n"
        "    }\n"
        "#endif\n"
        "}\n"
    )
    findings = NativeAnalyzer().analyze([src], tmp_path)
    assert not any(f.rule_id == "MISRA-C:2012 Rule 15.6" for f in findings), \
        [f.message for f in findings if "15.6" in f.rule_id]


def test_real_missing_brace_still_detected_next_to_preprocessor_noise(tmp_path):
    src = tmp_path / "a.c"
    src.write_text(
        "void checkStatus(void)\n"
        "{\n"
        "    if (getValue() != 0)\n"
        "        doA();\n"
        "#if defined(FEATURE_X)\n"
        "    doB();\n"
        "#endif\n"
        "}\n"
    )
    findings = NativeAnalyzer().analyze([src], tmp_path)
    assert any(f.rule_id == "MISRA-C:2012 Rule 15.6" for f in findings)


# ------------------------------------------------------- recursion-check perf
def test_recursion_check_is_linear_not_quadratic(tmp_path):
    """benchmark/ suite finding: the old recursion check looped over EVERY
    function name seen so far for EVERY line (O(functions x lines)), turning
    a 2000-function/12k-line synthetic file into a 374s scan. Fixed by
    tracking only the current enclosing function via a brace-depth stack.
    A few hundred functions must scan in well under a second now."""
    lines = ["#include <stdint.h>", ""]
    n = 400
    for i in range(n):
        lines += [f"int32_t fn_{i}(int32_t a)", "{", "    return a + 1;", "}", ""]
    src = tmp_path / "many_functions.c"
    src.write_text("\n".join(lines), "utf-8")

    t0 = time.monotonic()
    findings = NativeAnalyzer().analyze([src], tmp_path)
    elapsed = time.monotonic() - t0

    assert elapsed < 5.0, f"took {elapsed:.1f}s for {n} functions — recursion check may have regressed to O(n^2)"
    assert not any(f.rule_id == "MISRA-C:2012 Rule 17.2" for f in findings)


def test_recursion_check_still_flags_real_recursion_at_scale(tmp_path):
    lines = ["#include <stdint.h>", ""]
    n = 200
    for i in range(n):
        lines += [f"int32_t fn_{i}(int32_t a)", "{", "    return a + 1;", "}", ""]
    lines += [
        "int32_t recurse_me(int32_t n)",
        "{",
        "    if (n == 0)",
        "    {",
        "        return 0;",
        "    }",
        "    return recurse_me(n - 1);",
        "}",
    ]
    src = tmp_path / "many_functions_with_recursion.c"
    src.write_text("\n".join(lines), "utf-8")
    findings = NativeAnalyzer().analyze([src], tmp_path)
    assert any(f.rule_id == "MISRA-C:2012 Rule 17.2" for f in findings)


# ------------------------------------------------------- Windows console I/O
def test_markdown_report_has_no_non_cp1252_characters(tmp_path):
    """benchmark/ suite finding: `maishac report --format markdown` crashed
    with UnicodeEncodeError on a default Windows console (cp1252) because the
    standards-matrix table used checkmark/cross/party emoji. A compliance
    report must be printable on any terminal or redirected into any log file
    — verify the generated markdown round-trips through cp1252 (encode with
    errors='strict') without needing errors='replace' to save it."""
    from maishac.memory import MemoryStore
    from maishac import report as report_mod

    mem = MemoryStore(tmp_path)
    md = report_mod.markdown_report(mem, project_name="encoding-test")
    md.encode("cp1252")  # raises UnicodeEncodeError if any non-cp1252 char slipped back in


# --------------------------------------------------- MISRA 18.8 (VLA) false positive
def test_no_18_8_false_positive_for_macro_sized_array(tmp_path):
    """benchmark/ suite finding: a fixed array sized by an ALL_CAPS macro
    constant (e.g. "uint8_t data[BUF_SIZE];" inside a struct) was
    misidentified as a variable-length array — confirmed twice across the
    benchmark fixtures (a very common embedded C pattern)."""
    src = tmp_path / "a.c"
    src.write_text(
        "#define BUF_SIZE 16\n"
        "void f(void)\n"
        "{\n"
        "    char buf[BUF_SIZE];\n"
        "    (void)buf;\n"
        "}\n"
    )
    findings = NativeAnalyzer().analyze([src], tmp_path)
    assert not any(f.rule_id == "MISRA-C:2012 Rule 18.8" for f in findings)


def test_genuine_vla_still_detected(tmp_path):
    src = tmp_path / "a.c"
    src.write_text(
        "void f(int n)\n"
        "{\n"
        "    char buf[n];\n"
        "    (void)buf;\n"
        "}\n"
    )
    findings = NativeAnalyzer().analyze([src], tmp_path)
    assert any(f.rule_id == "MISRA-C:2012 Rule 18.8" for f in findings)
