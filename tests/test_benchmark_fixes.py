"""Regression tests for the three tool bugs BENCHMARKS.md surfaced against the
FreeRTOS kernel run: missing include-path forwarding, the MISRA 17.2
(recursion) false positive from a context-fragile enclosing-function
heuristic, and the MISRA 15.6 (braceless body) false positive from
preprocessor-blindness.
"""

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
