"""Unit tests for the cppcheck and clang-tidy adapters' parsing/mapping logic.

These monkeypatch each analyzer's `_run` to feed synthetic tool output, so they
exercise the full parse-and-map path (MISRA id mapping, cppcheck-id -> CERT
mapping, generic fallthrough, severity mapping, the Windows drive-letter path
regression) WITHOUT needing cppcheck/clang-tidy installed — keeping the suite
green on any machine while covering code the direct-invocation tests skip.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from maishac.analyzers.cppcheck import CppcheckAnalyzer
from maishac.analyzers.clang_tidy import ClangTidyAnalyzer


def _proc(stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["x"], returncode=0,
                                       stdout=stdout, stderr=stderr)


CPPCHECK_XML = """\
<?xml version="1.0"?>
<results version="2">
  <cppcheck version="2.17.1"/>
  <errors>
    <error id="misra-c2012-10.1" severity="style" msg="misra violation">
      <location file="src/a.c" line="10" column="3"/>
    </error>
    <error id="nullPointer" severity="error" msg="Possible null pointer dereference: p">
      <location file="src/a.c" line="20" column="5"/>
    </error>
    <error id="unusedVariable" severity="style" msg="Unused variable: x">
      <location file="src/a.c" line="30" column="1"/>
    </error>
    <error id="someWarning" severity="warning" msg="a generic warning">
      <location file="src/a.c" line="40" column="1"/>
    </error>
    <error id="noLocationError" severity="error" msg="has no location element"/>
  </errors>
</results>
"""


def test_cppcheck_parses_and_maps(monkeypatch, tmp_path):
    an = CppcheckAnalyzer()
    monkeypatch.setattr(an, "_run", lambda cmd, timeout=300: _proc(stderr=CPPCHECK_XML))
    findings = an.analyze([Path("src/a.c")], tmp_path)
    by_rule = {f.rule_id: f for f in findings}

    # MISRA id mapped onto the knowledge base, with the summary filled in for the
    # placeholder "misra violation" message
    assert "MISRA-C:2012 Rule 10.1" in by_rule
    assert by_rule["MISRA-C:2012 Rule 10.1"].standard == "MISRA-C:2012"

    # cppcheck semantic id -> CERT rule
    assert "CERT EXP34-C" in by_rule
    assert by_rule["CERT EXP34-C"].standard == "CERT-C"

    # a plain warning survives as generic supporting evidence
    assert "cppcheck:someWarning" in by_rule

    # a 'style' id that maps to neither MISRA nor CERT and isn't error/warning
    # is dropped (not surfaced as noise)
    assert "cppcheck:unusedVariable" not in by_rule

    # an error with no <location> is skipped rather than crashing
    assert not any("noLocation" in r for r in by_rule)


def test_cppcheck_empty_files_returns_empty():
    assert CppcheckAnalyzer().analyze([], Path(".")) == []


def test_cppcheck_non_xml_output_is_tolerated(monkeypatch, tmp_path):
    an = CppcheckAnalyzer()
    # first call: no <results ...> so the addon-retry path triggers; both return junk
    monkeypatch.setattr(an, "_run", lambda cmd, timeout=300: _proc(stderr="garbage, not xml"))
    assert an.analyze([Path("src/a.c")], tmp_path) == []


CLANG_TIDY_OUT = r"""
D:\proj\src\a.c:12:9: warning: 'atoi' used to convert a string to an integer value [cert-err34-c]
D:\proj\src\a.c:18:5: warning: suspicious usage of something [bugprone-branch-clone]
D:\proj\src\a.c:25:3: error: use of undeclared identifier 'foo' [clang-diagnostic-error]
"""


def test_clang_tidy_parses_windows_paths_and_maps(monkeypatch, tmp_path):
    an = ClangTidyAnalyzer()
    monkeypatch.setattr(an, "_run", lambda cmd, timeout=600: _proc(stdout=CLANG_TIDY_OUT))
    findings = an.analyze([Path("src/a.c")], tmp_path)
    rules = {f.rule_id for f in findings}

    # the drive-letter path did NOT break the file:line:col split (the regression)
    assert len(findings) == 3
    # cert-err34-c mapped to the CERT rule
    assert "CERT ERR34-C" in rules
    # non-cert checks preserved as generic clang-tidy evidence
    assert "clang-tidy:bugprone-branch-clone" in rules
    assert "clang-tidy:clang-diagnostic-error" in rules
    # severity mapping: warning -> major, error -> critical
    sev = {f.rule_id: f.severity for f in findings}
    assert sev["clang-tidy:bugprone-branch-clone"] == "major"
    assert sev["clang-tidy:clang-diagnostic-error"] == "critical"


def test_clang_tidy_no_c_files_returns_empty(tmp_path):
    # only a header, no .c file -> analyzer skips
    assert ClangTidyAnalyzer().analyze([Path("src/a.h")], tmp_path) == []
