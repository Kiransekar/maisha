"""Issue #7: the gcc/clang compiler-warnings adapter.

Parsing/mapping is tested by feeding synthetic compiler output through a
monkeypatched `_run`, so it needs no compiler installed. Availability/graceful
degradation is tested directly. On a machine that *does* have gcc/clang the
adapter joins `analyzers_used` automatically (it's in ALL_ANALYZERS).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from maishac.analyzers.compiler import CompilerAnalyzer, WFLAG_TO_RULE
from maishac.analyzers import ALL_ANALYZERS
from maishac.rules import REGISTRY

# realistic gcc/clang -Wall -Wextra output (drive-letter path included on purpose)
GCC_OUT = r"""
D:\proj\src\a.c:12:9: warning: comparison of integer expressions of different signedness [-Wsign-compare]
D:\proj\src\a.c:20:5: warning: 'x' may be used uninitialized [-Wmaybe-uninitialized]
D:\proj\src\a.c:31:5: warning: comparing floating-point with '==' is unsafe [-Wfloat-equal]
D:\proj\src\a.c:40:5: warning: variable length array used [-Wvla]
D:\proj\src\a.c:55:1: warning: something the harness has no rule for [-Wpadded]
"""


def _proc(stdout="", stderr=""):
    return subprocess.CompletedProcess(["cc"], 0, stdout=stdout, stderr=stderr)


def test_registered_in_all_analyzers():
    assert CompilerAnalyzer in ALL_ANALYZERS


def test_every_wflag_target_resolves():
    for flag, ref in WFLAG_TO_RULE.items():
        assert REGISTRY.resolve(ref), f"-W{flag} -> '{ref}' does not resolve in the KB"


def test_maps_flags_to_rules_and_keeps_unmapped(monkeypatch, tmp_path):
    an = CompilerAnalyzer()
    # force one compiler present + feed canned output
    monkeypatch.setattr(CompilerAnalyzer, "_compiler", staticmethod(lambda: "gcc"))
    monkeypatch.setattr(an, "_run", lambda cmd, timeout=120: _proc(stderr=GCC_OUT))
    findings = an.analyze([Path("src/a.c")], tmp_path)
    rules = {f.rule_id for f in findings}

    # drive-letter path parsed; all five diagnostics captured
    assert len(findings) == 5
    assert "CERT INT31-C" in rules          # -Wsign-compare
    assert "CERT EXP33-C" in rules          # -Wmaybe-uninitialized
    assert "CERT FLP37-C" in rules          # -Wfloat-equal
    assert "MISRA-C:2012 Rule 18.8" in rules  # -Wvla
    # an unmapped flag survives as evidence rather than being dropped
    assert "compiler:-Wpadded" in rules
    assert all(f.analyzer == "compiler" for f in findings)


def test_degrades_gracefully_without_a_compiler(monkeypatch, tmp_path):
    monkeypatch.setattr(CompilerAnalyzer, "_compiler", staticmethod(lambda: None))
    an = CompilerAnalyzer()
    assert an.available() is False
    assert an.analyze([Path("src/a.c")], tmp_path) == []
