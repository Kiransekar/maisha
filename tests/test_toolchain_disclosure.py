"""A narrowed toolchain must never be silent.

Maisha's native analyzer is zero-dependency and always runs, so a scan on a bare
install *succeeds* — it just checks a fraction of the rules it knows about. A
clean result then reads exactly like a clean result from a full toolchain. These
tests pin the disclosure at every surface where a conclusion gets drawn: scan,
session start, the CLI, and the Guideline Enforcement Plan.
"""

import json
import subprocess
import sys

import pytest

from maishac.coverage import toolchain_status, toolchain_warning
from maishac.engine import LoopEngine
from maishac import report as report_mod

CLEAN_C = "#include <stdint.h>\n\nuint32_t add(uint32_t a, uint32_t b)\n{\n    return a + b;\n}\n"


def _project(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "clean.c").write_text(CLEAN_C, "utf-8")
    return LoopEngine(tmp_path)


# ----------------------------------------------------------------- the status
def test_status_reports_installed_and_missing():
    st = toolchain_status()
    assert "native" in st["installed"]          # always available, zero deps
    assert st["rules_enforced_total"] > 0
    assert 0 <= st["coverage_pct"] <= 100
    for gap in st["missing"]:
        assert gap["rules_lost"] > 0 and gap["needs"] and gap["examples"]


def test_explicitly_selecting_a_subset_is_reported_as_degraded():
    """Choosing native-only is legitimate, but it still narrows coverage and the
    result must say so — otherwise `--analyzers native` becomes a quiet way to
    make a project look compliant."""
    st = toolchain_status(selected=["native"])
    assert st["degraded"] is True
    assert st["selected"] == ["native"]


def test_warning_names_the_cost_and_refuses_to_imply_compliance():
    st = toolchain_status(selected=["native"])
    w = toolchain_warning(st)
    assert "does NOT mean the code is compliant" in w
    assert "maishac doctor" in w
    assert w.isascii(), "console output must survive a legacy Windows code page"


def test_full_toolchain_produces_no_warning():
    st = dict(toolchain_status(), degraded=False)
    assert toolchain_warning(st) == ""


# ------------------------------------------------------------------ the scan
def test_scan_result_carries_toolchain_block(tmp_path):
    out = _project(tmp_path).scan(["src"], ["native"])
    assert out["toolchain"]["degraded"] is True
    assert out["toolchain"]["rules_reachable"] < out["toolchain"]["rules_enforced_total"]


def test_a_clean_scan_still_warns(tmp_path):
    """The dangerous case: zero findings on a narrow toolchain. Silence here is
    what makes Maisha look stronger than it is."""
    out = _project(tmp_path).scan(["src"], ["native"])
    assert out["total_findings"] == 0
    assert "coverage_warning" in out


def test_session_hoists_the_warning_and_tells_the_agent(tmp_path):
    """A session start is the beginning of a whole compliance campaign, so the
    limitation must be top-level, not buried in the nested baseline."""
    out = _project(tmp_path).begin_session(["src"], {"analyzers": ["native"]})
    assert "coverage_warning" in out
    assert "coverage_warning" in out["guidance"]
    assert "not present" not in out["guidance"]


# ------------------------------------------------------------------- the GEP
def test_gep_lists_absent_analyzers_not_just_present_ones(tmp_path):
    """MISRA Compliance:2020 requires the plan to record how each guideline is
    enforced *including* where nothing covers it. A tool inventory listing only
    what happens to be installed reads as though the rest of the standard were
    checked and passed."""
    eng = _project(tmp_path)
    eng.scan(["src"], ["native"])
    tools = {t["tool"]: t for t in report_mod.enforcement_tools(eng.mem)}
    assert set(tools) >= {"native", "cppcheck", "clang-tidy", "compiler"}
    assert tools["native"]["status"] == "available"
    for name in ("cppcheck", "clang-tidy", "compiler"):
        if tools[name]["version"] == "not installed":
            assert "NOT INSTALLED" in tools[name]["status"]
            assert tools[name]["requires"]


def test_compiler_adapter_is_not_labelled_native_when_absent(tmp_path):
    """Its `requires` is None only because it resolves gcc/clang/cc dynamically;
    it is still an external dependency and must not inherit 'native'."""
    eng = _project(tmp_path)
    tools = {t["tool"]: t for t in report_mod.enforcement_tools(eng.mem)}
    if tools["compiler"]["version"] == "not installed":
        assert tools["compiler"]["kind"] == "external analyzer"


def test_gep_markdown_carries_an_explicit_incomplete_toolchain_notice(tmp_path):
    eng = _project(tmp_path)
    eng.scan(["src"], ["native"])
    md = report_mod.guideline_enforcement_markdown(eng.mem)
    absent = [t for t in report_mod.enforcement_tools(eng.mem)
              if t["version"] == "not installed"]
    if absent:
        assert "Toolchain incomplete" in md
        assert "not checked at all" in md
        assert (" were" if len(absent) > 1 else " was") + " not installed" in md


# ------------------------------------------------------------------- the CLI
def test_cli_scan_warns_on_stderr_and_keeps_stdout_pipeable(tmp_path):
    """stdout is JSON consumed by jq and CI steps, so the warning must not
    corrupt it — and must not be invisible either."""
    _project(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-m", "maishac", "--project", str(tmp_path),
         "scan", "src", "--analyzers", "native"],
        capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stderr
    parsed = json.loads(proc.stdout)          # stdout stayed valid JSON
    assert parsed["total_findings"] == 0
    assert "WARNING" in proc.stderr and "doctor" in proc.stderr


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
