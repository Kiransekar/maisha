"""`maishac doctor` — install/toolchain/project diagnostics.

The behaviour that matters is that doctor is *honest about a narrow install*:
a native-only machine is a supported mode and must exit 0, while a genuinely
broken one (unloadable KB, corrupt memory, cppcheck without its MISRA addon)
must exit non-zero so CI can gate on it.
"""

import json
import sqlite3
import subprocess
import sys

import pytest

from maishac import doctor
from maishac.engine import LoopEngine


def _flat(report):
    return [c for g in report["groups"] for c in g["checks"]]


def _by_name(report, needle):
    return [c for c in _flat(report) if needle in c["name"]]


# ------------------------------------------------------------------ structure
def test_diagnose_reports_every_group(tmp_path):
    report = doctor.diagnose(tmp_path)
    titles = [g["group"] for g in report["groups"]]
    assert titles == ["Environment", "Analyzers", "Rule coverage on this machine",
                      "Knowledge base", "Project"]
    assert report["summary"]["ok"] + report["summary"]["warnings"] \
        + report["summary"]["errors"] == len(_flat(report))


def test_every_check_is_well_formed(tmp_path):
    for c in _flat(doctor.diagnose(tmp_path)):
        assert c["status"] in (doctor.OK, doctor.WARN, doctor.ERROR)
        assert c["name"] and c["detail"]
        # A warning or error the user can't act on is noise.
        if c["status"] != doctor.OK and not c["name"].strip().startswith(
                ("reachable", "MISRA-C", "BARR-C", "CERT-C", "open findings")):
            assert c["hint"], f"{c['name']} has no remediation hint"


def test_native_only_install_is_healthy(tmp_path):
    """The zero-dependency path is a documented mode, not a failure. Narrow
    coverage must warn, never error — otherwise CI breaks on a valid setup."""
    report = doctor.diagnose(tmp_path)
    assert report["healthy"] is True
    reach = _by_name(report, "reachable rules")[0]
    assert reach["status"] in (doctor.OK, doctor.WARN)


def test_render_is_ascii_only(tmp_path):
    """A Windows console in a legacy code page turns non-ASCII into mojibake,
    which makes a diagnostic tool look broken exactly when it is being trusted."""
    text = doctor.render(doctor.diagnose(tmp_path))
    assert text.isascii(), [ln for ln in text.splitlines() if not ln.isascii()]


# -------------------------------------------------------------- knowledge base
def test_knowledge_base_integrity_is_clean():
    report = doctor.diagnose(".")
    for c in _by_name(report, "cross-standard references") + \
            _by_name(report, "authoring patterns") + \
            _by_name(report, "rule knowledge base"):
        assert c["status"] == doctor.OK, f"{c['name']}: {c['detail']}"


def test_cert_recommendations_are_not_reported_as_broken_links():
    """CERT ids numbered 00-29 are non-normative Recommendations that the KB
    deliberately does not carry. Pointing at one is intentional, not a defect."""
    report = doctor.diagnose(".")
    outside = _by_name(report, "references outside the subset")
    assert outside and outside[0]["status"] == doctor.OK
    assert "Recommendation" in outside[0]["detail"]


def test_mandatory_rules_are_reported():
    c = _by_name(doctor.diagnose("."), "MISRA mandatory rules")[0]
    assert c["status"] == doctor.OK and "16" in c["detail"]


# ------------------------------------------------------------------- project
def test_fresh_project_warns_that_memory_does_not_exist_yet(tmp_path):
    c = _by_name(doctor.diagnose(tmp_path), "project memory")[0]
    assert c["status"] == doctor.WARN and "scan" in c["hint"]


def test_scanned_project_reports_database_contents(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text(
        "void f(void)\n{\n    int *p = malloc(4);\n    free(p);\n}\n", "utf-8")
    LoopEngine(tmp_path).scan(["src"], ["native"])
    report = doctor.diagnose(tmp_path)
    db = _by_name(report, "memory database")[0]
    assert db["status"] == doctor.OK and "integrity ok" in db["detail"]
    assert "findings" in _by_name(report, "contents")[0]["detail"]


def test_corrupt_memory_database_is_an_error(tmp_path):
    (tmp_path / ".maishac").mkdir()
    (tmp_path / ".maishac" / "memory.db").write_bytes(b"this is not a sqlite file")
    report = doctor.diagnose(tmp_path)
    db = _by_name(report, "memory database")[0]
    assert db["status"] == doctor.ERROR
    assert report["healthy"] is False


def test_missing_gitignore_entry_warns(tmp_path):
    LoopEngine(tmp_path)  # creates .maishac
    c = _by_name(doctor.diagnose(tmp_path), "gitignored")[0]
    assert c["status"] == doctor.WARN
    (tmp_path / ".gitignore").write_text(".maishac/\n", "utf-8")
    assert _by_name(doctor.diagnose(tmp_path), "gitignored")[0]["status"] == doctor.OK


# ----------------------------------------------------------------------- CLI
def test_cli_doctor_runs_and_exits_zero_on_a_healthy_project(tmp_path):
    proc = subprocess.run([sys.executable, "-m", "maishac", "--project", str(tmp_path),
                           "doctor"], capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Rule coverage on this machine" in proc.stdout


def test_cli_doctor_json_is_machine_readable(tmp_path):
    proc = subprocess.run([sys.executable, "-m", "maishac", "--project", str(tmp_path),
                           "doctor", "--json"], capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads(proc.stdout)
    assert report["healthy"] is True and report["groups"]


def test_cli_doctor_exits_nonzero_when_something_is_broken(tmp_path):
    """CI gating depends on this: a broken install must fail the build."""
    (tmp_path / ".maishac").mkdir()
    (tmp_path / ".maishac" / "memory.db").write_bytes(b"corrupt")
    proc = subprocess.run([sys.executable, "-m", "maishac", "--project", str(tmp_path),
                           "doctor"], capture_output=True, text=True, timeout=180)
    assert proc.returncode == 1
    assert "[FAIL]" in proc.stdout


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
