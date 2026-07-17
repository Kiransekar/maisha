"""The verification gate: a fix that only silenced the analyzer is NOT resolved
until a passing test run or a human confirms it (backlog §1/§5)."""

import sys
from pathlib import Path

from maishac.engine import LoopEngine
from maishac.memory import semantic_risk

# Cross-platform always-pass / always-fail test commands. The engine runs the
# configured test_command through subprocess with shell=True, which resolves to
# cmd.exe on Windows and /bin/sh on POSIX. The Unix shell builtins `true`/`false`
# are NOT cmd.exe commands, so hard-coding them makes these tests pass only where
# a `true`/`false` executable happens to be on PATH (Linux, Git Bash) and fail on
# a bare Windows shell. Driving the current interpreter is portable everywhere.
PASS_CMD = f'"{sys.executable}" -c "raise SystemExit(0)"'
FAIL_CMD = f'"{sys.executable}" -c "raise SystemExit(1)"'

# An unbraced control statement: the native analyzer flags MISRA Rule 15.6, which
# is semantic-risk — like the signed/unsigned sentinel example, a minimal edit can
# silence the rule while changing control flow at a boundary no rescan can see.
# (It also incidentally trips Dir 4.6, a minor, non-risk finding — handy below.)
RISKY = 'int f(int x)\n{\n    if (x > 0)\n        return 1;\n    return 0;\n}\n'
# A long line: minor, non-semantic-risk (BARR-C 3.1a) — a test pass may confirm it.
LONG = '    /* ' + 'x' * 90 + ' */\n'
CLEAN = '#include <stdint.h>\nint32_t ok(void)\n{\n    return 0;\n}\n'


def _proj(tmp_path, body):
    proj = tmp_path / "p"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "m.c").write_text(body)
    return proj


def _find(eng, rule_substr):
    for f in eng.mem.pending_findings() + eng.mem.open_findings(limit=1000):
        if rule_substr in f["rule_id"]:
            return f
    return None


def test_semantic_risk_classifier():
    assert semantic_risk("CERT FLP37-C", "if (a == b)")
    assert semantic_risk("MISRA-C:2012 Rule 15.6", "if (x > 0)")
    assert semantic_risk("CERT INT31-C", "y = (uint32_t)threshold;")
    assert not semantic_risk("MISRA-C:2012 Rule 21.3", "p = malloc(10);")
    assert not semantic_risk("BARR-C 3.1a", "    /* a very long comment */")


def test_gate_holds_finding_pending_without_confirmation(tmp_path):
    """A fix that passes the analyzer rescan but has no test/approval stays
    pending_verification, NOT resolved (backlog §1 acceptance)."""
    proj = _proj(tmp_path, RISKY)
    eng = LoopEngine(proj)
    # default policy with no test_command => human_gated
    sess = eng.begin_session(["src"], {"analyzers": ["native"]})
    sid = sess["session_id"]
    fp = _find(eng, "15.6")["fingerprint"]

    # "fix" it: rewrite to clean code — the analyzer stops flagging everything
    (proj / "src" / "m.c").write_text(CLEAN)
    v = eng.verify(sid)

    assert v["state"] == "awaiting_verification"
    assert v["diff"]["resolved"] == 0
    assert v["pending_verification"] >= 1
    f = eng.mem.get_finding(fp)
    assert f["status"] == "pending_verification"   # NOT resolved
    assert f["semantic_risk"] == 1


def test_human_approval_resolves(tmp_path):
    proj = _proj(tmp_path, RISKY)
    eng = LoopEngine(proj)
    sess = eng.begin_session(["src"], {"analyzers": ["native"]})
    sid = sess["session_id"]
    risky_fp = _find(eng, "15.6")["fingerprint"]
    (proj / "src" / "m.c").write_text(CLEAN)
    eng.verify(sid)

    # approval requires a signer
    assert "error" in eng.approve(risky_fp, "")
    # approve every pending fix -> audit trail recorded, session converges
    for f in eng.mem.pending_findings():
        assert eng.approve(f["fingerprint"], "lead-eng")["ok"]
    r = eng.mem.get_finding(risky_fp)
    assert r["status"] == "resolved"
    assert r["verification_method"] == "human"
    assert r["approved_by"] == "lead-eng"
    assert eng.verify(sid)["state"] == "converged"


def test_cannot_approve_a_still_detected_finding(tmp_path):
    proj = _proj(tmp_path, RISKY)
    eng = LoopEngine(proj)
    sess = eng.begin_session(["src"], {"analyzers": ["native"]})
    fp = _find(eng, "15.6")["fingerprint"]
    # do NOT fix it — still open/detected
    assert "error" in eng.approve(fp, "lead-eng")
    assert eng.mem.get_finding(fp)["status"] != "resolved"


def test_test_gated_confirms_safe_but_not_risky(tmp_path):
    """A passing test auto-confirms a plain finding, but a semantic-risk /
    high-severity one still requires human approval (backlog §5)."""
    proj = _proj(tmp_path, RISKY + LONG)
    eng = LoopEngine(proj)
    sess = eng.begin_session(["src"], {"analyzers": ["native"],
                                       "verification_policy": "test_gated",
                                       "test_command": PASS_CMD})
    sid = sess["session_id"]
    (proj / "src" / "m.c").write_text(CLEAN)
    v = eng.verify(sid)

    # the minor, non-risky findings were confirmed by the passing test...
    assert v["confirmed_by_test"], "a passing test should confirm the safe findings"
    # ...but the risky Rule 15.6 finding is still awaiting a human
    assert v["awaiting_human_approval"] >= 1
    assert v["state"] == "awaiting_verification"
    risky = [f for f in eng.mem.pending_findings() if f["semantic_risk"]]
    assert risky and all(f["status"] == "pending_verification" for f in risky)


def test_failing_tests_confirm_nothing(tmp_path):
    proj = _proj(tmp_path, LONG)
    eng = LoopEngine(proj)
    sess = eng.begin_session(["src"], {"analyzers": ["native"],
                                       "verification_policy": "test_gated",
                                       "test_command": FAIL_CMD})  # always exits 1
    sid = sess["session_id"]
    (proj / "src" / "m.c").write_text(CLEAN)
    v = eng.verify(sid)
    assert v["test_run"]["passed"] is False
    assert v["confirmed_by_test"] == []
    assert v["pending_verification"] >= 1
    assert v["state"] == "awaiting_verification"


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
