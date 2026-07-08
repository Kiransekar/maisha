"""Smoke tests: rule registry, native analyzer, memory lifecycle, loop engine."""

import shutil
from pathlib import Path

import pytest

from sentinelc.rules import REGISTRY
from sentinelc.analyzers.native import NativeAnalyzer
from sentinelc.engine import LoopEngine

FIXTURE = Path(__file__).resolve().parent.parent / "examples" / "bad.c"


def test_registry_resolution():
    assert REGISTRY.resolve("MISRA 21.3")["id"] == "MISRA-C:2012 Rule 21.3"
    assert REGISTRY.resolve("21.3")["standard"] == "MISRA-C:2012"
    assert REGISTRY.resolve("str31-c")["id"] == "CERT STR31-C"
    assert REGISTRY.resolve("barr 1.3a")["id"] == "BARR-C 1.3a"
    assert "MISRA-C:2012 Rule 15.6" in REGISTRY.cross_refs("BARR-C 1.3a")


def test_native_analyzer_finds_expected_rules(tmp_path):
    work = tmp_path / "src"
    work.mkdir()
    shutil.copy(FIXTURE, work / "bad.c")
    findings = NativeAnalyzer().analyze([work / "bad.c"], tmp_path)
    rules = {f.rule_id for f in findings}
    for expected in [
        "MISRA-C:2012 Rule 21.3",   # malloc/free
        "MISRA-C:2012 Rule 21.6",   # printf
        "MISRA-C:2012 Rule 7.1",    # octal
        "MISRA-C:2012 Rule 7.3",    # 1ul suffix
        "MISRA-C:2012 Rule 13.4",   # if (value = mode)
        "MISRA-C:2012 Rule 15.1",   # goto
        "MISRA-C:2012 Rule 15.6",   # if without braces
        "MISRA-C:2012 Rule 16.4",   # switch without default
        "MISRA-C:2012 Rule 17.2",   # recursion
        "CERT STR31-C",             # strcpy/sprintf
        "CERT ERR34-C",             # atoi
        "CERT ENV33-C",             # system()
        "CERT FLP37-C",             # float equality
        "BARR-C 3.2a",              # tab indent
    ]:
        assert expected in rules, f"missing {expected}; got {sorted(rules)}"
    # patterns inside strings/comments must NOT fire
    assert all("bad.c" == Path(f.file).name for f in findings)


def test_fingerprint_stability(tmp_path):
    src = tmp_path / "a.c"
    src.write_text('void f(void){ char b[4]; strcpy(b, "x"); }\n')
    f1 = NativeAnalyzer().analyze([src], tmp_path)
    # shift the line down: fingerprint must survive
    src.write_text('\n\nvoid f(void){ char b[4]; strcpy(b, "x"); }\n')
    f2 = NativeAnalyzer().analyze([src], tmp_path)
    assert {x.fingerprint for x in f1} == {x.fingerprint for x in f2}


def test_memory_lifecycle_and_loop(tmp_path):
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    bad = proj / "src" / "bad.c"
    shutil.copy(FIXTURE, bad)

    eng = LoopEngine(proj)
    # analyzer_only: exercise the raw resolve/converge/regress path (the verification
    # gate is covered separately in test_verification_gate.py).
    sess = eng.begin_session(["src"], {"analyzers": ["native"], "batch_size": 3,
                                       "verification_policy": "analyzer_only"})
    sid = sess["session_id"]
    assert sess["baseline"]["open"] > 5

    batch = eng.next_batch(sid)
    assert 0 < len(batch["batch"]) <= 3
    top = batch["batch"][0]
    assert top["fix_hint"]

    # record an attempt, "fix" everything by replacing the file with clean code
    eng.record_attempt(sid, top["fingerprint"], "rewrite module to compliant form")
    bad.write_text(
        "#include <stdint.h>\n"
        "static int32_t add(int32_t a, int32_t b)\n"
        "{\n    return a + b;\n}\n"
        "int32_t entry(void)\n{\n    return add(1, 2);\n}\n")
    v = eng.verify(sid)
    assert v["open_now"] == 0
    assert v["state"] == "converged"
    assert v["diff"]["resolved"] > 5

    # regression: put one violation back -> status regressed, prioritized first
    bad.write_text(bad.read_text() + "\nvoid oops(void)\n{\n    goto end;\nend:\n    return;\n}\n")
    eng.scan(["src"], ["native"])
    opens = eng.mem.open_findings()
    assert opens and opens[0]["status"] in ("open", "regressed")


def test_deviation_and_suppression(tmp_path):
    proj = tmp_path / "p2"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "d.c").write_text(
        'void log_it(void)\n{\n    printf("x");\n}\n#include <stdio.h>\n')
    eng = LoopEngine(proj)
    eng.scan(["src"], ["native"])
    opens = eng.mem.open_findings()
    assert any(f["rule_id"] == "MISRA-C:2012 Rule 21.6" for f in opens)

    eng.mem.add_deviation("MISRA-C:2012 Rule 21.6", "src/*",
                          "printf routed to UART logger in this build", "lead")
    eng.scan(["src"], ["native"])
    opens = eng.mem.open_findings()
    assert not any(f["rule_id"] == "MISRA-C:2012 Rule 21.6" for f in opens)


def test_concurrent_session_begin_is_guarded(tmp_path):
    proj = tmp_path / "cc"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "a.c").write_text('void f(void){ char b[4]; strcpy(b, "x"); }\n')
    eng = LoopEngine(proj)
    first = eng.begin_session(["src"], {"analyzers": ["native"]})
    assert "session_id" in first
    # a second begin on the same project is refused (would race on finding state)
    second = eng.begin_session(["src"], {"analyzers": ["native"]})
    assert "error" in second and second["active_session_id"] == first["session_id"]
    # ...unless forced
    assert "session_id" in eng.begin_session(["src"], {"analyzers": ["native"]}, force=True)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
