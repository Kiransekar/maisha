#!/usr/bin/env python
"""End-to-end fix-loop simulation against the synthetic firmware module.

Plays the role of the "agent" in AGENT_PLAYBOOK.md driving a real Maisha
session: begin -> next_batch -> apply scripted fixes -> record_attempt ->
verify -> repeat, against benchmark/firmware/*.c copied into a scratch
project. Exercises:

  1. The verification gate under verification_policy='test_gated' with an
     always-passing fake test_command, including the README's sentinel-cast
     trap (a fix that silences the analyzer but is behaviorally wrong).
  2. Oscillation freezing (a finding regressing twice -> needs_human), on a
     separate scratch copy with verification_policy='analyzer_only' to
     isolate the mechanic from gate complexity.
  3. Stall detection (no-progress verifies).
  4. Iteration-budget exhaustion.

Usage (from repo root): python benchmark/run_loop_simulation.py
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from maishac.engine import LoopEngine  # noqa: E402

FIRMWARE_SRC = ROOT / "benchmark" / "firmware"
WORK_BASE = ROOT / "benchmark" / "results" / "_loop_sim_workdir"
TRANSCRIPT: list[str] = []


def log(msg: str = "") -> None:
    print(msg)
    TRANSCRIPT.append(msg)


def fresh_workdir(name: str) -> Path:
    d = WORK_BASE / name
    if d.exists():
        shutil.rmtree(d)
    (d / "src").mkdir(parents=True)
    for f in FIRMWARE_SRC.glob("*"):
        shutil.copy(f, d / "src" / f.name)
    return d


def find_fp(eng: LoopEngine, rule_id: str, file_suffix: str) -> str | None:
    for f in eng.mem.open_findings(limit=1000):
        if f["rule_id"] == rule_id and f["file"].replace("\\", "/").endswith(file_suffix):
            return f["fingerprint"]
    return None


def replace_in_file(path: Path, old: str, new: str) -> None:
    text = path.read_text("utf-8")
    if old not in text:
        raise AssertionError(f"expected snippet not found in {path}:\n{old}")
    path.write_text(text.replace(old, new, 1), "utf-8")


# ============================================================ SESSION 1 =====
def session_gate_and_convergence() -> None:
    log("\n" + "=" * 78)
    log("SESSION 1 — verification gate + convergence (test_gated policy)")
    log("=" * 78)

    work = fresh_workdir("session1")
    eng = LoopEngine(work)
    motor = work / "src" / "motor_control.c"
    uart = work / "src" / "uart_driver.c"

    baseline = eng.scan(["src"])
    log(f"Baseline scan: {baseline['total_findings']} findings, "
        f"{baseline['open']} open, analyzers={baseline['analyzers_used']}")

    # Suppress the two confirmed analyzer false positives found during triage
    # (a bare function-prototype mistaken for a call; a macro-sized array
    # mistaken for a VLA) so they don't clutter the batch — a realistic
    # first step per AGENT_PLAYBOOK.md ("If the finding is a false positive,
    # call compliance_suppress_finding with a concrete reason").
    fp1 = find_fp(eng, "CERT STR31-C", "fw_types.h")
    fp2 = find_fp(eng, "MISRA-C:2012 Rule 18.8", "uart_driver.c")
    if fp1:
        eng.mem.suppress(fp1, "fw_types.h:17 is a bare function PROTOTYPE "
                          "(char *strcpy(...);), not a call site — native's "
                          "banned-call regex can't tell the two apart.")
        log(f"Suppressed false positive: CERT STR31-C in fw_types.h ({fp1})")
    if fp2:
        eng.mem.suppress(fp2, "g_uart_tx_buf is a fixed array sized by the "
                          "compile-time macro UART_TX_BUF_SIZE, not a "
                          "variable-length array.")
        log(f"Suppressed false positive: MISRA 18.8 in uart_driver.c ({fp2})")

    sess = eng.begin_session(["src"], {
        "verification_policy": "test_gated",
        "test_command": f'"{sys.executable}" -c "import sys; sys.exit(0)"',
        "batch_size": 8,
        "max_iterations": 10,
    })
    sid = sess["session_id"]
    log(f"\nbegin_session -> {sid}, policy={sess['baseline']['analyzers_used']}, "
        f"open={sess['baseline']['open']}")

    # ---- Fix strategies, keyed by rule_id -----------------------------
    def fix_switch_default():
        replace_in_file(motor,
            "        case 2:\n            speed = 1000u;\n            break;\n    }",
            "        case 2:\n            speed = 1000u;\n            break;\n"
            "        default:\n            speed = 0u;\n            break;\n    }")

    def fix_braceless_if():
        replace_in_file(motor,
            "    if (*requested_speed > max_delta)\n        *requested_speed = max_delta;",
            "    if (*requested_speed > max_delta)\n    {\n        *requested_speed = max_delta;\n    }")

    def fix_float_equality():
        replace_in_file(motor,
            "    if (duty == 1.0f)\n    {\n        return 1;\n    }\n    return 0;",
            "    if ((duty > 0.9999f) && (duty < 1.0001f))\n    {\n        return 1;\n    }\n    return 0;")

    def fix_str31c_uart():
        replace_in_file(uart,
            "    strcpy(g_uart_tx_buf, msg);",
            "    uint32_t idx = 0u;\n"
            "    while ((msg[idx] != '\\0') && (idx < (UART_TX_BUF_SIZE - 1u)))\n"
            "    {\n        g_uart_tx_buf[idx] = msg[idx];\n        idx++;\n    }\n"
            "    g_uart_tx_buf[idx] = '\\0';")

    def fix_octal():
        replace_in_file(uart, "return 011;", "return 9u;")

    def fix_goto():
        replace_in_file(uart,
            "    uint32_t i;\n\n    if (data == NULL)\n    {\n        goto fail;\n    }\n"
            "    for (i = 0u; i < len; i++)\n    {\n        (void)data[i];\n    }\n    return 0;\n\nfail:\n    return -1;",
            "    uint32_t i;\n    int32_t result;\n\n    if (data == NULL)\n    {\n        result = -1;\n    }\n"
            "    else\n    {\n        for (i = 0u; i < len; i++)\n        {\n            (void)data[i];\n        }\n"
            "        result = 0;\n    }\n    return result;")

    def fix_sentinel_DANGEROUS():
        # The exact README trap: silences the analyzer, breaks the -1 "no
        # limit configured" sentinel by turning it into UINT32_MAX.
        replace_in_file(motor,
            "    if (sensor_val_ma > threshold)",
            "    if (sensor_val_ma > (uint32_t)threshold)")

    FIXES = {
        "MISRA-C:2012 Rule 16.4": fix_switch_default,
        "clang-tidy:bugprone-switch-missing-default-case": None,  # cleared by fix_switch_default
        "clang-tidy:clang-analyzer-core.uninitialized.UndefReturn": None,
        "MISRA-C:2012 Rule 15.6": fix_braceless_if,
        "CERT FLP37-C": fix_float_equality,
        "CERT STR31-C": fix_str31c_uart,
        "clang-tidy:clang-analyzer-security.insecureAPI.strcpy": None,
        "MISRA-C:2012 Rule 17.7": None,  # cleared alongside the strcpy fix
        "MISRA-C:2012 Rule 7.1": fix_octal,
        "MISRA-C:2012 Rule 15.1": fix_goto,
        "MISRA-C:2012 Rule 10.4": fix_sentinel_DANGEROUS,
    }
    DEVIATED = {"MISRA-C:2012 Rule 15.5", "MISRA-C:2012 Rule 8.9", "MISRA-C:2012 Rule 8.7",
                "MISRA-C:2012 Rule 2.5"}
    applied_fix_fns: set = set()

    iteration = 0
    while True:
        iteration += 1
        batch = eng.next_batch(sid)
        if not batch["batch"]:
            log(f"\n[iter {iteration}] next_batch: empty — nothing left to fix.")
            break
        log(f"\n[iter {iteration}] next_batch: {len(batch['batch'])} findings "
            f"(remaining_open={batch['remaining_open']})")
        for item in batch["batch"]:
            rule, fp = item["rule_id"], item["fingerprint"]
            log(f"  - {rule:<45} {item['location']}  severity={item['severity']}")
            if rule in DEVIATED:
                continue  # handled once, below, outside the batch loop
            fn = FIXES.get(rule)
            if fn is not None and fn not in applied_fix_fns:
                fn()
                applied_fix_fns.add(fn)
                eng.record_attempt(sid, fp, f"scripted fix for {rule}")
            elif fn is None:
                eng.record_attempt(sid, fp, f"cleared as a side effect of another fix ({rule})")

        # issue deviations once, the first time we see each deviated rule
        for item in batch["batch"]:
            if item["rule_id"] in DEVIATED:
                already = eng.mem.db.execute(
                    "SELECT 1 FROM deviations WHERE rule_id = ?", (item["rule_id"],)).fetchone()
                if not already:
                    just = {
                        "MISRA-C:2012 Rule 15.5": "Guard-clause single-purpose helpers are "
                            "intentionally single-branch-return; a forced single exit would "
                            "add nesting without safety benefit here.",
                        "MISRA-C:2012 Rule 8.9": "g_uart_tx_buf must persist across calls by "
                            "design (it is the transmit queue); moving it to block scope "
                            "would silently break that.",
                        "MISRA-C:2012 Rule 8.7": "Adding const to public driver API parameters "
                            "is an ABI-affecting signature change tracked separately, not "
                            "blocking this compliance pass.",
                        "MISRA-C:2012 Rule 2.5": "MOTOR_MAX_CURRENT_MA is a documented hardware "
                            "current-limit constant kept for the next revision's clamp logic; "
                            "not yet wired up, tracked as a deviation rather than deleted.",
                    }[item["rule_id"]]
                    eng.mem.add_deviation(item["rule_id"], "src/*", just, "bench-reviewer")
                    log(f"    -> DEVIATED: {item['rule_id']} ({just[:60]}...)")

        v = eng.verify(sid)
        log(f"[iter {iteration}] verify -> state={v['state']}  open={v['open_now']}  "
            f"pending={v['pending_verification']}  awaiting_human={v['awaiting_human_approval']}  "
            f"diff={v['diff']}")
        if v["state"] != "active":
            break

    # ---- Handle awaiting_verification: approve the safe fixes, but watch
    # what happens to the sentinel-cast one specifically.
    if v["state"] == "awaiting_verification":
        pending = eng.mem.pending_findings()
        log(f"\n{len(pending)} findings pending verification (test passed, but policy still "
            f"requires review for high-severity/semantic-risk findings):")
        sentinel_fp = None
        for p in pending:
            risky = bool(p.get("semantic_risk"))
            log(f"  - {p['rule_id']:<40} severity={p['severity']:<9} semantic_risk={risky}")
            if p["rule_id"] == "MISRA-C:2012 Rule 10.4":
                sentinel_fp = p["fingerprint"]

        log("\n--- Human reviewer looks at the sentinel-cast fix specifically ---")
        if sentinel_fp:
            frow = eng.mem.get_finding(sentinel_fp)
            log(f"Finding {sentinel_fp}: line_content now = {frow['line_content']!r}")
            log("A human reviewer recognizes the '-1 means no limit' sentinel is now "
                "broken by the cast (threshold=-1 -> (uint32_t)-1 = 4294967295, i.e. "
                "'no limit' became 'an enormous limit') and REJECTS this fix — applying "
                "the correct one instead of approving it.")
            replace_in_file(motor,
                "    if (sensor_val_ma > (uint32_t)threshold)",
                "    if ((threshold >= 0) && (sensor_val_ma > (uint32_t)threshold))")
            eng.record_attempt(sid, sentinel_fp, "corrected: explicit sentinel guard before the cast")

        # approve everything else that's genuinely fixed and pending
        for p in pending:
            if p["fingerprint"] != sentinel_fp:
                res = eng.approve(p["fingerprint"], "bench-reviewer@example.com")
                log(f"  approve_finding {p['rule_id']:<40} -> {res.get('status', res)}")

        v = eng.verify(sid)
        log(f"\nverify -> state={v['state']}  open={v['open_now']}  "
            f"pending={v['pending_verification']}")

        if v["state"] == "awaiting_verification":
            pending2 = eng.mem.pending_findings()
            for p in pending2:
                res = eng.approve(p["fingerprint"], "bench-reviewer@example.com")
                log(f"  approve_finding {p['rule_id']:<40} (corrected) -> {res.get('status', res)}")
            v = eng.verify(sid)
            log(f"verify -> state={v['state']}  open={v['open_now']}  pending={v['pending_verification']}")

    log(f"\nFINAL STATE: {v['state']}")
    log(f"Session status: {json.dumps(eng.session_status(sid)['history'][-3:], indent=2, default=str)}")


# ============================================================ SESSION 2 =====
def session_oscillation() -> None:
    log("\n" + "=" * 78)
    log("SESSION 2 — oscillation freezing (analyzer_only policy, isolated)")
    log("=" * 78)

    work = fresh_workdir("session2")
    eng = LoopEngine(work)
    uart = work / "src" / "uart_driver.c"

    eng.scan(["src"])
    sess = eng.begin_session(["src"], {
        "verification_policy": "analyzer_only",
        "batch_size": 20,
        "oscillation_limit": 2,
        "max_iterations": 20,
    })
    sid = sess["session_id"]

    def octal_present() -> bool:
        return "return 011;" in uart.read_text("utf-8")

    def fix_octal():
        replace_in_file(uart, "return 011;", "return 9u;")

    def regress_octal():
        replace_in_file(uart, "return 9u;", "return 011;")

    # Cycle: fix -> verify(resolved) -> regress -> verify(regressed #1)
    #        -> fix -> verify(resolved) -> regress -> verify(regressed #2 -> frozen)
    for cycle in range(2):
        fix_octal()
        v = eng.verify(sid)
        log(f"[cycle {cycle+1}] after FIX    -> state={v['state']} diff={v['diff']}")
        regress_octal()
        v = eng.verify(sid)
        log(f"[cycle {cycle+1}] after REGRESS -> state={v['state']} diff={v['diff']} "
            f"regressions={[r['rule_id'] for r in v['regressions']]}")

    batch = eng.next_batch(sid)
    frozen = batch.get("frozen_needs_human", [])
    log(f"\nnext_batch frozen_needs_human: {[f['rule_id'] + ' x' + str(f['times_regressed']) for f in frozen]}")
    assert any(f["rule_id"] == "MISRA-C:2012 Rule 7.1" for f in frozen), \
        "expected the twice-regressed octal finding to be frozen as needs_human"
    log("CONFIRMED: finding frozen as needs_human after 2 regressions, no longer offered in next_batch.")


# ============================================================ SESSION 3 =====
def session_stall() -> None:
    log("\n" + "=" * 78)
    log("SESSION 3 — stall detection (no-progress verifies)")
    log("=" * 78)

    work = fresh_workdir("session3")
    eng = LoopEngine(work)
    eng.scan(["src"])
    sess = eng.begin_session(["src"], {
        "verification_policy": "analyzer_only",
        "stall_limit": 2,
        "max_iterations": 20,
    })
    sid = sess["session_id"]

    # Make no-op edits (touch a comment) each iteration — no real fix, so
    # open-finding count never drops.
    target = work / "src" / "motor_control.c"
    for i in range(4):
        text = target.read_text("utf-8")
        target.write_text(text + f"\n/* no-op edit {i} */\n", "utf-8")
        v = eng.verify(sid)
        log(f"[iter {i+1}] verify -> state={v['state']} open={v['open_now']}")
        if v["state"] != "active":
            break

    log(f"FINAL STATE: {v['state']}")
    assert v["state"] == "stalled", f"expected 'stalled', got {v['state']}"
    log("CONFIRMED: session correctly stalls after stall_limit verifies with no net progress.")


# ============================================================ SESSION 4 =====
def session_budget_exhaustion() -> None:
    log("\n" + "=" * 78)
    log("SESSION 4 — iteration budget exhaustion")
    log("=" * 78)

    work = fresh_workdir("session4")
    eng = LoopEngine(work)
    eng.scan(["src"])
    sess = eng.begin_session(["src"], {
        "verification_policy": "analyzer_only",
        "max_iterations": 2,
    })
    sid = sess["session_id"]

    target = work / "src" / "motor_control.c"
    for i in range(3):
        text = target.read_text("utf-8")
        target.write_text(text + f"\n/* no-op edit {i} */\n", "utf-8")
        v = eng.verify(sid)
        log(f"[iter {i+1}] verify -> state={v['state']} iteration={v['iteration']}")
        if v["state"] != "active":
            break

    log(f"FINAL STATE: {v['state']}")
    assert v["state"] == "budget_exhausted", f"expected 'budget_exhausted', got {v['state']}"
    log("CONFIRMED: session correctly stops at max_iterations regardless of remaining findings.")


def main() -> None:
    WORK_BASE.mkdir(parents=True, exist_ok=True)
    session_gate_and_convergence()
    session_oscillation()
    session_stall()
    session_budget_exhaustion()

    out = ROOT / "benchmark" / "results" / "loop_simulation_transcript.txt"
    out.write_text("\n".join(TRANSCRIPT), "utf-8")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
