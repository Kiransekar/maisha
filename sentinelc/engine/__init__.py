"""The engineered fix loop.

Sentinel-C deliberately splits responsibilities:

  deterministic side (this engine)      probabilistic side (the IDE's LLM)
  ------------------------------------  ----------------------------------
  scanning, fingerprinting, memory      reading code, writing the fix
  prioritization and batching           choosing a strategy
  verification and regression diffing   explaining/deviating when justified
  budgets, stall & oscillation guards

The loop, as seen by the host agent:

    begin  -> baseline scan, memory sync, session created
    repeat:
      next_batch -> small, file-grouped batch of findings + per-finding brief
                    (rule guidance, previously FAILED strategies to avoid,
                    relevant project memory notes)
      [agent records intended strategy, edits code]
      verify     -> rescan, memory sync, diff (resolved/new/regressed),
                    convergence decision
    until state in {converged, budget_exhausted, stalled}

Guards:
  * iteration budget         hard cap on loop turns
  * stall detection          N consecutive verifies with no net progress
  * oscillation detection    a finding that resolves then regresses twice is
                             frozen ("needs_human") so the agent stops thrashing
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from ..analyzers import run_scan, available_analyzers
from ..memory import MemoryStore
from ..rules import REGISTRY

DEFAULT_CONFIG = {
    "max_iterations": 10,
    "batch_size": 5,
    "stall_limit": 2,           # consecutive no-progress verifies before stalling
    "oscillation_limit": 2,     # regress_count at which a finding is frozen
    "severity_floor": "minor",  # ignore anything below this
    "analyzers": None,          # None = all available
    # How a finding is allowed to leave the queue as 'resolved':
    #   analyzer_only  the analyzer stopped flagging it (NOT recommended for
    #                  compliance work — the analyzer is the only judge of its
    #                  own blind spot; see the sentinel-cast trap in the tests)
    #   test_gated     a configured test/build command must exit 0 first
    #   human_gated    a human must call approve_finding first
    # None => auto: test_gated if test_command is set, else human_gated.
    "verification_policy": None,
    "test_command": None,       # shell command; exit 0 confirms pending fixes
}

_VALID_POLICIES = ("analyzer_only", "test_gated", "human_gated")

_SEV_ORDER = ["blocker", "critical", "major", "minor", "info"]


def _severities_at_or_above(floor: str) -> list[str]:
    idx = _SEV_ORDER.index(floor) if floor in _SEV_ORDER else 3
    return _SEV_ORDER[: idx + 1]


class LoopEngine:
    def __init__(self, project_root: str | Path):
        self.root = Path(project_root).resolve()
        self.mem = MemoryStore(self.root)

    # ------------------------------------------------------------------ scan
    def scan(self, paths: list[str], analyzers: list[str] | None = None,
             gate: bool = False) -> dict:
        findings, used = run_scan(paths, self.root, analyzers)
        from ..analyzers.base import collect_c_files
        scanned = [str(f.resolve().relative_to(self.root)) if str(f).startswith(str(self.root))
                   else str(f) for f in collect_c_files(paths, self.root)]
        diff = self.mem.sync_scan(findings, scanned, gate=gate, producers=set(used))
        return {
            "analyzers_used": used,
            "files_scanned": len(scanned),
            "total_findings": len(findings),
            "diff": {k: len(v) for k, v in diff.items()},
            "open": len(self.mem.open_findings(limit=100000)),
            "pending_verification": self.mem.count_pending(),
        }

    def import_sarif(self, path: str | Path) -> dict:
        """Ingest findings from an external SARIF file (e.g. a qualified engine
        like Helix QAC / Polyspace, or cppcheck's own --sarif output) into the
        same memory/loop/gate machinery as a native scan. Imported findings are
        not cleared by native rescans (see sync_scan producers)."""
        from .. import report as report_mod
        import json
        data = json.loads(Path(path).read_text("utf-8"))
        findings = report_mod.parse_sarif(data, self.root)
        diff = self.mem.sync_scan(findings, [], producers=set())
        tools = sorted({f.analyzer for f in findings})
        return {
            "source": str(path),
            "tools": tools,
            "imported": len(findings),
            "diff": {k: len(v) for k, v in diff.items()},
            "open": len(self.mem.open_findings(limit=100000)),
        }

    @staticmethod
    def _policy(cfg: dict) -> str:
        p = cfg.get("verification_policy")
        if p in _VALID_POLICIES:
            return p
        return "test_gated" if cfg.get("test_command") else "human_gated"

    def _run_tests(self, cmd: str) -> dict:
        # ponytail: pass/fail on exit code only — doesn't diff new-vs-baseline
        # failures. Add a baseline capture if a flaky suite needs delta scoring.
        try:
            proc = subprocess.run(cmd, shell=True, cwd=self.root,
                                  capture_output=True, text=True, timeout=1800)
        except Exception as e:  # noqa: BLE001 — surface any launch/timeout failure to the loop
            return {"ran": False, "passed": False, "error": str(e), "command": cmd}
        return {"ran": True, "passed": proc.returncode == 0, "exit_code": proc.returncode,
                "command": cmd, "output_tail": (proc.stdout + proc.stderr)[-2000:]}

    def approve(self, fingerprint: str, approved_by: str) -> dict:
        if not (approved_by or "").strip():
            return {"error": "approved_by is required — record who signed off on this fix."}
        return self.mem.approve_finding(fingerprint, approved_by.strip())

    # --------------------------------------------------------------- session
    def begin_session(self, paths: list[str], config: dict | None = None) -> dict:
        cfg = {**DEFAULT_CONFIG, **(config or {}), "paths": paths}
        baseline = self.scan(paths, cfg.get("analyzers"))
        sid = self.mem.create_session(cfg)
        self.mem.update_session(sid, history=[{
            "iteration": 0, "event": "baseline",
            "open": baseline["open"], "ts": time.time(),
        }])
        return {
            "session_id": sid,
            "state": "active",
            "baseline": baseline,
            "guidance": ("Call next_batch to receive the highest-priority findings. "
                          "Before editing, call record_attempt with your intended strategy. "
                          "After editing, call verify. Repeat until the session converges."),
        }

    def next_batch(self, session_id: str) -> dict:
        sess = self._require(session_id)
        cfg = sess["config"]
        sevs = _severities_at_or_above(cfg.get("severity_floor", "minor"))
        opens = self.mem.open_findings(limit=500, severities=sevs)

        # freeze oscillating findings
        frozen, workable = [], []
        for f in opens:
            if f["regress_count"] >= cfg.get("oscillation_limit", 2):
                frozen.append(f)
            else:
                workable.append(f)

        if not workable:
            return {"session_id": session_id, "batch": [], "frozen_needs_human": self._brief_many(frozen),
                    "message": "No workable open findings. Call verify to close out the session."}

        # group by file: take the file of the top-priority finding first
        batch, seen_files = [], []
        size = cfg.get("batch_size", 5)
        for f in workable:
            if len(batch) >= size:
                break
            if f["file"] in seen_files or not seen_files or len(seen_files) < 2:
                batch.append(f)
                if f["file"] not in seen_files:
                    seen_files.append(f["file"])

        return {
            "session_id": session_id,
            "iteration": sess["iteration"],
            "remaining_open": len(opens),
            "frozen_needs_human": self._brief_many(frozen),
            "batch": [self._brief(f) for f in batch],
            "instructions": (
                "Fix ONLY these findings; do not refactor unrelated code. "
                "Preserve behavior. Prefer the fix_hint approach unless it appears in "
                "failed_strategies. When done editing, call verify."),
        }

    def record_attempt(self, session_id: str, fingerprint: str,
                       strategy: str, notes: str = "") -> dict:
        self._require(session_id)
        aid = self.mem.record_fix_attempt(fingerprint, session_id, strategy, notes)
        return {"attempt_id": aid, "fingerprint": fingerprint, "recorded": True}

    def verify(self, session_id: str) -> dict:
        sess = self._require(session_id)
        cfg = sess["config"]
        policy = self._policy(cfg)
        result = self.scan(cfg["paths"], cfg.get("analyzers"), gate=policy != "analyzer_only")
        iteration = sess["iteration"] + 1
        history = sess["history"]
        prev_open = history[-1]["open"] if history else result["open"]
        open_now = result["open"]

        # close pending attempts on findings that persist
        for f in self.mem.open_findings(limit=100000):
            self.mem.close_pending_attempts(f["fingerprint"], "persisting")

        # verification gate: a fix that merely silenced the analyzer is NOT
        # resolved until a passing test run or a human confirms it.
        test_run, confirmed_by_test = None, []
        if policy == "test_gated" and cfg.get("test_command"):
            test_run = self._run_tests(cfg["test_command"])
            if test_run.get("passed"):
                confirmed_by_test = self.mem.confirm_pending_by_test()

        pending = self.mem.count_pending()
        awaiting_human = self.mem.count_pending(require_human=True)
        history.append({"iteration": iteration, "event": "verify", "open": open_now,
                        "pending": pending, "diff": result["diff"], "ts": time.time()})

        state, reason = "active", ""
        if open_now == 0 and pending == 0:
            state, reason = "converged", "All findings resolved, suppressed, or deviated."
        elif open_now == 0 and pending > 0:
            need = []
            if awaiting_human:
                need.append(f"{awaiting_human} require human approval (call approve_finding)")
            if policy == "test_gated" and not cfg.get("test_command"):
                need.append("no test_command configured to auto-confirm the rest")
            elif policy == "human_gated":
                need.append(f"{pending - awaiting_human} more await approval under human_gated policy")
            state = "awaiting_verification"
            reason = ("Analyzer-clean, but the fixes are UNVERIFIED — "
                      + "; ".join(need) + ". They do not count as resolved until confirmed.")
        elif iteration >= cfg.get("max_iterations", 10):
            state, reason = "budget_exhausted", f"Iteration budget ({cfg['max_iterations']}) reached."
        else:
            recent = [h for h in history if h["event"] == "verify"][-cfg.get("stall_limit", 2):]
            if len(recent) >= cfg.get("stall_limit", 2) and all(
                    h["open"] >= prev for h, prev in
                    zip(recent, [prev_open] + [r["open"] for r in recent[:-1]])):
                # no verify in the window reduced the open count
                if all(h["open"] >= history[max(0, len(history) - len(recent) - 1)]["open"]
                       for h in recent):
                    state, reason = "stalled", (
                        "No net progress across recent iterations. Escalate to a human, "
                        "add deviations for justified findings, or change approach.")

        self.mem.update_session(session_id, status=state if state != "active" else "active",
                                iteration=iteration, history=history)
        return {
            "session_id": session_id,
            "iteration": iteration,
            "state": state,
            "reason": reason,
            "verification_policy": policy,
            "open_before": prev_open,
            "open_now": open_now,
            "pending_verification": pending,
            "awaiting_human_approval": awaiting_human,
            "confirmed_by_test": confirmed_by_test,
            "test_run": test_run,
            "diff": result["diff"],
            "pending_findings": self._brief_many(self.mem.pending_findings()),
            "regressions": self._brief_many(
                [f for f in self.mem.open_findings(limit=100) if f["status"] == "regressed"]),
            "next": ("Session complete." if state == "converged"
                     else "Approve verified fixes (approve_finding) or call next_batch."
                     if state == "awaiting_verification"
                     else "Call next_batch for the next set of findings." if state == "active"
                     else "Session ended."),
        }

    def session_status(self, session_id: str) -> dict:
        sess = self._require(session_id)
        return {"session_id": session_id, "state": sess["status"],
                "iteration": sess["iteration"], "history": sess["history"],
                "config": sess["config"]}

    # ------------------------------------------------------------- briefings
    def _brief(self, f: dict) -> dict:
        meta = REGISTRY.get(f["rule_id"]) or {}
        failed = self.mem.failed_strategies(f["fingerprint"])
        notes = self.mem.search_notes(f["rule_id"], limit=2) + \
                self.mem.search_notes(f["file"], limit=2)
        return {
            "fingerprint": f["fingerprint"],
            "rule_id": f["rule_id"],
            "standard": f["standard"],
            "severity": f["severity"],
            "status": f["status"],
            "location": f"{f['file']}:{f['line']}",
            "line_content": f["line_content"],
            "function": f["context_symbol"],
            "message": f["message"],
            "rule_summary": meta.get("summary", ""),
            "fix_hint": f["fix_hint"] or meta.get("fix", ""),
            "equivalent_rules": REGISTRY.cross_refs(f["rule_id"]),
            "failed_strategies": failed,
            "relevant_memory": [{"topic": n["topic"], "content": n["content"]}
                                 for n in {n["id"]: n for n in notes}.values()][:3],
            "times_seen": f["seen_count"],
            "times_regressed": f["regress_count"],
        }

    def _brief_many(self, fs: list[dict]) -> list[dict]:
        return [self._brief(f) for f in fs]

    def _require(self, session_id: str) -> dict:
        sess = self.mem.get_session(session_id)
        if not sess:
            raise ValueError(
                f"Unknown session '{session_id}'. Call begin_session first, or use "
                "session_status with a valid id.")
        return sess
