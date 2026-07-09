"""Maisha MCP server.

Exposes the whole harness over the Model Context Protocol (stdio transport),
so ANY agentic IDE that speaks MCP — Claude Code, Cursor, Windsurf, VS Code
Copilot agent mode, Zed, Continue, JetBrains AI — can drive the compliance
loop with zero IDE-specific code.

Run:  maishac serve --project /path/to/project
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .engine import LoopEngine
from .memory import MemoryStore
from .rules import REGISTRY
from . import report as report_mod

mcp = FastMCP(
    "maisha",
    instructions=(
        "Maisha is a compliance harness for MISRA C:2012, BARR-C:2018 and CERT C. "
        "Typical flow: compliance_begin_session -> compliance_next_batch -> "
        "(compliance_record_attempt, edit code) -> compliance_verify -> repeat until "
        "converged. Use compliance_explain_rule for guidance, memory_* tools to persist "
        "project knowledge, and compliance_report for an auditable summary."),
)

_ENGINE: LoopEngine | None = None


def _engine() -> LoopEngine:
    global _ENGINE
    if _ENGINE is None:
        root = os.environ.get("MAISHAC_PROJECT", os.getcwd())
        _ENGINE = LoopEngine(root)
    return _ENGINE


def _j(obj) -> str:
    return json.dumps(obj, indent=2, default=str)


# ------------------------------------------------------------------ scanning
@mcp.tool()
def compliance_scan(paths: list[str], analyzers: list[str] | None = None,
                    include_paths: list[str] | None = None) -> str:
    """Scan C files/directories for MISRA C, BARR-C and CERT C violations and
    sync results into persistent project memory.

    Args:
        paths: Files or directories, relative to the project root (e.g. ["src"]).
        analyzers: Optional subset of ["native", "cppcheck", "clang-tidy"].
            Default: every analyzer installed on this machine.
        include_paths: Header search dirs forwarded to cppcheck/clang-tidy as -I.
            Without these, headers outside `paths` (e.g. a project's config.h)
            are invisible to those analyzers and they misreport "undefined
            identifier"/"file not found" false positives instead of real defects.

    Returns JSON with counts and a memory diff (new/persisting/resolved/
    regressed/suppressed/deviated). Use compliance_list_findings to see details.
    """
    return _j(_engine().scan(paths, analyzers, include_paths=include_paths))


@mcp.tool()
def compliance_list_findings(limit: int = 25, severity_floor: str = "info") -> str:
    """List open findings from memory, most severe first (regressions on top).

    Args:
        limit: Maximum findings to return (default 25).
        severity_floor: Minimum severity to include: one of
            blocker|critical|major|minor|info.
    """
    sev_order = ["blocker", "critical", "major", "minor", "info"]
    idx = sev_order.index(severity_floor) if severity_floor in sev_order else 4
    eng = _engine()
    rows = eng.mem.open_findings(limit=limit, severities=sev_order[: idx + 1])
    return _j({"count": len(rows), "findings": eng._brief_many(rows)})


@mcp.tool()
def compliance_get_finding(fingerprint: str) -> str:
    """Get full detail for one finding: rule guidance, fix hint, equivalent
    rules in other standards, prior fix attempts and relevant project memory.

    Args:
        fingerprint: The finding's stable fingerprint (from scan/list output).
    """
    eng = _engine()
    f = eng.mem.get_finding(fingerprint)
    if not f:
        return _j({"error": f"No finding with fingerprint '{fingerprint}'. "
                            "Run compliance_scan first or check compliance_list_findings."})
    detail = eng._brief(f)
    detail["fix_attempt_history"] = eng.mem.attempts_for(fingerprint)
    return _j(detail)


# ---------------------------------------------------------------- rule intel
@mcp.tool()
def compliance_explain_rule(rule: str) -> str:
    """Explain a coding-standard rule and how to fix violations of it.

    Args:
        rule: Any reasonable reference — "MISRA 21.3", "21.3", "STR31-C",
            "BARR 1.3a", "cert err34-c".
    """
    meta = REGISTRY.resolve(rule)
    if not meta:
        hits = REGISTRY.search(rule)
        return _j({"error": f"Rule '{rule}' not found in the knowledge base.",
                   "closest_matches": [h["id"] for h in hits]})
    out = dict(meta)
    out["equivalent_rules"] = REGISTRY.cross_refs(meta["id"])
    return _j(out)


@mcp.tool()
def compliance_search_rules(query: str, limit: int = 10) -> str:
    """Full-text search the MISRA/BARR-C/CERT rule knowledge base.

    Args:
        query: Keyword(s), e.g. "recursion", "dynamic memory", "format string".
        limit: Max results (default 10).
    """
    return _j(REGISTRY.search(query, limit))


# --------------------------------------------------------------- the loop
@mcp.tool()
def compliance_begin_session(paths: list[str], max_iterations: int = 10,
                             batch_size: int = 5,
                             severity_floor: str = "minor",
                             verification_policy: str | None = None,
                             test_command: str | None = None,
                             force: bool = False,
                             include_paths: list[str] | None = None) -> str:
    """Start an engineered fix session: runs a baseline scan and opens a loop
    with budgets, stall detection and oscillation guards.

    Args:
        paths: Files/directories to bring into compliance (e.g. ["src"]).
        max_iterations: Hard cap on fix/verify cycles (default 10).
        batch_size: Findings handed out per next_batch call (default 5).
        severity_floor: Ignore findings below this severity
            (blocker|critical|major|minor|info; default minor).
        verification_policy: How a fix is confirmed resolved:
            "analyzer_only" (the analyzer stopped flagging it — NOT recommended
            for compliance; it can't see behavior changes at sentinel/boundary
            values), "test_gated" (a passing test_command confirms fixes), or
            "human_gated" (a human must call compliance_approve_finding).
            Default: test_gated if test_command is given, else human_gated.
        test_command: Shell command that must exit 0 to confirm fixes at verify
            time, e.g. "make test". High-severity and semantic-risk findings
            (casts/comparisons/conversions) still require human approval.
        force: Start a new session even if one is already active on this project
            (otherwise begin returns the active session id so you can resume it).
        include_paths: Header search dirs forwarded to cppcheck/clang-tidy as -I
            on every scan/verify in this session. Without these, headers outside
            `paths` are invisible to those analyzers and they misreport
            "undefined identifier"/"file not found" false positives.

    Follow with compliance_next_batch.
    """
    return _j(_engine().begin_session(paths, {
        "max_iterations": max_iterations, "batch_size": batch_size,
        "severity_floor": severity_floor, "verification_policy": verification_policy,
        "test_command": test_command, "include_paths": include_paths}, force=force))


@mcp.tool()
def compliance_next_batch(session_id: str) -> str:
    """Get the next prioritized batch of findings to fix (regressions first,
    then by severity, grouped by file). Each finding includes rule guidance,
    strategies that already FAILED (do not repeat them), and relevant project
    memory.

    Args:
        session_id: From compliance_begin_session.
    """
    return _j(_engine().next_batch(session_id))


@mcp.tool()
def compliance_record_attempt(session_id: str, fingerprint: str,
                              strategy: str, notes: str = "") -> str:
    """Record the fix strategy you are about to apply to a finding. Call this
    BEFORE editing; the outcome is graded automatically at the next verify, and
    failed strategies are remembered so future sessions don't repeat them.

    Args:
        session_id: Active session id.
        fingerprint: Finding fingerprint being fixed.
        strategy: One line, e.g. "replace sprintf with snprintf(buf, sizeof buf, ...)".
        notes: Optional extra context.
    """
    return _j(_engine().record_attempt(session_id, fingerprint, strategy, notes))


@mcp.tool()
def compliance_verify(session_id: str) -> str:
    """Re-scan after your edits, grade every pending fix attempt, detect
    regressions, and decide the loop state: active | converged |
    budget_exhausted | stalled. Call after each editing round.

    Args:
        session_id: Active session id.
    """
    return _j(_engine().verify(session_id))


@mcp.tool()
def compliance_session_status(session_id: str) -> str:
    """Get a session's state, iteration count and per-iteration history.

    Args:
        session_id: Session id (or use the id from begin_session).
    """
    return _j(_engine().session_status(session_id))


@mcp.tool()
def compliance_import_sarif(path: str) -> str:
    """Import findings from an external SARIF 2.1.0 file into project memory, so
    a qualified/certified engine's output (Helix QAC, Polyspace, Parasoft,
    IAR C-STAT, or cppcheck's own --sarif) gets the same loop, memory, gate and
    deviation treatment as a native scan. Recognized MISRA/CERT ruleIds map onto
    the knowledge base; others are kept as `sarif:<ruleId>`. Imported findings
    are NOT cleared by native rescans.

    Args:
        path: Path to the SARIF file (relative to the project root or absolute).
    """
    return _j(_engine().import_sarif(path))


@mcp.tool()
def compliance_approve_finding(fingerprint: str, approved_by: str) -> str:
    """Human sign-off that a fix is genuinely correct, moving a finding from
    pending_verification to resolved. Required for high-severity and
    semantic-risk findings (casts, comparisons, sign conversions, control-flow
    changes) whose fix a passing test suite alone cannot vouch for — the
    analyzer only checks the pattern is gone, never that the edit preserved the
    intended behavior at sentinel/boundary values.

    Args:
        fingerprint: The pending finding's fingerprint (from compliance_verify).
        approved_by: Who is signing off — recorded in the audit trail.
    """
    return _j(_engine().approve(fingerprint, approved_by))


# ---------------------------------------------------- deviations/suppression
@mcp.tool()
def compliance_add_deviation(rule: str, scope: str, justification: str,
                             approver: str = "", expires_days: float = 0) -> str:
    """Record a formal, justified deviation from a rule (MISRA-style deviation
    record). Deviated findings stop counting against compliance but stay in the
    audit trail. Use sparingly and only with a real engineering justification.

    Args:
        rule: Rule reference, e.g. "MISRA 21.6".
        scope: Glob over project-relative file paths, e.g. "src/debug/*" or "*".
        justification: Engineering rationale (required, be specific).
        approver: Person/role approving the deviation.
        expires_days: Auto-expire after N days (0 = never).
    """
    meta = REGISTRY.resolve(rule)
    if not meta:
        return _j({"error": f"Unknown rule '{rule}'."})
    if len(justification.strip()) < 15:
        return _j({"error": "Justification too short; write a real engineering rationale."})
    did = _engine().mem.add_deviation(meta["id"], scope, justification, approver,
                                       expires_days or None)
    return _j({"deviation_id": did, "rule_id": meta["id"], "scope": scope,
               "note": "Re-run compliance_scan or compliance_verify to apply."})


@mcp.tool()
def compliance_suppress_finding(fingerprint: str, reason: str) -> str:
    """Mark one specific finding as a false positive. Requires a reason;
    suppressions are permanent for that fingerprint and audited.

    Args:
        fingerprint: The finding fingerprint.
        reason: Why this is a false positive.
    """
    eng = _engine()
    if not eng.mem.get_finding(fingerprint):
        return _j({"error": f"No finding with fingerprint '{fingerprint}'."})
    if len(reason.strip()) < 10:
        return _j({"error": "Reason too short; explain why the analyzer is wrong here."})
    eng.mem.suppress(fingerprint, reason)
    return _j({"suppressed": fingerprint})


# -------------------------------------------------------------------- memory
@mcp.tool()
def memory_note(content: str, topic: str = "", tags: str = "") -> str:
    """Persist project knowledge for future sessions: conventions, approved
    allocator/logging shims, architectural decisions, gotchas.

    Args:
        content: The knowledge itself (1-3 sentences works best).
        topic: Short label, e.g. "logging", "allocator", "naming".
        tags: Comma-separated tags; include rule ids or file paths to make the
            note surface automatically in related fix batches.
    """
    nid = _engine().mem.add_note(content, topic, tags)
    return _j({"note_id": nid})


@mcp.tool()
def memory_search(query: str, limit: int = 10) -> str:
    """Search persisted project memory notes.

    Args:
        query: Keyword, rule id, or file path.
        limit: Max results.
    """
    return _j(_engine().mem.search_notes(query, limit))


@mcp.tool()
def memory_stats() -> str:
    """Snapshot of everything the harness remembers about this project:
    finding lifecycle counts, deviations, suppressions, notes, fix attempts."""
    return _j(_engine().mem.stats())


# ------------------------------------------------------------------- reports
@mcp.tool()
def compliance_report(format: str = "markdown") -> str:
    """Generate an auditable compliance report from memory.

    Args:
        format: "markdown" (human review), "json" (matrix only) or
            "sarif" (CI / IDE problem panes).
    """
    mem = _engine().mem
    if format == "sarif":
        return _j(report_mod.sarif(mem))
    if format == "json":
        return _j(report_mod.compliance_matrix(mem))
    return report_mod.markdown_report(mem, project_name=_engine().root.name)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
