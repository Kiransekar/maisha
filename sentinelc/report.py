"""Compliance reporting.

Generates an auditable snapshot from memory: per-standard compliance matrix,
open findings by severity, deviation register, and SARIF export for CI and
IDE problem panes.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .memory import MemoryStore
from .rules import REGISTRY

_STANDARDS = ["MISRA-C:2012", "BARR-C:2018", "CERT-C"]


def compliance_matrix(mem: MemoryStore) -> dict:
    rows = [dict(r) for r in mem.db.execute("SELECT * FROM findings")]
    matrix = {}
    for std in _STANDARDS:
        checked = set(REGISTRY.all_ids(std))
        violated = {r["rule_id"] for r in rows
                    if r["standard"] == std and r["status"] in ("open", "regressed")}
        deviated = {d["rule_id"] for d in mem.deviations() if d["rule_id"] in checked}
        matrix[std] = {
            "rules_checked": len(checked),
            "rules_violated": sorted(violated),
            "rules_deviated": sorted(deviated),
            "open_findings": sum(1 for r in rows if r["standard"] == std
                                 and r["status"] in ("open", "regressed")),
            "resolved_findings": sum(1 for r in rows if r["standard"] == std
                                     and r["status"] == "resolved"),
            "clean": not violated,
        }
    return matrix


def markdown_report(mem: MemoryStore, project_name: str = "") -> str:
    stats = mem.stats()
    matrix = compliance_matrix(mem)
    lines = [
        f"# Sentinel-C Compliance Report{(' — ' + project_name) if project_name else ''}",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        f"Findings by status: {json.dumps(stats['findings_by_status'])}",
        f"Deviations on record: {stats['deviations']} · Suppressions: {stats['suppressions']}"
        f" · Fix attempts logged: {stats['fix_attempts']}",
        "",
        "## Standards matrix",
        "",
        "| Standard | Rules checked | Open | Resolved | Violated rules | Deviated rules | Clean |",
        "|---|---|---|---|---|---|---|",
    ]
    for std, m in matrix.items():
        lines.append(
            f"| {std} | {m['rules_checked']} | {m['open_findings']} | {m['resolved_findings']} | "
            f"{', '.join(m['rules_violated']) or '—'} | {', '.join(m['rules_deviated']) or '—'} | "
            f"{'✅' if m['clean'] else '❌'} |")
    lines += ["", "## Open findings", ""]
    opens = mem.open_findings(limit=500)
    if not opens:
        lines.append("None. 🎉")
    for f in opens:
        lines.append(f"- **{f['rule_id']}** ({f['severity']}, {f['status']}) "
                     f"`{f['file']}:{f['line']}` — {f['message']}")
    devs = mem.deviations()
    if devs:
        lines += ["", "## Deviation register", ""]
        for d in devs:
            lines.append(f"- **{d['rule_id']}** scope `{d['scope']}` — {d['justification']}"
                         f"{(' (approved by ' + d['approver'] + ')') if d['approver'] else ''}")
    return "\n".join(lines) + "\n"


def sarif(mem: MemoryStore) -> dict:
    opens = mem.open_findings(limit=100000)
    rules_seen, results = {}, []
    for f in opens:
        meta = REGISTRY.get(f["rule_id"]) or {}
        rid = f["rule_id"]
        rules_seen.setdefault(rid, {
            "id": rid,
            "shortDescription": {"text": meta.get("summary", f["message"])[:200]},
            "help": {"text": meta.get("fix", "")},
        })
        results.append({
            "ruleId": rid,
            "level": {"blocker": "error", "critical": "error",
                      "major": "warning", "minor": "note", "info": "note"}.get(f["severity"], "warning"),
            "message": {"text": f["message"] or meta.get("summary", "")},
            "partialFingerprints": {"sentinelc/v1": f["fingerprint"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": max(1, f["line"])},
                }}],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Sentinel-C", "version": "0.1.0",
                                  "rules": list(rules_seen.values())}},
            "results": results,
        }],
    }
