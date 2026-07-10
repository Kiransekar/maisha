"""Compliance reporting.

Generates an auditable snapshot from memory: per-standard compliance matrix,
open findings by severity, deviation register, and SARIF export for CI and
IDE problem panes.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from .analyzers.cppcheck import CPPCHECK_TO_CERT
from .memory import MemoryStore
from .model import Finding, compute_fingerprint, relpath
from .rules import REGISTRY

_STANDARDS = ["MISRA-C:2012", "BARR-C:2018", "CERT-C"]

# SARIF result.level -> unified severity (used only when the rule isn't one we
# recognize; recognized rules take severity from the knowledge base).
_LEVEL_SEV = {"error": "critical", "warning": "major", "note": "minor", "none": "info"}
_SARIF_MISRA = re.compile(r"misra[_-]c?[-_]?2012[-_](\d+\.\d+)", re.I)
_SARIF_CERT = re.compile(r"\b([A-Z]{3}\d{2}-C)\b", re.I)


def _resolve_sarif_rule(rule_id: str) -> dict | None:
    """Best-effort map of a foreign SARIF ruleId onto a Maisha rule.
    Handles Maisha's own ids, MISRA (misra-c2012-21.3), CERT (cert-err34-c
    or ERR34-C) and cppcheck semantic ids (nullPointer -> EXP34-C)."""
    meta = REGISTRY.get(rule_id) or REGISTRY.resolve(rule_id)
    if meta:
        return meta
    m = _SARIF_MISRA.search(rule_id)
    if m:
        return REGISTRY.resolve(f"MISRA {m.group(1)}")
    m = _SARIF_CERT.search(rule_id)
    if m:
        return REGISTRY.resolve(f"CERT {m.group(1).upper()}")
    if rule_id in CPPCHECK_TO_CERT:
        return REGISTRY.resolve(f"CERT {CPPCHECK_TO_CERT[rule_id]}")
    return None


def parse_sarif(data: dict, root: Path) -> list[Finding]:
    """Parse SARIF 2.1.0 results into Findings. Reuses Maisha fingerprints
    from partialFingerprints when present (so its own export round-trips)."""
    findings: list[Finding] = []
    for run in data.get("runs", []):
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = (driver.get("name") or "sarif").lower()
        for res in run.get("results", []):
            rid_raw = res.get("ruleId") or ""
            loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
            uri = (loc.get("artifactLocation") or {}).get("uri") or ""
            region = loc.get("region") or {}
            line = int(region.get("startLine") or 0)
            col = int(region.get("startColumn") or 0)
            snippet = (region.get("snippet") or {}).get("text") or ""
            msg = (res.get("message") or {}).get("text") or ""
            level = res.get("level") or "warning"

            meta = _resolve_sarif_rule(rid_raw)
            if meta:
                rid, standard = meta["id"], meta["standard"]
                severity = meta.get("severity", _LEVEL_SEV.get(level, "major"))
                fix = meta.get("fix", "")
            else:
                rid, standard = f"sarif:{rid_raw}" if rid_raw else "sarif:unknown", "generic"
                severity, fix = _LEVEL_SEV.get(level, "major"), ""

            line_content = snippet.strip()
            if not line_content and uri and line:
                line_content = _read_line(root / uri, line)

            fp = (res.get("partialFingerprints") or {}).get("maishac/v1")
            if not fp:
                if line_content:
                    fp = compute_fingerprint(rid, relpath(root / uri, root), line_content)
                else:
                    # ponytail: no source line to anchor to — fall back to a
                    # location+message hash. Not line-stable, but external SARIF
                    # is re-imported wholesale, so identity only needs to be
                    # unique within one import. Upgrade: fetch the source line.
                    fp = hashlib.sha1(
                        f"{rid}\x1f{uri}\x1f{line}\x1f{col}\x1f{msg}".encode("utf-8", "replace")
                    ).hexdigest()[:16]

            findings.append(Finding(
                rule_id=rid, standard=standard, severity=severity, file=uri, line=line,
                column=col, message=msg, analyzer=f"sarif:{tool}",
                line_content=line_content, fix_hint=fix, fingerprint=fp,
                code_flow=_parse_code_flows(res)))
    return findings


def _parse_code_flows(res: dict) -> list[dict]:
    """Flatten SARIF codeFlows -> threadFlows -> locations into an ordered list
    of {file, line, message} steps. This is a qualified engine's core value-add
    (the data-flow path to the defect); Maisha carries it through to the agent
    briefing instead of dropping it. Only the first codeFlow is kept — engines
    emit alternates but the primary path is what a fixer needs."""
    steps: list[dict] = []
    for cf in (res.get("codeFlows") or [])[:1]:
        for tf in cf.get("threadFlows") or []:
            for loc in tf.get("locations") or []:
                inner = loc.get("location") or {}
                pl = inner.get("physicalLocation") or {}
                uri = (pl.get("artifactLocation") or {}).get("uri") or ""
                region = pl.get("region") or {}
                steps.append({
                    "file": uri,
                    "line": int(region.get("startLine") or 0),
                    "message": (inner.get("message") or {}).get("text") or "",
                })
    return steps


def _read_line(path: Path, line: int) -> str:
    try:
        lines = path.read_text("utf-8", errors="replace").splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""
    except OSError:
        return ""


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
            "pending_verification": sum(1 for r in rows if r["standard"] == std
                                        and r["status"] == "pending_verification"),
            "resolved_findings": sum(1 for r in rows if r["standard"] == std
                                     and r["status"] == "resolved"),
            "clean": not violated,
        }
    return matrix


def markdown_report(mem: MemoryStore, project_name: str = "") -> str:
    stats = mem.stats()
    matrix = compliance_matrix(mem)
    lines = [
        f"# Maisha Compliance Report{(' — ' + project_name) if project_name else ''}",
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
        "| Standard | Rules checked | Open | Pending | Resolved | Violated rules | Deviated rules | Clean |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for std, m in matrix.items():
        lines.append(
            f"| {std} | {m['rules_checked']} | {m['open_findings']} | "
            f"{m['pending_verification']} | {m['resolved_findings']} | "
            f"{', '.join(m['rules_violated']) or '—'} | {', '.join(m['rules_deviated']) or '—'} | "
            f"{'yes' if m['clean'] else 'no'} |")
    lines += ["", "## Open findings", ""]
    opens = mem.open_findings(limit=500)
    if not opens:
        lines.append("None.")
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


def _rule_descriptor(rid: str, fallback_msg: str = "") -> dict:
    meta = REGISTRY.get(rid) or {}
    return {
        "id": rid,
        "shortDescription": {"text": (meta.get("summary") or fallback_msg or rid)[:200]},
        "help": {"text": meta.get("fix", "")},
    }


def _code_flows_to_sarif(steps: list[dict]) -> list[dict]:
    return [{"threadFlows": [{"locations": [
        {"location": {
            "physicalLocation": {
                "artifactLocation": {"uri": s.get("file", "")},
                "region": {"startLine": max(1, int(s.get("line") or 1))},
            },
            "message": {"text": s.get("message", "")},
        }} for s in steps]}]}]


def sarif(mem: MemoryStore) -> dict:
    opens = mem.open_findings(limit=100000)
    rules_seen, results = {}, []
    for f in opens:
        rid = f["rule_id"]
        rules_seen.setdefault(rid, _rule_descriptor(rid, f["message"]))
        meta = REGISTRY.get(rid) or {}
        result = {
            "ruleId": rid,
            "level": {"blocker": "error", "critical": "error",
                      "major": "warning", "minor": "note", "info": "note"}.get(f["severity"], "warning"),
            "message": {"text": f["message"] or meta.get("summary", "")},
            "partialFingerprints": {"maishac/v1": f["fingerprint"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": max(1, f["line"]),
                               **({"startColumn": f["column"]} if f.get("column") else {})},
                }}],
        }
        # Carry an imported qualified-engine data-flow path back out, so an
        # import -> export round-trip preserves it.
        flow = f.get("code_flow")
        if flow:
            steps = json.loads(flow) if isinstance(flow, str) else flow
            if steps:
                result["codeFlows"] = _code_flows_to_sarif(steps)
        results.append(result)

    # Cross-standard equivalences as SARIF reportingDescriptor.relationships
    # (e.g. MISRA 21.3 <-> its CERT equivalent). Referenced rules are added as
    # descriptors so a consumer/re-import can resolve each relationship target.
    for rid in list(rules_seen):
        refs = REGISTRY.cross_refs(rid)
        if not refs:
            continue
        rels = []
        for ref in refs:
            rules_seen.setdefault(ref, _rule_descriptor(ref))
            rels.append({"target": {"id": ref}, "kinds": ["relevant"]})
        rules_seen[rid]["relationships"] = rels

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Maisha", "version": "0.2.0",
                                  "rules": list(rules_seen.values())}},
            "results": results,
        }],
    }


# --------------------------------------------------------------------------
# MISRA Compliance:2020 Guideline Compliance Summary (GCS)
# --------------------------------------------------------------------------
# The artifact a functional-safety assessor actually asks for: every enforced
# guideline classified Compliant / Deviations / Violations, tied to deviation
# permits, with the legality checks MISRA Compliance:2020 mandates (a Mandatory
# guideline may NOT be deviated or disapplied; Required may be deviated;
# Advisory may be deviated or disapplied). This is a *summary of recorded
# evidence*, not a certification — see the disclaimer in the rendered report.

_MISRA_STD = "MISRA-C:2012"
# Approx size of the full guideline set (143 rules + 16 directives + Amendment
# 1/2/3 security rules). Used only to state honest coverage, never to score.
_MISRA_UNIVERSE = 175

_STATUS_KEY = {"Compliant": "compliant", "Deviations": "deviations",
               "Violations": "violations", "Pending verification": "pending"}


def misra_compliance_summary(mem: MemoryStore) -> dict:
    rows = [dict(r) for r in mem.db.execute(
        "SELECT rule_id, status FROM findings WHERE standard=?", (_MISRA_STD,))]
    dev_by_rule: dict[str, list] = {}
    for d in mem.deviations():
        dev_by_rule.setdefault(d["rule_id"], []).append(d)

    enforced = REGISTRY.all_ids(_MISRA_STD)
    guidelines, blocking = [], []
    counts = {"compliant": 0, "deviations": 0, "violations": 0, "pending": 0}
    for gid in enforced:
        meta = REGISTRY.get(gid) or {}
        cat = meta.get("category", "required")
        gr = [r for r in rows if r["rule_id"] == gid]
        open_v = sum(1 for r in gr if r["status"] in ("open", "regressed"))
        pending = sum(1 for r in gr if r["status"] == "pending_verification")
        deviated = sum(1 for r in gr if r["status"] == "deviated")
        permits = dev_by_rule.get(gid, [])

        if open_v:
            status = "Violations"
        elif pending:
            status = "Pending verification"
        elif deviated or permits:
            status = "Deviations"
        else:
            status = "Compliant"

        # A Mandatory guideline can be neither deviated nor left in violation.
        is_blocking = cat == "mandatory" and status != "Compliant"
        if is_blocking:
            blocking.append(gid)
        counts[_STATUS_KEY[status]] += 1
        guidelines.append({
            "guideline": gid, "category": cat, "status": status,
            "open": open_v, "pending": pending, "deviated": deviated,
            "permits": len(permits), "blocking": is_blocking,
            "summary": meta.get("summary", ""),
        })

    if blocking:
        verdict = "NON-COMPLIANT — a Mandatory guideline is violated or deviated"
    elif counts["violations"]:
        verdict = "NON-COMPLIANT — open violations without a deviation permit"
    elif counts["pending"]:
        verdict = "PENDING — fixes recorded but not yet verified"
    elif counts["deviations"]:
        verdict = "COMPLIANT WITH DEVIATIONS"
    else:
        verdict = "COMPLIANT"

    return {
        "standard": _MISRA_STD,
        "verdict": verdict,
        "enforced": len(enforced),
        "not_checked": max(0, _MISRA_UNIVERSE - len(enforced)),
        "universe": _MISRA_UNIVERSE,
        "counts": counts,
        "guidelines": guidelines,
        "deviation_permits": mem.deviations(),
        "blocking_guidelines": blocking,
    }


def misra_compliance_markdown(mem: MemoryStore, project_name: str = "") -> str:
    s = misra_compliance_summary(mem)
    c = s["counts"]
    L = [
        f"# MISRA C:2012 Guideline Compliance Summary{(' — ' + project_name) if project_name else ''}",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} · Standard: {s['standard']}"
        " · Framework: MISRA Compliance:2020",
        "",
        f"## Verdict: **{s['verdict']}**",
        "",
        f"- Guidelines enforced by this configuration: **{s['enforced']}** of "
        f"~{s['universe']} (Amendments included). **{s['not_checked']} not checked** "
        "by Maisha — see coverage caveat below.",
        f"- Compliant: **{c['compliant']}** · With deviations: **{c['deviations']}** · "
        f"Pending verification: **{c['pending']}** · In violation: **{c['violations']}**",
    ]
    if s["blocking_guidelines"]:
        L += ["", "> ⚠ **Audit-blocking:** Mandatory guideline(s) not compliant — "
              f"{', '.join(s['blocking_guidelines'])}. MISRA Compliance:2020 permits "
              "no deviation or disapplication of a Mandatory guideline."]

    L += ["", "## Guideline compliance",
          "", "| Guideline | Category | Status | Open | Pending | Deviated | Permits |",
          "|---|---|---|---|---|---|---|"]
    order = {"Violations": 0, "Pending verification": 1, "Deviations": 2, "Compliant": 3}
    for g in sorted(s["guidelines"], key=lambda g: (order[g["status"]], g["guideline"])):
        mark = "🚫 " if g["blocking"] else ""
        L.append(f"| {g['guideline']} | {g['category']} | {mark}{g['status']} | "
                 f"{g['open']} | {g['pending']} | {g['deviated']} | {g['permits']} |")

    permits = s["deviation_permits"]
    L += ["", "## Deviation permits", ""]
    if not permits:
        L.append("None on record.")
    else:
        L += ["| Guideline | Scope | Justification | Approver | Expires |",
              "|---|---|---|---|---|"]
        for d in permits:
            exp = time.strftime("%Y-%m-%d", time.localtime(d["expires"])) if d.get("expires") else "—"
            appr = d.get("approver") or "**UNAPPROVED**"
            L.append(f"| {d['rule_id']} | `{d['scope']}` | {d['justification']} | {appr} | {exp} |")

    L += ["", "---", "",
          "*Coverage caveat:* Maisha enforces a curated subset of MISRA C:2012. "
          "Guidelines it does not check are reported as \"not checked\", **not** as "
          "compliant — for the remaining guidelines, layer a qualified engine's "
          "findings via `maishac import` and re-run this report.",
          "",
          "*Disclaimer:* This is a summary of the evidence recorded in Maisha's "
          "memory (findings, fixes, deviations, approvals). It is **not** a formal "
          "compliance certification and Maisha is not a qualified/proven-in-use "
          "analysis tool. Rule summaries are original paraphrases; consult the "
          "official MISRA C:2012 and MISRA Compliance:2020 documents for normative wording."]
    return "\n".join(L) + "\n"
