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
_SARIF_MISRA = re.compile(r"misra[_-]c?[-_]?20\d\d[-_ ]?(?:rule[-_ ]?|dir(?:ective)?[-_ ]?)?(\d+\.\d+)", re.I)
_SARIF_MISRA_WORD = re.compile(r"\b(?:rule|dir(?:ective)?)\s*(\d+\.\d+)\b", re.I)
_SARIF_BARE_NUM = re.compile(r"^\s*(\d+\.\d+)\s*$")
_SARIF_CERT = re.compile(r"\b([A-Z]{3}\d{2}-C)\b", re.I)
# Results whose kind is not a genuine defect must not be imported as violations.
_NON_DEFECT_KINDS = {"pass", "notApplicable", "informational", "open", "review"}


def _resolve_sarif_rule(rule_id: str) -> dict | None:
    """Best-effort map of a foreign SARIF ruleId / taxon id onto a Maisha rule.
    Handles Maisha's own ids, MISRA in many forms (``misra-c2012-21.3``,
    ``MISRA C 2012 Rule 21.3``, ``Rule 21.3``, bare ``21.3``), CERT
    (``cert-err34-c``, ``ERR34-C``) and cppcheck semantic ids
    (``nullPointer`` -> EXP34-C)."""
    if not rule_id:
        return None
    meta = REGISTRY.get(rule_id) or REGISTRY.resolve(rule_id)
    if meta:
        return meta
    for pat in (_SARIF_MISRA, _SARIF_MISRA_WORD, _SARIF_BARE_NUM):
        m = pat.search(rule_id)
        if m and (r := REGISTRY.resolve(f"MISRA {m.group(1)}")):
            return r
    m = _SARIF_CERT.search(rule_id)
    if m and (r := REGISTRY.resolve(f"CERT {m.group(1).upper()}")):
        return r
    if rule_id in CPPCHECK_TO_CERT:
        return REGISTRY.resolve(f"CERT {CPPCHECK_TO_CERT[rule_id]}")
    return None


def _norm_uri(uri: str) -> str:
    """Normalize a SARIF artifactLocation URI to a project-relative-ish path:
    strip file:// schemes and leading ./ so fingerprints and file lookups are
    stable across engines that emit absolute/scheme-prefixed URIs."""
    if not uri:
        return ""
    if uri.startswith("file://"):
        uri = uri[7:]
        if len(uri) > 2 and uri[0] == "/" and uri[2] == ":":  # file:///C:/...
            uri = uri[1:]
    while uri.startswith("./"):
        uri = uri[2:]
    return uri


def _run_indexes(run: dict) -> tuple[list[dict], list[list[dict]]]:
    """Return (driver rule descriptors, taxonomy taxa lists) for a run, so
    results can be resolved by ruleIndex and rules can be mapped to standard
    guidelines via their relationships into a taxonomy."""
    driver = (run.get("tool") or {}).get("driver") or {}
    rules = driver.get("rules") or []
    taxonomies = [(t.get("taxa") or []) for t in (run.get("taxonomies") or [])]
    return rules, taxonomies


def _result_descriptor(res: dict, rules: list[dict]) -> dict:
    """Locate a result's reportingDescriptor via result.rule (index/id),
    result.ruleIndex, or result.ruleId — whichever the tool used."""
    ref = res.get("rule") or {}
    idx = ref.get("index")
    if idx is None:
        idx = res.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        return rules[idx]
    rid = ref.get("id") or res.get("ruleId")
    if rid:
        for r in rules:
            if r.get("id") == rid:
                return r
    return {}


def _guideline_candidates(res: dict, desc: dict, taxonomies: list[list[dict]]) -> list[str]:
    """Ordered candidate ids to map onto the registry. Taxonomy guideline ids
    (reached via the rule's relationships — how Helix QAC / Coverity attach the
    MISRA/CERT number to a checker-specific ruleId like ``ABV.GENERAL``) come
    first, then the ruleId / descriptor id / name strings."""
    cands: list[str] = []
    for rel in desc.get("relationships") or []:
        tgt = rel.get("target") or {}
        if tgt.get("id"):
            cands.append(tgt["id"])
        tc = (tgt.get("toolComponent") or {}).get("index")
        ti = tgt.get("index")
        if isinstance(tc, int) and isinstance(ti, int) and 0 <= tc < len(taxonomies):
            taxa = taxonomies[tc]
            if 0 <= ti < len(taxa):
                tax = taxa[ti]
                cands += [tax.get("id", ""), tax.get("name", "")]
    for taxon in res.get("taxa") or []:            # some tools attach taxa to the result
        cands.append(taxon.get("id", ""))
    cands += [res.get("ruleId") or "", desc.get("id") or "", desc.get("name") or ""]
    seen, out = set(), []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _primary_location(res: dict) -> dict:
    for loc in res.get("locations") or []:
        if loc.get("physicalLocation"):
            return loc["physicalLocation"]
    return {}


def parse_sarif(data: dict, root: Path) -> list[Finding]:
    """Parse SARIF 2.1.0 results from any tool into Findings, robustly across
    real qualified-engine dialects. Handles ruleId / ruleIndex / result.rule,
    taxonomy+relationship guideline mapping, defaultConfiguration levels,
    result.kind / baselineState filtering, multi-location results, missing
    regions, scheme-prefixed URIs, and reuses Maisha's partialFingerprints so
    its own export round-trips."""
    findings: list[Finding] = []
    for run in data.get("runs", []):
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = (driver.get("name") or "sarif").lower()
        rules, taxonomies = _run_indexes(run)
        for res in run.get("results", []):
            # Only genuine defects. kind defaults to "fail"; skip pass/etc.,
            # and skip findings a baseline marks as no longer present.
            if (res.get("kind") or "fail") in _NON_DEFECT_KINDS:
                continue
            if res.get("baselineState") == "absent":
                continue

            desc = _result_descriptor(res, rules)
            phys = _primary_location(res)
            uri = _norm_uri((phys.get("artifactLocation") or {}).get("uri") or "")
            region = phys.get("region") or {}
            line = int(region.get("startLine") or 0)
            col = int(region.get("startColumn") or 0)
            snippet = (region.get("snippet") or {}).get("text") or ""
            msg = (res.get("message") or {}).get("text") or ""
            level = (res.get("level")
                     or (desc.get("defaultConfiguration") or {}).get("level")
                     or "warning")

            candidates = _guideline_candidates(res, desc, taxonomies)
            meta = next((m for c in candidates if (m := _resolve_sarif_rule(c))), None)
            if meta:
                rid, standard = meta["id"], meta["standard"]
                severity = meta.get("severity", _LEVEL_SEV.get(level, "major"))
                fix = meta.get("fix", "")
            else:
                raw = next((c for c in candidates if c), "unknown")
                rid, standard = f"sarif:{raw}", "generic"
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
                code_flow=_parse_code_flows(res), suppression=_parse_suppression(res)))
    return findings


def _parse_suppression(res: dict) -> dict:
    """Read SARIF result.suppressions. A result is suppressed unless every
    entry is explicitly rejected (SARIF 2.1.0 §3.27.23). Returns {justification,
    kind} for a carried-over suppression, or {} if the result is live."""
    supps = res.get("suppressions")
    if not supps:
        return {}
    active = [s for s in supps if (s.get("status") or "accepted") != "rejected"]
    if not active:
        return {}
    just = "; ".join(s["justification"] for s in active
                     if s.get("justification")) or "suppressed in imported SARIF"
    return {"justification": just, "kind": active[0].get("kind", "")}


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
            "tool": {"driver": {"name": "Maisha", "version": "0.3.0",
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
               "Violations": "violations", "Pending verification": "pending",
               "Disapplied": "disapplied"}


def misra_compliance_summary(mem: MemoryStore) -> dict:
    rows = [dict(r) for r in mem.db.execute(
        "SELECT rule_id, status FROM findings WHERE standard=?", (_MISRA_STD,))]
    dev_by_rule: dict[str, list] = {}
    for d in mem.deviations():
        dev_by_rule.setdefault(d["rule_id"], []).append(d)
    recats = mem.recategorizations()  # GRP: rule_id -> {to_category, ...}

    enforced = REGISTRY.all_ids(_MISRA_STD)
    guidelines, blocking = [], []
    counts = {"compliant": 0, "deviations": 0, "violations": 0, "pending": 0, "disapplied": 0}
    for gid in enforced:
        meta = REGISTRY.get(gid) or {}
        base_cat = meta.get("category", "required")
        recat = recats.get(gid)
        cat = recat["to_category"] if recat else base_cat  # effective category (post-GRP)
        gr = [r for r in rows if r["rule_id"] == gid]
        open_v = sum(1 for r in gr if r["status"] in ("open", "regressed"))
        pending = sum(1 for r in gr if r["status"] == "pending_verification")
        deviated = sum(1 for r in gr if r["status"] == "deviated")
        permits = dev_by_rule.get(gid, [])

        if cat == "disapplied":
            # Removed from the compliance argument by an agreed GRP entry;
            # violations are neither counted nor blocking.
            status = "Disapplied"
        elif open_v:
            status = "Violations"
        elif pending:
            status = "Pending verification"
        elif deviated or permits:
            status = "Deviations"
        else:
            status = "Compliant"

        # A Mandatory guideline (post-GRP) can be neither deviated nor left in violation.
        is_blocking = cat == "mandatory" and status not in ("Compliant",)
        if is_blocking:
            blocking.append(gid)
        counts[_STATUS_KEY[status]] += 1
        guidelines.append({
            "guideline": gid, "category": cat, "base_category": base_cat,
            "recategorized": bool(recat), "status": status,
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
        "recategorizations": list(recats.values()),
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
        f"Pending verification: **{c['pending']}** · In violation: **{c['violations']}** · "
        f"Disapplied (GRP): **{c['disapplied']}**",
    ]
    if s["blocking_guidelines"]:
        L += ["", "> ⚠ **Audit-blocking:** Mandatory guideline(s) not compliant — "
              f"{', '.join(s['blocking_guidelines'])}. MISRA Compliance:2020 permits "
              "no deviation or disapplication of a Mandatory guideline."]

    L += ["", "## Guideline compliance",
          "", "| Guideline | Category | Status | Open | Pending | Deviated | Permits |",
          "|---|---|---|---|---|---|---|"]
    order = {"Violations": 0, "Pending verification": 1, "Deviations": 2,
             "Disapplied": 3, "Compliant": 4}
    for g in sorted(s["guidelines"], key=lambda g: (order[g["status"]], g["guideline"])):
        mark = "🚫 " if g["blocking"] else ""
        cat = g["category"] + (" *(re-cat)*" if g["recategorized"] else "")
        L.append(f"| {g['guideline']} | {cat} | {mark}{g['status']} | "
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


# --------------------------------------------------------------------------
# Guideline Enforcement Plan (GEP) — MISRA Compliance:2020 §3.3
# --------------------------------------------------------------------------
# "A GEP listing each guideline ... shall indicate how compliance is to be
# checked" and, for each tool, record its version, config, options, and evidence
# it can detect the guidelines it checks. Maisha generates this over the
# guidelines it enforces, records the live tool inventory, and honestly flags
# the remainder of the standard as requiring a separately-assigned method.

def enforcement_tools(mem: MemoryStore) -> list[dict]:
    """The tool inventory for the GEP: every static-analysis tool that could be
    enforcing guidelines here — Maisha's active analyzers (with live versions +
    options) plus any external engine whose SARIF was imported into memory."""
    from .analyzers import available_analyzers
    tools = [{
        "tool": a.name, "version": a.version(), "options": a.options,
        "kind": "native" if a.requires is None else "external analyzer",
    } for a in available_analyzers()]
    # engines whose findings arrived via `maishac import` (analyzer = "sarif:<tool>")
    imported = sorted({r["analyzer"] for r in mem.db.execute(
        "SELECT DISTINCT analyzer FROM findings WHERE analyzer LIKE 'sarif:%'")})
    for a in imported:
        tools.append({"tool": a.split("sarif:", 1)[1], "version": "(from imported SARIF)",
                      "options": "imported via SARIF 2.1.0", "kind": "imported qualified engine"})
    return tools


def guideline_enforcement_plan(mem: MemoryStore) -> dict:
    summary = misra_compliance_summary(mem)
    tools = enforcement_tools(mem)
    tool_names = [t["tool"] for t in tools]
    # which guidelines have an observed detection in this project (strong evidence)
    observed = {r["rule_id"] for r in mem.db.execute(
        "SELECT DISTINCT rule_id FROM findings WHERE standard=?", (_MISRA_STD,))}
    rows = []
    for g in summary["guidelines"]:
        gid = g["guideline"]
        rows.append({
            "guideline": gid, "category": g["category"],
            "method": "Static analysis",
            "checked_by": tool_names,
            "evidence": "observed in project" if gid in observed else "configured (tooling covers it)",
        })
    return {"standard": _MISRA_STD, "tools": tools, "guidelines": rows,
            "enforced": summary["enforced"], "not_checked": summary["not_checked"],
            "universe": summary["universe"]}


def guideline_enforcement_markdown(mem: MemoryStore, project_name: str = "") -> str:
    gep = guideline_enforcement_plan(mem)
    L = [
        f"# MISRA C:2012 Guideline Enforcement Plan (GEP){(' — ' + project_name) if project_name else ''}",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} · Standard: {gep['standard']}"
        " · Framework: MISRA Compliance:2020 §3.3",
        "",
        "## Enforcement tools",
        "",
        "| Tool | Version | Options | Role |",
        "|---|---|---|---|",
    ]
    for t in gep["tools"]:
        L.append(f"| {t['tool']} | {t['version']} | {t['options']} | {t['kind']} |")
    if not gep["tools"]:
        L.append("| _(none active)_ | | | |")

    L += ["", "## Per-guideline enforcement", "",
          f"This plan covers the **{gep['enforced']}** guidelines Maisha enforces. "
          f"The remaining **{gep['not_checked']}** of ~{gep['universe']} MISRA C:2012 "
          "guidelines are **not covered by this plan** and must be assigned an "
          "enforcement method (compiler, an additional/qualified tool, or manual "
          "review) — layer a qualified engine's SARIF via `maishac import` to extend "
          "coverage, then regenerate.",
          "",
          "| Guideline | Category | Method | Checked by | Detection evidence |",
          "|---|---|---|---|---|"]
    for r in sorted(gep["guidelines"], key=lambda r: r["guideline"]):
        L.append(f"| {r['guideline']} | {r['category']} | {r['method']} | "
                 f"{', '.join(r['checked_by']) or '—'} | {r['evidence']} |")

    L += ["", "---", "",
          "*Detection evidence:* \"observed in project\" means at least one violation "
          "of that guideline was produced by the tooling on this codebase. Maisha's "
          "own regression tests and `examples/bad.c` provide standing evidence that "
          "the native analyzer detects the guidelines it claims.",
          "",
          "*Disclaimer:* Maisha is a workflow/orchestration layer, not a "
          "qualified/proven-in-use analysis tool. For tool-qualification evidence "
          "(ISO 26262, DO-330, IEC 61508), the qualified engine you layer via SARIF "
          "is the qualified component; record its qualification artifacts alongside "
          "this plan."]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# Guideline Re-categorization Plan (GRP) — MISRA Compliance:2020 §5.4
# --------------------------------------------------------------------------

def guideline_recategorization_markdown(mem: MemoryStore, project_name: str = "") -> str:
    recats = mem.recategorizations()
    L = [
        f"# MISRA C:2012 Guideline Re-categorization Plan (GRP){(' — ' + project_name) if project_name else ''}",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} · Standard: {_MISRA_STD}"
        " · Framework: MISRA Compliance:2020 §5.4",
        "",
        "Agreed re-categorizations for this project. MISRA permits: Advisory → "
        "Mandatory/Required/Disapplied; Required → Mandatory only; a **Mandatory "
        "guideline may not be re-categorized in any way**. Maisha enforces these "
        "rules when a re-categorization is recorded (`maishac recategorize`).",
        "",
    ]
    if not recats:
        L.append("No re-categorizations on record — every guideline retains its "
                 "default MISRA category.")
        return "\n".join(L) + "\n"
    L += ["| Guideline | Original category | Re-categorized to | Rationale | Approver |",
          "|---|---|---|---|---|"]
    for gid, r in recats.items():
        meta = REGISTRY.get(gid) or {}
        base = meta.get("category", "—")
        appr = r.get("approver") or "**UNAPPROVED**"
        L.append(f"| {gid} | {base} | {r['to_category']} | {r['rationale']} | {appr} |")
    return "\n".join(L) + "\n"
