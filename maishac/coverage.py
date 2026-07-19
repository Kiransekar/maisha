"""Which rules can actually be detected, and by what.

Single source of truth for the enforced/reference split. Both `COVERAGE.md`
(via tools/gen_coverage.py) and the authoring-pattern completeness test read
from here, so the published table and the test gate can never disagree about
what the harness claims to detect.

Two tiers:

  * **enforced** — at least one analyzer we ship maps a check onto the rule.
    These carry the full obligation: an authoring pattern, fix guidance, and a
    place in the accuracy benchmark.
  * **reference** — no analyzer detects it. The entry still earns its place:
    cross-standard equivalence, deviation records, MISRA Guideline Enforcement
    Plan rows, and mapping external SARIF onto a known rule. It just must not
    be presented as something Maisha finds for you.

The external columns are an upper bound. A check existing in cppcheck or
clang-tidy is not a promise it fires on a given construct.
"""

from __future__ import annotations

import re
from pathlib import Path

from .rules import REGISTRY
from .analyzers.cppcheck import CPPCHECK_TO_CERT, CPPCHECK_MISRA_IMPLEMENTED
from .analyzers.clang_tidy import CLANG_TIDY_CERT_RULES
from .analyzers.compiler import WFLAG_TO_RULE

_NATIVE_SRC = Path(__file__).resolve().parent / "analyzers" / "native.py"
_RULE_QUERY = re.compile(r'"((?:MISRA|CERT|BARR)[^"]*)"')

# Rules where the native check implements a real but *partial* subset of what the
# guideline requires. MISRA Compliance:2020 requires a Guideline Enforcement Plan
# to record partial tool coverage explicitly, with the residual assigned to
# another means (a second tool, review, or proof) — so these must never render as
# plain "detected".
#
# Every entry here is a rule MISRA classifies Undecidable: a lexical analyzer can
# only ever catch a decidable slice of it. Detecting that slice is worth doing;
# claiming the whole rule is not.
NATIVE_PARTIAL = {
    "MISRA-C:2012 Rule 17.2":
        "direct self-recursion only - mutual recursion, and any cycle that "
        "crosses a translation unit, needs a whole-program call graph",
}


def native_ids() -> set[str]:
    """Canonical ids the native analyzer can emit, read from its own source.

    Deliberately derived from the code rather than hand-listed: adding a check
    to native.py updates the coverage table and the tier split automatically,
    so a new detector can't ship while the docs still say 'not detected'.
    """
    ids = set()
    for q in _RULE_QUERY.findall(_NATIVE_SRC.read_text("utf-8")):
        meta = REGISTRY.resolve(q)
        if meta:
            ids.add(meta["id"])
    return ids


def analyzers_for(rule_id: str, native: set[str] | None = None) -> list[str]:
    """Analyzers that map a check onto `rule_id`, in reporting order."""
    meta = REGISTRY.get(rule_id) or REGISTRY.resolve(rule_id)
    if not meta:
        return []
    rid, std = meta["id"], meta["standard"]
    native = native_ids() if native is None else native
    out = []
    if rid in native:
        out.append("native (partial)" if rid in NATIVE_PARTIAL else "native")
    num = rid.rsplit(" ", 1)[-1]
    if std == "MISRA-C:2012" and rid.startswith("MISRA-C:2012 Rule "):
        if num in CPPCHECK_MISRA_IMPLEMENTED:
            out.append("cppcheck")
    if std == "CERT-C":
        if num in CLANG_TIDY_CERT_RULES:
            out.append("clang-tidy")
        if num in set(CPPCHECK_TO_CERT.values()):
            out.append("cppcheck")
    if rid in _compiler_ids():
        out.append("compiler")
    return out


def _compiler_ids() -> set[str]:
    """Canonical ids the gcc/clang warning adapter maps a -W flag onto."""
    out = set()
    for ref in WFLAG_TO_RULE.values():
        meta = REGISTRY.resolve(ref)
        if meta:
            out.add(meta["id"])
    return out


def tier(rule_id: str, native: set[str] | None = None) -> str:
    """'enforced' if any analyzer detects the rule, else 'reference'."""
    return "enforced" if analyzers_for(rule_id, native) else "reference"


def toolchain_status(selected: list[str] | None = None) -> dict:
    """What this machine can detect right now, and what the gap costs.

    Maisha's native analyzer is zero-dependency and always runs, so a scan on a
    bare install *succeeds* — it just quietly checks a fraction of the rules it
    knows about. A clean result then reads exactly like a clean result from a
    full toolchain, which is the most dangerous failure mode a compliance tool
    can have. Every path that draws a conclusion (scan, session, report) calls
    this so the narrowing is stated rather than inferred.

    Availability only — no subprocess probes, since this runs on every scan.
    `maishac doctor` does the deeper checks (e.g. cppcheck present but missing
    its MISRA addon, which silently removes all MISRA findings).

    Args:
        selected: analyzer names the caller explicitly asked for, if any. An
            explicit narrowing is still reported, but as a choice rather than a
            missing dependency.
    """
    from .analyzers import ALL_ANALYZERS

    installed, missing = [], []
    for cls in ALL_ANALYZERS:
        an = cls()
        if an.available():
            installed.append(an.name)
        else:
            missing.append(an)

    usable = set(installed)
    if selected:
        usable &= set(selected)

    enforced = enforced_ids()
    native = native_ids()
    reachable = {rid for rid in enforced
                 if any(m.split(" ")[0] in usable for m in analyzers_for(rid, native))}

    gaps = []
    for an in missing:
        lost = sorted(rid for rid in enforced - reachable
                      if an.name in [m.split(" ")[0] for m in analyzers_for(rid, native)])
        if not lost:
            continue
        gaps.append({
            "analyzer": an.name,
            "needs": an.requires or "gcc, clang or cc",
            "rules_lost": len(lost),
            "examples": lost[:5],
        })
    gaps.sort(key=lambda g: -g["rules_lost"])

    deselected = sorted(set(installed) - usable) if selected else []
    total = len(enforced)
    return {
        "installed": sorted(installed),
        "selected": sorted(selected) if selected else None,
        "deselected": deselected,
        "missing": gaps,
        "rules_reachable": len(reachable),
        "rules_enforced_total": total,
        "rules_reference_only": len(reference_ids()),
        "coverage_pct": round(100 * len(reachable) / total, 1) if total else 0.0,
        "degraded": bool(gaps) or bool(deselected),
    }


def toolchain_warning(status: dict) -> str:
    """One-paragraph, human-readable version of a degraded toolchain, or ''.

    Deliberately blunt about what a clean scan does and does not mean here.
    """
    if not status["degraded"]:
        return ""
    L = [f"Reduced coverage: {status['rules_reachable']}/{status['rules_enforced_total']} "
         f"detectable rules active ({status['coverage_pct']:.0f}%)."]
    for g in status["missing"]:
        L.append(f"  - {g['analyzer']} not installed ({g['needs']}): "
                 f"{g['rules_lost']} rule(s) unchecked, e.g. "
                 + ", ".join(g["examples"][:3]))
    for name in status["deselected"]:
        L.append(f"  - {name} is installed but was not selected for this run")
    L.append("A clean result here does NOT mean the code is compliant with the "
             "rules above - they were never checked. Run `maishac doctor` for "
             "detail, or install the missing analyzers.")
    return "\n".join(L)


def enforced_ids(standard: str | None = None) -> set[str]:
    native = native_ids()
    return {r for r in REGISTRY.all_ids(standard)
            if analyzers_for(r, native)}


def reference_ids(standard: str | None = None) -> set[str]:
    native = native_ids()
    return {r for r in REGISTRY.all_ids(standard)
            if not analyzers_for(r, native)}
