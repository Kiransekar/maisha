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
        "direct self-recursion only — mutual recursion, and any cycle that "
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
    return out


def tier(rule_id: str, native: set[str] | None = None) -> str:
    """'enforced' if any analyzer detects the rule, else 'reference'."""
    return "enforced" if analyzers_for(rule_id, native) else "reference"


def enforced_ids(standard: str | None = None) -> set[str]:
    native = native_ids()
    return {r for r in REGISTRY.all_ids(standard)
            if analyzers_for(r, native)}


def reference_ids(standard: str | None = None) -> set[str]:
    native = native_ids()
    return {r for r in REGISTRY.all_ids(standard)
            if not analyzers_for(r, native)}
