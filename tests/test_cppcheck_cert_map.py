"""Issue #5: newly-mapped cppcheck ids resolve to their CERT rules.

Feeds the cppcheck adapter synthetic XML carrying the ids added to
CPPCHECK_TO_CERT this change, and asserts each becomes an enriched CERT finding
(with knowledge-base metadata) rather than a raw `cppcheck:<id>` evidence line.
No cppcheck install needed — the tool's `_run` is monkeypatched.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from maishac.analyzers.cppcheck import CppcheckAnalyzer, CPPCHECK_TO_CERT
from maishac.rules import REGISTRY

# ids added this change -> expected CERT rule id
NEWLY_MAPPED = {
    "nullPointerArithmetic": "CERT EXP34-C",
    "uninitdata": "CERT EXP33-C",
    "pointerOutOfBounds": "CERT ARR30-C",
    "negativeArraySize": "CERT ARR32-C",
    "memleakOnRealloc": "CERT MEM31-C",
    "autoVariables": "CERT DCL30-C",
    "wrongmathcall": "CERT FLP32-C",
}


def _xml(ids):
    errs = "".join(
        f'<error id="{eid}" severity="error" msg="{eid} problem">'
        f'<location file="src/a.c" line="{10 + i}" column="1"/></error>'
        for i, eid in enumerate(ids))
    return f'<?xml version="1.0"?><results version="2">{errs}</results>'


# Pre-existing mappings whose CERT rule is not yet in the knowledge base (they
# still produce a finding, just without enriched metadata). Tracked so the guard
# below stays honest without failing on gaps this change did not introduce.
_KB_GAPS = {"MSC39-C"}


def test_mapping_targets_exist_in_the_kb():
    """Every CERT target resolves to knowledge-base metadata (except documented,
    pre-existing gaps) — so a mapped id becomes an enriched finding, not a raw
    passthrough."""
    for eid, cert in CPPCHECK_TO_CERT.items():
        if cert in _KB_GAPS:
            continue
        assert REGISTRY.resolve(f"CERT {cert}"), \
            f"CPPCHECK_TO_CERT['{eid}'] -> CERT {cert} is not in the knowledge base"


def test_newly_mapped_ids_become_enriched_cert_findings(monkeypatch, tmp_path):
    an = CppcheckAnalyzer()
    monkeypatch.setattr(an, "_run",
                        lambda cmd, timeout=300: subprocess.CompletedProcess(
                            ["x"], 0, stdout="", stderr=_xml(list(NEWLY_MAPPED))))
    findings = {f.rule_id: f for f in an.analyze([Path("src/a.c")], tmp_path)}

    for cppcheck_id, expected in NEWLY_MAPPED.items():
        assert expected in findings, f"{cppcheck_id} did not map to {expected}"
        f = findings[expected]
        assert f.standard == "CERT-C"
        assert f.analyzer == "cppcheck"
        # enriched, not a raw sarif:/cppcheck: passthrough
        assert not f.rule_id.startswith(("cppcheck:", "sarif:"))
