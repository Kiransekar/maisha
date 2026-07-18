"""cppcheck adapter.

Runs cppcheck with its MISRA addon (when the addon is available in the
cppcheck install) plus its general semantic checks, and normalizes output
into Findings. Semantic cppcheck IDs are mapped onto CERT C rules where a
faithful mapping exists; everything else is surfaced as supporting evidence
under a `cppcheck:<id>` rule so nothing is silently dropped.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import Analyzer
from ..model import Finding, enclosing_function, relpath
from ..rules import REGISTRY

# cppcheck error id -> CERT rule. Every target here must be a CERT rule present
# in the knowledge base (maishac/rules/cert_c.json) so it resolves to enriched
# metadata; an unmapped id falls through to a raw `cppcheck:<id>` finding.
CPPCHECK_TO_CERT = {
    "nullPointer": "EXP34-C", "nullPointerRedundantCheck": "EXP34-C",
    "nullPointerArithmetic": "EXP34-C", "nullPointerArithmeticRedundantCheck": "EXP34-C",
    "uninitvar": "EXP33-C", "uninitStructMember": "EXP33-C", "uninitdata": "EXP33-C",
    "arrayIndexOutOfBounds": "ARR30-C", "bufferAccessOutOfBounds": "ARR30-C",
    "outOfBounds": "ARR30-C", "negativeIndex": "ARR30-C", "pointerOutOfBounds": "ARR30-C",
    "negativeArraySize": "ARR32-C",
    "doubleFree": "MEM31-C", "deallocuse": "MEM30-C", "useAfterFree": "MEM30-C",
    "memleak": "MEM31-C", "memleakOnRealloc": "MEM31-C",
    "mismatchAllocDealloc": "MEM34-C", "autovarInvalidDeallocation": "MEM34-C",
    "zerodiv": "INT33-C", "zerodivcond": "INT33-C",
    "integerOverflow": "INT32-C", "signConversion": "INT31-C", "truncLongCastAssignment": "INT31-C",
    "returnDanglingLifetime": "DCL30-C", "danglingLifetime": "DCL30-C", "returnTempAddress": "DCL30-C",
    "autoVariables": "DCL30-C",
    "ignoredReturnValue": "ERR33-C", "leakReturnValNotUsed": "ERR33-C",
    "invalidscanf": "STR31-C", "bufferNotZeroTerminated": "STR32-C",
    "wrongmathcall": "FLP32-C",
    "va_start_wrongParameter": "MSC39-C",
}

# MISRA C:2012 rules the free cppcheck MISRA addon can actually raise, read off
# `addons/misra.py` at danmar/cppcheck@main. The addon reflects on its own source
# for `def misra_X_Y(` definitions (130 rules) and delegates a further 27 to
# cppcheck's core checkers; this is the union.
#
# Two caveats that matter for how COVERAGE.md reads this set:
#   * A `def misra_X_Y` existing means the check is *present*, not that it is
#     complete — many carry documented exceptions and false negatives. Treat this
#     as an upper bound on cppcheck's coverage.
#   * The addon targets MISRA C:2012 + Amendment 1 + Amendment 2 only (its own
#     header says so, and its rule total is 143). It implements *none* of
#     Amendment 3/4 — so any AMD3/AMD4 guideline added to the KB later is
#     native-or-nothing, and must not be credited to cppcheck here.
CPPCHECK_MISRA_IMPLEMENTED = frozenset(
    # implemented inside the addon itself
    "1.2 1.4 2.2 2.3 2.4 2.5 2.7 3.1 4.1 4.2 5.1 5.2 5.4 5.5 5.6 5.7 5.8 5.9 "
    "6.1 6.2 7.1 7.2 7.3 7.4 8.1 8.2 8.4 8.5 8.6 8.7 8.8 8.9 8.10 8.11 8.12 "
    "8.14 9.2 9.3 9.4 9.5 10.1 10.2 10.3 10.4 10.5 10.6 10.7 10.8 11.1 11.2 "
    "11.3 11.4 11.5 11.6 11.7 11.8 11.9 12.1 12.2 12.3 12.4 13.1 13.3 13.4 "
    "13.5 13.6 14.1 14.2 14.4 15.1 15.2 15.3 15.4 15.5 15.6 15.7 16.1 16.2 "
    "16.3 16.4 16.5 16.6 16.7 17.1 17.2 17.3 17.6 17.7 17.8 18.4 18.5 18.7 "
    "18.8 19.2 20.1 20.2 20.3 20.4 20.5 20.7 20.8 20.9 20.10 20.11 20.12 "
    "20.13 20.14 21.1 21.2 21.3 21.4 21.5 21.6 21.7 21.8 21.9 21.10 21.11 "
    "21.12 21.14 21.15 21.16 21.19 21.20 21.21 22.5 22.7 22.8 22.9 22.10 "
    # delegated to cppcheck's own core checkers
    "1.3 2.1 2.6 5.3 8.3 8.13 9.1 13.2 14.3 17.4 17.5 18.1 18.2 18.3 18.6 "
    "19.1 20.6 21.13 21.17 21.18 22.1 22.2 22.3 22.4 22.6".split())

# Rules in MISRA C:2012+AMD1/2 that the free addon does NOT implement at all.
CPPCHECK_MISRA_MISSING = frozenset({"1.1", "3.2", "12.5"})

_SEV_MAP = {"error": "critical", "warning": "major", "style": "minor",
            "performance": "minor", "portability": "minor", "information": "info"}

_MISRA_ID = re.compile(r"misra-c2012-(\d+\.\d+)")


class CppcheckAnalyzer(Analyzer):
    name = "cppcheck"
    requires = "cppcheck"
    options = "--addon=misra --enable=all (MISRA C:2012 addon)"

    def analyze(self, files: list[Path], root: Path,
                include_paths: list[str] | None = None) -> list[Finding]:
        if not files:
            return []
        # Without the project's own include dirs, cppcheck can't see headers like
        # FreeRTOSConfig.h, so it misreports "undefined identifier"/"unresolved
        # declaration" on macros and functions that are perfectly visible to a
        # real build — see BENCHMARKS.md for the measured false-positive cost.
        include_flags = [f"-I{p}" for p in (include_paths or [])]
        cmd = ["cppcheck", "--enable=all", "--inline-suppr", "--xml",
               "--suppress=missingIncludeSystem", "--suppress=unusedFunction",
               "--suppress=checkersReport", "--addon=misra"] \
              + include_flags + [str(f) for f in files]
        try:
            proc = self._run(cmd)
        except Exception:
            return []
        xml_text = proc.stderr
        if "<results" not in xml_text:
            # addon may be missing; retry without it
            cmd = [c for c in cmd if not c.startswith("--addon")]
            try:
                proc = self._run(cmd)
                xml_text = proc.stderr
            except Exception:
                return []
        return self._parse(xml_text, root)

    def _parse(self, xml_text: str, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            tree = ET.fromstring(xml_text)
        except ET.ParseError:
            return findings
        for err in tree.iter("error"):
            eid = err.get("id", "")
            msg = err.get("msg", "") or err.get("verbose", "")
            sev = _SEV_MAP.get(err.get("severity", "warning"), "major")
            loc = err.find("location")
            if loc is None:
                continue
            fpath = loc.get("file", "")
            line = int(loc.get("line", "0") or 0)
            col = int(loc.get("column", "0") or 0)
            rel = relpath(fpath, root)
            line_content, ctx_symbol = self._line_of(root, fpath, line)

            m = _MISRA_ID.match(eid)
            if m:
                meta = REGISTRY.resolve(f"MISRA {m.group(1)}") or {}
                rid = meta.get("id", f"MISRA-C:2012 Rule {m.group(1)}")
                summary = meta.get("summary", "")
                if not msg or msg.startswith("misra violation"):
                    msg = summary or f"MISRA C:2012 Rule {m.group(1)} violation"
                findings.append(Finding(
                    rule_id=rid, standard="MISRA-C:2012",
                    severity=meta.get("severity", sev), file=rel, line=line, column=col,
                    message=msg or summary, analyzer=self.name,
                    line_content=line_content, context_symbol=ctx_symbol, fix_hint=meta.get("fix", ""),
                    cross_refs=REGISTRY.cross_refs(rid) if meta else [],
                ))
            elif eid in CPPCHECK_TO_CERT:
                meta = REGISTRY.resolve(f"CERT {CPPCHECK_TO_CERT[eid]}") or {}
                rid = meta.get("id", f"CERT {CPPCHECK_TO_CERT[eid]}")
                findings.append(Finding(
                    rule_id=rid, standard="CERT-C",
                    severity=meta.get("severity", sev), file=rel, line=line, column=col,
                    message=msg, analyzer=self.name, line_content=line_content,
                    context_symbol=ctx_symbol, fix_hint=meta.get("fix", ""), cross_refs=REGISTRY.cross_refs(rid) if meta else [],
                ))
            elif err.get("severity") in ("error", "warning"):
                findings.append(Finding(
                    rule_id=f"cppcheck:{eid}", standard="generic", severity=sev,
                    file=rel, line=line, column=col, message=msg,
                    analyzer=self.name, line_content=line_content, context_symbol=ctx_symbol,
                ))
        return findings

    @staticmethod
    def _line_of(root: Path, fpath: str, line: int) -> tuple[str, str]:
        try:
            p = Path(fpath)
            if not p.is_absolute():
                p = root / fpath
            lines = p.read_text("utf-8", errors="replace").splitlines()
            if 0 < line <= len(lines):
                return lines[line - 1], enclosing_function(lines, line - 1)
            return "", ""
        except OSError:
            return "", ""
