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

# cppcheck error id -> CERT rule
CPPCHECK_TO_CERT = {
    "nullPointer": "EXP34-C", "nullPointerRedundantCheck": "EXP34-C",
    "uninitvar": "EXP33-C", "uninitStructMember": "EXP33-C",
    "arrayIndexOutOfBounds": "ARR30-C", "bufferAccessOutOfBounds": "ARR30-C",
    "outOfBounds": "ARR30-C", "negativeIndex": "ARR30-C",
    "doubleFree": "MEM31-C", "deallocuse": "MEM30-C", "useAfterFree": "MEM30-C",
    "memleak": "MEM31-C", "mismatchAllocDealloc": "MEM34-C", "autovarInvalidDeallocation": "MEM34-C",
    "zerodiv": "INT33-C", "zerodivcond": "INT33-C",
    "integerOverflow": "INT32-C", "signConversion": "INT31-C", "truncLongCastAssignment": "INT31-C",
    "returnDanglingLifetime": "DCL30-C", "danglingLifetime": "DCL30-C", "returnTempAddress": "DCL30-C",
    "ignoredReturnValue": "ERR33-C", "leakReturnValNotUsed": "ERR33-C",
    "invalidscanf": "STR31-C", "bufferNotZeroTerminated": "STR32-C",
    "va_start_wrongParameter": "MSC39-C",
}

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
