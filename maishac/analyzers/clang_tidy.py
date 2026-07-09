"""clang-tidy adapter.

Enables the cert-* check group (plus bugprone/clang-analyzer evidence) and
maps diagnostics back onto CERT C rules by their check name, e.g.
`cert-err34-c` -> `CERT ERR34-C`.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer
from ..model import Finding, enclosing_function, relpath
from ..rules import REGISTRY

_DIAG = re.compile(
    r"^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s+(?P<sev>warning|error):\s+"
    r"(?P<msg>.*?)\s+\[(?P<check>[\w\-.,]+)\]\s*$", re.MULTILINE)
_CERT_CHECK = re.compile(r"cert-([a-z]{3}\d{2})-c")


class ClangTidyAnalyzer(Analyzer):
    name = "clang-tidy"
    requires = "clang-tidy"

    def analyze(self, files: list[Path], root: Path,
                include_paths: list[str] | None = None) -> list[Finding]:
        if not files:
            return []
        c_files = [f for f in files if f.suffix == ".c"]
        if not c_files:
            return []
        # Without include dirs, clang-tidy can't find project headers ("file not
        # found") and never parses the file at all — see BENCHMARKS.md.
        include_flags = [f"-I{p}" for p in (include_paths or [])]
        cmd = ["clang-tidy", "--quiet",
               "--checks=-*,cert-*,bugprone-*,clang-analyzer-*"] \
              + [str(f) for f in c_files] + ["--", "-std=c11"] + include_flags
        try:
            proc = self._run(cmd, timeout=600)
        except Exception:
            return []
        findings = []
        for m in _DIAG.finditer(proc.stdout + "\n" + proc.stderr):
            check = m.group("check")
            cm = _CERT_CHECK.search(check)
            fpath = m.group("file")
            rel = relpath(fpath, root)
            line = int(m.group("line"))
            line_content, ctx_symbol = self._line_of(root, fpath, line)
            if cm:
                meta = REGISTRY.resolve(f"CERT {cm.group(1).upper()}-C") or {}
                rid = meta.get("id", f"CERT {cm.group(1).upper()}-C")
                findings.append(Finding(
                    rule_id=rid, standard="CERT-C",
                    severity=meta.get("severity", "critical"),
                    file=rel, line=line, column=int(m.group("col")),
                    message=m.group("msg"), analyzer=self.name,
                    line_content=line_content, context_symbol=ctx_symbol,
                    fix_hint=meta.get("fix", ""),
                ))
            else:
                findings.append(Finding(
                    rule_id=f"clang-tidy:{check}", standard="generic",
                    severity="major" if m.group("sev") == "warning" else "critical",
                    file=rel, line=line, column=int(m.group("col")),
                    message=m.group("msg"), analyzer=self.name,
                    line_content=line_content, context_symbol=ctx_symbol,
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
