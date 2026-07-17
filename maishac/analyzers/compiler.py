"""Compiler-warnings adapter (gcc / clang -Wall -Wextra).

A C compiler at a high warning level is a legitimate MISRA/BARR-C enforcement
source — it flags exactly the kind of latent defects (sign-compare, uninitialized
reads, VLAs, float equality, ignored results) several guidelines target, and the
GEP can cite it as a checking tool. This adapter runs the compiler in
syntax-only mode, parses `file:line:col: warning: msg [-Wflag]`, and maps the
`-Wflag` onto a registry rule where a clear equivalence exists; unmapped warnings
survive as `compiler:-Wflag` evidence. It degrades to nothing when no compiler is
installed.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from .base import Analyzer
from ..model import Finding, enclosing_function, relpath
from ..rules import REGISTRY

# gcc/clang `-Wflag` -> registry rule (fuzzy id). Only clear, defensible
# equivalences; every target must resolve in the knowledge base.
WFLAG_TO_RULE = {
    "vla": "MISRA 18.8",                       # variable-length array
    "vla-extension": "MISRA 18.8",
    "float-equal": "CERT FLP37-C",             # exact float comparison
    "switch": "MISRA 16.4",                    # switch missing a case/default
    "switch-default": "MISRA 16.4",
    "uninitialized": "CERT EXP33-C",           # read of uninitialized object
    "maybe-uninitialized": "CERT EXP33-C",
    "sometimes-uninitialized": "CERT EXP33-C",
    "sign-compare": "CERT INT31-C",            # signed/unsigned comparison
    "sign-conversion": "CERT INT31-C",
    "unused-result": "MISRA 17.7",             # ignored non-void return
}

_DIAG = re.compile(
    # non-greedy file group so a Windows drive-letter colon isn't mistaken for
    # the line:col separator (same care as the clang-tidy adapter).
    r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+):\s+(?P<sev>warning|error):\s+"
    r"(?P<msg>.*?)\s+\[-W(?P<flag>[\w=+-]+)\]\s*$", re.MULTILINE)


class CompilerAnalyzer(Analyzer):
    name = "compiler"
    requires = None  # resolved dynamically (gcc or clang); see available()
    options = "-fsyntax-only -Wall -Wextra (gcc/clang warnings)"

    @staticmethod
    def _compiler() -> str | None:
        for cc in ("gcc", "clang", "cc"):
            if shutil.which(cc):
                return cc
        return None

    def available(self) -> bool:
        return self._compiler() is not None

    def version(self) -> str:
        cc = self._compiler()
        if not cc:
            return "unknown"
        try:
            proc = self._run([cc, "--version"], timeout=10)
            first = (proc.stdout or proc.stderr).strip().splitlines()
            return first[0].strip() if first else cc
        except Exception:  # noqa: BLE001 — a missing/odd compiler must not break the GEP
            return cc

    def analyze(self, files: list[Path], root: Path,
                include_paths: list[str] | None = None) -> list[Finding]:
        cc = self._compiler()
        if not cc:
            return []
        c_files = [f for f in files if f.suffix == ".c"]
        if not c_files:
            return []
        include_flags = [f"-I{p}" for p in (include_paths or [])]
        # -fsyntax-only: warn without producing objects or linking. Compile each
        # file on its own so one file's fatal error (a missing header) can't
        # suppress warnings from the others.
        findings: list[Finding] = []
        for f in c_files:
            cmd = [cc, "-fsyntax-only", "-std=c11", "-Wall", "-Wextra"] \
                + include_flags + [str(f)]
            try:
                proc = self._run(cmd, timeout=120)
            except Exception:  # noqa: BLE001 — degrade to no findings on launch failure
                continue
            findings.extend(self._parse(proc.stdout + "\n" + proc.stderr, root))
        return findings

    def _parse(self, text: str, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for m in _DIAG.finditer(text):
            flag = m.group("flag").split("=", 1)[0]  # -Wformat=2 -> format
            fpath = m.group("file")
            rel = relpath(fpath, root)
            line = int(m.group("line"))
            line_content, ctx = self._line_of(root, fpath, line)
            ref = WFLAG_TO_RULE.get(flag)
            meta = REGISTRY.resolve(ref) if ref else None
            if meta:
                findings.append(Finding(
                    rule_id=meta["id"], standard=meta["standard"],
                    severity=meta.get("severity", "major"),
                    file=rel, line=line, column=int(m.group("col")),
                    message=m.group("msg"), analyzer=self.name,
                    line_content=line_content, context_symbol=ctx,
                    fix_hint=meta.get("fix", ""), cross_refs=REGISTRY.cross_refs(meta["id"]),
                ))
            else:
                findings.append(Finding(
                    rule_id=f"compiler:-W{flag}", standard="generic",
                    severity="major" if m.group("sev") == "warning" else "critical",
                    file=rel, line=line, column=int(m.group("col")),
                    message=m.group("msg"), analyzer=self.name,
                    line_content=line_content, context_symbol=ctx))
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
