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
    # `file` is non-greedy .+? rather than [^:\n]+ so a Windows drive-letter
    # colon ("D:\path\file.c") doesn't get mistaken for the line:col
    # separator — clang-tidy always emits absolute (drive-letter) paths in
    # its diagnostics on Windows regardless of how the path was passed in,
    # and the old pattern silently matched zero diagnostics as a result.
    r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+):\s+(?P<sev>warning|error):\s+"
    r"(?P<msg>.*?)\s+\[(?P<check>[\w\-.,]+)\]\s*$", re.MULTILINE)
_CERT_CHECK = re.compile(r"cert-([a-z]{3}\d{2})-c")

# The CERT C *Rules* clang-tidy actually ships a `cert-*` check for. This is a
# closed list, not "every CERT rule": clang-tidy publishes 22 cert-* checks, and
# four of those target CERT *Recommendations* (DCL03-C, DCL16-C, INT09-C,
# MSC24-C), which are non-normative and deliberately absent from the KB. Without
# this list COVERAGE.md claimed clang-tidy detection for every CERT rule we ship,
# which is exactly the kind of silent over-claim the project disclaims.
#
# On LLVM trunk every cert-* check became an alias of a bugprone-*/misc-*/
# modernize-* check. No cert-* name was removed, so the names above still resolve
# and the `_CERT_CHECK` regex above keeps working — but a future LLVM that drops
# the aliases would need this map rebuilt against the canonical names.
CLANG_TIDY_CERT_RULES = frozenset({
    "ARR39-C",   # cert-arr39-c   -> bugprone-sizeof-expression
    "CON36-C",   # cert-con36-c   -> bugprone-spuriously-wake-up-functions
    "DCL37-C",   # cert-dcl37-c   -> bugprone-reserved-identifier
    "ENV33-C",   # cert-env33-c   -> bugprone-command-processor
    "ERR33-C",   # cert-err33-c   -> bugprone-unused-return-value
    "ERR34-C",   # cert-err34-c   -> bugprone-unchecked-string-to-number-conversion
    "EXP42-C",   # cert-exp42-c   -> bugprone-suspicious-memory-comparison
    "EXP45-C",   # cert-exp45-c   -> bugprone-assignment-in-selection-statement
                 #                   (absent in LLVM 21.1.0, present on trunk)
    "FIO38-C",   # cert-fio38-c   -> misc-non-copyable-objects
    "FLP30-C",   # cert-flp30-c   -> bugprone-float-loop-counter
    "FLP37-C",   # cert-flp37-c   -> bugprone-suspicious-memory-comparison
    "MSC30-C",   # cert-msc30-c   -> misc-predictable-rand
    "MSC32-C",   # cert-msc32-c   -> bugprone-random-generator-seed
    "MSC33-C",   # cert-msc33-c   -> bugprone-unsafe-functions
    "POS44-C",   # cert-pos44-c   -> bugprone-bad-signal-to-kill-thread
    "POS47-C",   # cert-pos47-c   -> concurrency-thread-canceltype-asynchronous
    "SIG30-C",   # cert-sig30-c   -> bugprone-signal-handler
    "STR34-C",   # cert-str34-c   -> bugprone-signed-char-misuse
})


class ClangTidyAnalyzer(Analyzer):
    name = "clang-tidy"
    requires = "clang-tidy"
    options = "--checks=-*,cert-*,bugprone-*,clang-analyzer-* (CERT C checks)"

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
