"""Native analyzer: zero-dependency lexical + light structural checks.

This guarantees Maisha produces useful findings even on machines without
cppcheck or clang-tidy. It runs on a comment/string-stripped view of each file
so patterns never fire inside literals, and reports against the *original*
source line for correct fingerprints.

These are deliberately high-precision checks (banned functions/headers,
mechanical style rules). Deep semantic analysis (dataflow, lifetimes) is
delegated to the cppcheck/clang-tidy adapters when present.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Analyzer
from ..model import Finding, enclosing_function, relpath
from ..rules import REGISTRY


def strip_comments_strings(src: str) -> str:
    """Replace comment/string contents with spaces, preserving line structure
    and length so (line, col) positions remain valid."""
    out = []
    i, n = 0, len(src)
    mode = "code"  # code | line | block | str | chr
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if mode == "code":
            if c == "/" and nxt == "/":
                mode = "line"; out.append("  "); i += 2; continue
            if c == "/" and nxt == "*":
                mode = "block"; out.append("  "); i += 2; continue
            if c == '"':
                mode = "str"; out.append('"'); i += 1; continue
            if c == "'":
                mode = "chr"; out.append("'"); i += 1; continue
            out.append(c); i += 1
        elif mode == "line":
            if c == "\n":
                mode = "code"; out.append(c)
            else:
                out.append(" ")
            i += 1
        elif mode == "block":
            if c == "*" and nxt == "/":
                mode = "code"; out.append("  "); i += 2; continue
            out.append(c if c == "\n" else " "); i += 1
        elif mode in ("str", "chr"):
            quote = '"' if mode == "str" else "'"
            if c == "\\":
                out.append("  "); i += 2; continue
            if c == quote:
                mode = "code"; out.append(quote); i += 1; continue
            out.append(c if c == "\n" else " "); i += 1
    return "".join(out)


BANNED_CALLS = {
    # func -> (rule query, extra message)
    "malloc":  ("MISRA 21.3", "dynamic allocation"), "calloc": ("MISRA 21.3", "dynamic allocation"),
    "realloc": ("MISRA 21.3", "dynamic allocation"), "free":   ("MISRA 21.3", "dynamic allocation"),
    "setjmp":  ("MISRA 21.4", "non-local jump"),     "longjmp": ("MISRA 21.4", "non-local jump"),
    "signal":  ("MISRA 21.5", "signal handling"),    "raise":  ("MISRA 21.5", "signal handling"),
    "printf":  ("MISRA 21.6", "stdio in production"),"fprintf": ("MISRA 21.6", "stdio in production"),
    "scanf":   ("MISRA 21.6", "stdio in production"),"fscanf": ("MISRA 21.6", "stdio in production"),
    "puts":    ("MISRA 21.6", "stdio in production"),
    "atoi":    ("CERT ERR34-C", "no error detection possible"),
    "atol":    ("CERT ERR34-C", "no error detection possible"),
    "atof":    ("CERT ERR34-C", "no error detection possible"),
    "abort":   ("MISRA 21.8", "termination function"), "exit": ("MISRA 21.8", "termination function"),
    "getenv":  ("MISRA 21.8", "environment access"),
    "system":  ("CERT ENV33-C", "command processor invocation"),
    "qsort":   ("MISRA 21.9", "library sort (possibly recursive)"),
    "bsearch": ("MISRA 21.9", "library search"),
    "gets":    ("CERT STR31-C", "unbounded read, removed from C11"),
    "strcpy":  ("CERT STR31-C", "unbounded copy"), "strcat": ("CERT STR31-C", "unbounded concat"),
    "sprintf": ("CERT STR31-C", "unbounded format"),
    "strtok":  ("CERT CON33-C", "static internal state"),
    "rand":    ("CERT MSC32-C", "weak PRNG"),
    "asctime": ("CERT MSC33-C", "fixed static buffer"),
    "vsprintf": ("CERT STR31-C", "unbounded format"),
}

_CALL_RE = re.compile(r"\b(" + "|".join(BANNED_CALLS) + r")\s*\(")
_OCTAL_RE = re.compile(r"(?<![\w.])0[0-7]+(?![\dxXbB.eEuUlL'])")
_LSUFFIX_RE = re.compile(r"\b\d+[uU]?l\b")
_ASSIGN_COND_RE = re.compile(r"\b(if|while)\s*\(([^()]|\([^()]*\))*[^=!<>+\-*/%&|^]=(?!=)")
_NOBRACE_RE = re.compile(r"^\s*(if|else\s+if|for|while)\s*\(.*\)\s*[^{;\s].*;\s*$")
_ELSE_NOBRACE_RE = re.compile(r"^\s*else\s+(?!if\b)(?!\{)[^{;\s].*;\s*$")
_CTRL_HDR_RE = re.compile(r"^\s*(if|else\s+if|for|while)\s*\(.*\)\s*$")
_ELSE_HDR_RE = re.compile(r"^\s*else\s*$")
_GOTO_RE = re.compile(r"\bgoto\s+\w+\s*;")
_UNION_RE = re.compile(r"\bunion\b\s*(\w+)?\s*\{")
_UNDEF_RE = re.compile(r"^\s*#\s*undef\b")
_TRIGRAPH_RE = re.compile(r"\?\?[=/'()!<>\-]")
_VLA_RE = re.compile(r"\b(?:int|char|float|double|long|short|uint\d+_t|int\d+_t|size_t)\s+\w+\s*\[\s*([a-zA-Z_]\w*)\s*\]")
_MACRO_CONST_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_FLOAT_EQ_RE = re.compile(r"\b(float|double)\b")
_FUNC_DEF_RE = re.compile(r"^\s*(?:static\s+|inline\s+|extern\s+)*[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{?\s*$")
_BASIC_TYPE_DECL_RE = re.compile(r"^\s*(?:static\s+|const\s+|volatile\s+|extern\s+)*(?:unsigned\s+|signed\s+)?(int|short|long)\b(?!\s*\()")
_COMMENTED_CODE_RE = re.compile(r"(;|\{|\}|\breturn\b|=)")
_PREPROC_RE = re.compile(r"^\s*#")


def _next_significant(lines: list[str], start_idx: int) -> str | None:
    """First line at/after start_idx (0-based) that isn't blank or a
    preprocessor directive. A #if/#ifdef/#else/#endif conditional-compilation
    block sitting between a control header and its body is not a missing
    brace — it's the body wrapped in a compile-time choice, and the real
    brace is on the far side of it (see BENCHMARKS.md: 16/16 confirmed cases
    of this exact pattern in FreeRTOS)."""
    j = start_idx
    while j < len(lines) and (not lines[j].strip() or _PREPROC_RE.match(lines[j])):
        j += 1
    return lines[j] if j < len(lines) else None


class NativeAnalyzer(Analyzer):
    name = "native"
    requires = None

    def analyze(self, files: list[Path], root: Path,
                include_paths: list[str] | None = None) -> list[Finding]:
        # lexical checks need no compilation model, so include paths don't apply here
        findings: list[Finding] = []
        for f in files:
            try:
                src = f.read_text("utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self._analyze_file(f, src, root))
        return findings

    # ---------------------------------------------------------------- helpers
    def _mk(self, rule_query: str, f: Path, root: Path, lineno: int,
            lines: list[str], msg: str) -> Finding | None:
        meta = REGISTRY.resolve(rule_query)
        if not meta:
            return None
        return Finding(
            rule_id=meta["id"], standard=meta["standard"], severity=meta["severity"],
            file=relpath(f, root), line=lineno, message=msg, analyzer=self.name,
            line_content=lines[lineno - 1] if 0 < lineno <= len(lines) else "",
            context_symbol=enclosing_function(lines, lineno - 1),
            cross_refs=REGISTRY.cross_refs(meta["id"]),
            fix_hint=meta.get("fix", ""),
        )

    def _analyze_file(self, f: Path, src: str, root: Path) -> list[Finding]:
        out: list[Finding] = []
        raw_lines = src.splitlines()
        clean = strip_comments_strings(src)
        clean_lines = clean.splitlines()
        add = lambda rule, ln, msg: out.append(x) if (x := self._mk(rule, f, root, ln, raw_lines, msg)) else None

        func_stack: list[list] = []  # [name, depth_at_open], current function is func_stack[-1]
        pending_func_name: str | None = None
        switch_stack: list[tuple[int, int, bool]] = []  # (start_line, depth_at_open, saw_default)
        depth = 0

        for i, line in enumerate(clean_lines, start=1):
            raw = raw_lines[i - 1] if i <= len(raw_lines) else ""

            for m in _CALL_RE.finditer(line):
                fn = m.group(1)
                rule, why = BANNED_CALLS[fn]
                add(rule, i, f"call to banned function '{fn}' ({why})")
            if _OCTAL_RE.search(line):
                add("MISRA 7.1", i, "octal integer constant")
            if _LSUFFIX_RE.search(line):
                add("MISRA 7.3", i, "lowercase 'l' literal suffix is easily misread as '1'")
            if _ASSIGN_COND_RE.search(line):
                add("MISRA 13.4", i, "assignment used inside a condition expression")
            if _NOBRACE_RE.match(line) or _ELSE_NOBRACE_RE.match(line):
                add("MISRA 15.6", i, "control statement body is not a compound (braced) block")
            # header on one line, braceless body on the next — skip over any
            # #if/#else/#endif between the header and its real body first.
            if _CTRL_HDR_RE.match(line) or _ELSE_HDR_RE.match(line):
                nxt = _next_significant(clean_lines, i)  # clean_lines[i] is the line after `line` (0-based)
                if nxt is not None and not nxt.lstrip().startswith("{") \
                        and not _CTRL_HDR_RE.match(nxt) and not _ELSE_HDR_RE.match(nxt):
                    add("MISRA 15.6", i,
                        "control statement body is not a compound (braced) block")
            if _GOTO_RE.search(line):
                add("MISRA 15.1", i, "goto statement")
            if _UNION_RE.search(line):
                add("MISRA 19.2", i, "union declaration")
            if _UNDEF_RE.match(line):
                add("MISRA 20.5", i, "#undef directive")
            if _TRIGRAPH_RE.search(raw):
                add("MISRA 4.2", i, "trigraph sequence")
            vla_m = _VLA_RE.search(line)
            # An ALL_CAPS array-size identifier is, by nearly universal C
            # convention, a #define'd compile-time constant, not a runtime
            # variable — without preprocessing, this heuristic can't resolve
            # the macro's value, but it can at least stop mistaking
            # "uint8_t buf[BUF_SIZE]" (a fixed array) for a VLA (see
            # BENCHMARK-SUITE-REPORT.md: confirmed false positive, was firing
            # on every macro-sized array in a struct).
            if vla_m and "(" not in line.split("[")[0] and not _MACRO_CONST_RE.match(vla_m.group(1)):
                add("MISRA 18.8", i, "possible variable-length array")
            if _BASIC_TYPE_DECL_RE.match(line) and "main" not in line:
                add("MISRA Dir 4.6", i, "basic numeric type instead of fixed-width <stdint.h> type")
            if len(raw) > 80:
                add("BARR 3.1a", i, f"line is {len(raw)} characters (limit 80)")
            if "\t" in raw:
                add("BARR 3.2a", i, "tab character used for indentation/alignment")

            # commented-out code heuristic (uses raw line, since clean has comments blanked)
            stripped = raw.strip()
            if stripped.startswith("//") and _COMMENTED_CODE_RE.search(stripped[2:]) \
               and len(stripped) > 8 and not stripped[2:].strip().startswith(("!", "TODO", "NOTE", "FIXME")):
                add("MISRA Dir 4.4", i, "possible commented-out code")

            # recursion (direct): function calls itself. Checked against only
            # the CURRENT enclosing function (tracked incrementally via brace
            # depth below) rather than every function name seen so far in the
            # file — the previous every-name-times-every-line approach was
            # O(functions x lines), which made large files (thousands of
            # functions) unusably slow (see BENCHMARK-SUITE-REPORT.md).
            if func_stack:
                cur_name = func_stack[-1][0]
                if re.search(rf"(?<![\w.]){re.escape(cur_name)}\s*\(", line) and not _FUNC_DEF_RE.match(line):
                    add("MISRA 17.2", i, f"direct recursion: '{cur_name}' calls itself")

            fm = _FUNC_DEF_RE.match(line)
            if fm and not line.strip().startswith(("if", "for", "while", "switch", "return", "else")):
                pending_func_name = fm.group(1)

            # float equality: crude but effective — == or != on a line mentioning float vars is
            # too noisy; instead flag literal float comparisons like `x == 0.1`
            if re.search(r"[!=]=\s*-?\d+\.\d+[fF]?\b", line) or re.search(r"-?\d+\.\d+[fF]?\s*[!=]=", line):
                add("CERT FLP37-C", i, "floating-point equality comparison")

            # switch/default tracking
            depth += line.count("{") - line.count("}")
            if pending_func_name is not None and "{" in line:
                func_stack.append([pending_func_name, depth])
                pending_func_name = None
            while func_stack and func_stack[-1][1] > depth:
                func_stack.pop()
            if re.search(r"\bswitch\s*\(", line):
                switch_stack.append([i, depth, False])  # type: ignore[list-item]
            if switch_stack and re.search(r"\bdefault\s*:", line):
                switch_stack[-1][2] = True  # type: ignore[index]
            while switch_stack and depth < switch_stack[-1][1]:
                start, _, saw_default = switch_stack.pop()
                if not saw_default:
                    add("MISRA 16.4", start, "switch statement has no default label")

        for start, _, saw_default in switch_stack:  # unterminated at EOF
            if not saw_default:
                add("MISRA 16.4", start, "switch statement has no default label")

        return [f for f in out if f is not None]
