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
                # An escape blanks the backslash AND the char it escapes. Emit one
                # blank per consumed char to keep length parity, but preserve a
                # newline in the escaped position (a backslash-newline line
                # continuation inside a literal) so line/column offsets stay valid.
                # A backslash as the very last character escapes nothing.
                if i + 1 < n:
                    out.append(" ")
                    out.append("\n" if nxt == "\n" else " ")
                    i += 2
                else:
                    out.append(" "); i += 1
                continue
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

# --- MISRA Mandatory rules (no deviation is permitted against these) ---------
# `static`/qualifier inside an array parameter's brackets (Rule 17.6). The \b
# after each keyword matters: it stops `buf[static_offset]` matching, since an
# underscore is a word character.
_ARRAY_PARAM_QUAL_RE = re.compile(r"\[\s*(static|const|volatile|restrict)\b")
# A sizeof operand, non-nested plus one level of nesting — enough for the
# constructs that actually appear (`sizeof(x++)`, `sizeof(f(a))`, `sizeof(a[i])`).
_SIZEOF_RE = re.compile(r"\bsizeof\s*\(((?:[^()]|\([^()]*\))*)\)")
# Side effects inside that operand (Rule 13.6): increment, decrement, or an
# assignment. Deliberately does NOT treat call syntax as a side effect: without
# preprocessing we cannot tell a real function call from a macro that expands to
# a pure cast or member access, and lwip's `sizeof(ip_2_ip6(&x)->addr)` idiom
# made that arm produce nothing but false positives on the benchmark corpus.
# Real calls inside sizeof are left to cppcheck, which has the expansion.
_SIZEOF_SIDE_EFFECT_RE = re.compile(r"\+\+|--|(?<![=!<>+\-*/%&|^])=(?!=)")
# Rule 17.4 (every path of a non-void function returns a value) is Mandatory and
# Decidable, but deliberately NOT implemented here. A lexical version flags any
# function with no visible `return <expr>`, which on the benchmark corpus meant
# 69 hits across littlefs/lwip/mbedtls/zephyr — dominated by macro-wrapped
# returns (mbedtls's MBEDTLS_MPS_TRACE_RETURN) and noreturn exit calls. A
# macro-shaped guard only suppressed 13 of the 69, so this needs a real control
# flow graph, not a better regex. cppcheck delegates 17.4 to its core checker,
# which has one; the KB carries the rule for that path and for deviation records.


# --- MISRA section 20: the preprocessor -------------------------------------
# The densest block of Decidable / single-translation-unit rules in the
# standard, and the one a lexical analyzer can implement most honestly: these
# rules are *about* the token stream, so there is nothing semantic to miss.
#
# Directive names accepted by Rule 20.13. Includes the widely-implemented
# extensions (#warning, #include_next, #ident) deliberately: flagging them here
# would bury real malformed-directive findings under noise in any real firmware
# tree, and "this is a language extension" is Rule 1.2's job, not 20.13's.
# A line containing only `#` is the null directive, which is valid C.
_VALID_DIRECTIVES = {
    "include", "define", "undef", "if", "ifdef", "ifndef", "elif", "else",
    "endif", "line", "error", "pragma", "warning", "include_next", "ident",
    "sccs", "assert", "unassert", "elifdef", "elifndef", "embed",
}
_DIRECTIVE_RE = re.compile(r"^\s*#\s*(\w+)?")
_INCLUDE_RE = re.compile(r"^\s*#\s*include\s*(.*)$")
_WELL_FORMED_INCLUDE_RE = re.compile(r"^(?:<[^>]*>|\"[^\"]*\"|[A-Za-z_]\w*)")
# Characters undefined inside a header name (Rule 20.2). The quote/apostrophe
# cases are checked per-delimiter below, since a " is legal as the delimiter.
_BAD_IN_ANGLE = ("'", '"', "\\", "/*", "//")
_BAD_IN_QUOTE = ("'", "\\", "/*", "//")
_DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s*(\(([^)]*)\))?(.*)$")
# A lone # is stringize; ## is paste. The (?<!#)#(?!#) guard is load-bearing:
# without it, `a ## NAME ## b` matches as "# NAME ##" by grabbing the second
# character of the first paste operator, and every ordinary two-step paste is
# reported as a Rule 20.11 violation.
_STRINGIZE_RE = re.compile(r"(?<!#)#(?!#)\s*[A-Za-z_]\w*")
_PASTE_RE = re.compile(r"##")
_HASH_THEN_PASTE_RE = re.compile(r"(?<!#)#(?!#)\s*[A-Za-z_]\w*\s*##")
_IF_OPEN_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef)\b")
_IF_CLOSE_RE = re.compile(r"^\s*#\s*endif\b")
_IF_MID_RE = re.compile(r"^\s*#\s*(else|elif|elifdef|elifndef)\b")


def _logical_preproc(lines: list[str]) -> list[tuple[int, str]]:
    """Join backslash-continued preprocessor directives into logical lines.

    Returns (1-based line number of the directive's first line, joined text).
    Without this every multi-line macro -- which is most non-trivial macros in
    embedded code -- would be analysed as fragments, and the body checks below
    would see only the first line.
    """
    out = []
    i, n = 0, len(lines)
    while i < n:
        if lines[i].lstrip().startswith("#"):
            start = i
            parts = [lines[i].rstrip()]
            while parts[-1].endswith("\\") and i + 1 < n:
                parts[-1] = parts[-1][:-1]
                i += 1
                parts.append(lines[i].rstrip())
            out.append((start + 1, " ".join(p.strip() for p in parts)))
        i += 1
    return out


def _param_names(param_text: str) -> list[str]:
    out = []
    for p in param_text.split(","):
        p = p.strip()
        if p and p != "..." and re.fullmatch(r"[A-Za-z_]\w*", p):
            out.append(p)
    return out


def _array_param_names(decl: str) -> set[str]:
    """Names of parameters declared in array form, from a function-definition
    line. These decay to pointers, so sizeof on them is Rule 12.5."""
    try:
        params = decl[decl.index("(") + 1:decl.rindex(")")]
    except ValueError:
        return set()
    out = set()
    for part in params.split(","):
        m = re.search(r"\b([A-Za-z_]\w*)\s*\[", part)
        if m:
            out.add(m.group(1))
    return out


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
    options = "zero-dependency lexical checks (MISRA/BARR-C/CERT subset)"

    def version(self) -> str:
        from .. import __version__
        return f"maishac {__version__}"

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

    def analyze_source(self, code: str, filename: str, root: Path) -> list[Finding]:
        """Analyze an in-memory source string (never touches disk) — the entry
        point for proactively linting a draft before it is written to a file."""
        return self._analyze_file(root / filename, code, root)

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

    def _preprocessor_checks(self, raw_lines: list[str], clean_lines: list[str],
                             add) -> None:
        """MISRA section 20 (preprocessor).

        Header-name checks read the RAW line: strip_comments_strings blanks the
        contents of string literals, which is exactly where a header name lives,
        so `#include "a\\b.h"` would arrive as `#include "      "` and the whole
        rule would silently never fire.

        Macro-body checks read the CLEAN line, so a `#` or `##` inside a string
        literal is not mistaken for a stringize/paste operator.
        """
        # Resolve the file's directive structure ONCE. Both pieces are
        # load-bearing, and getting either wrong produces corpus-wide noise:
        #
        #   starts  -- line numbers where a logical directive begins. A
        #              continuation line can itself start with '#' (a stringize
        #              operator opening a line inside an inline-asm macro, e.g.
        #              zephyr's `#CRm ", " #op2 : "=r" (val)`), and reading
        #              those as directives reported every one as an invalid
        #              directive name.
        #   covered -- every line belonging to a directive, continuations
        #              included. Continuation lines do NOT start with '#', so
        #              without this the body of any multi-line #define counts as
        #              "code" and every conditional #include after it in a
        #              header is flagged. That produced 927 findings across the
        #              benchmark corpus, essentially all of them wrong.
        logical = _logical_preproc(clean_lines)
        starts = {lineno for lineno, _ in logical}
        covered = set()
        for start, _ in logical:
            j = start - 1
            while j < len(clean_lines):
                covered.add(j + 1)
                if not clean_lines[j].rstrip().endswith("\\"):
                    break
                j += 1

        # Rule 20.1 (#include should precede other code) is deliberately NOT
        # implemented here. It cannot be decided without knowing which
        # conditional branch is active, and a branch-blind lexer sees code that
        # the compiler never does. 820 findings across the benchmark corpus,
        # dominated by two patterns that are correct C:
        #
        #   static int wsa_init_done = 0;   /* only exists when _WIN32 */
        #   #else
        #   #include <sys/types.h>          /* nothing precedes it in THIS branch */
        #
        #   #ifdef __cplusplus
        #   extern "C" {                    /* absent from a C translation unit */
        #   #endif
        #   #include <mbedtls/platform_time.h>
        #
        # cppcheck's addon implements 20.1 with a real preprocessor; the KB
        # carries the rule for that path and for deviation records.

        # --- 20.13: a line starting with # must be a valid directive --------
        # --- 20.14: #else/#endif must be in the same file as their #if ------
        depth = 0
        for i, raw in enumerate(raw_lines, start=1):
            if i not in starts or not raw.lstrip().startswith("#"):
                continue
            m = _DIRECTIVE_RE.match(raw)
            name = m.group(1) if m else None
            if name is None:
                continue  # bare '#' is the null directive, which is valid
            if name not in _VALID_DIRECTIVES:
                add("MISRA 20.13", i, f"'#{name}' is not a valid preprocessing directive")
                continue
            if _IF_OPEN_RE.match(raw):
                depth += 1
            elif _IF_CLOSE_RE.match(raw):
                depth -= 1
                if depth < 0:
                    add("MISRA 20.14", i,
                        "#endif has no matching #if in this file")
                    depth = 0
            elif _IF_MID_RE.match(raw) and depth == 0:
                add("MISRA 20.14", i,
                    f"#{name} has no matching #if in this file")
        if depth > 0:
            add("MISRA 20.14", len(raw_lines) or 1,
                f"{depth} conditional block(s) left open at end of file")

        # --- 20.2 / 20.3: header names --------------------------------------
        for i, raw in enumerate(raw_lines, start=1):
            im = _INCLUDE_RE.match(raw)
            if not im or i not in starts:
                continue
            rest = im.group(1).strip()
            # Extract the delimited header name FIRST. A trailing comment can
            # only be stripped from the macro form: inside <> or "", a '/*' is
            # part of the name and is precisely what Rule 20.2 exists to catch,
            # so cutting at it here would convert every 20.2 into a bogus 20.3.
            if rest.startswith("<") and ">" in rest:
                name, bad = rest[1:rest.index(">")], _BAD_IN_ANGLE
            elif rest.startswith('"') and rest.count('"') >= 2:
                name, bad = rest[1:rest.index('"', 1)], _BAD_IN_QUOTE
            else:
                for cut in ("/*", "//"):
                    if (idx := rest.find(cut)) > 0:
                        rest = rest[:idx].strip()
                if not _WELL_FORMED_INCLUDE_RE.match(rest):
                    add("MISRA 20.3", i,
                        "#include is not followed by a well-formed <header> or \"header\"")
                continue  # macro-expanded form; can't judge without preprocessing
            for ch in bad:
                if ch in name:
                    shown = "\\\\" if ch == "\\" else ch
                    add("MISRA 20.2", i,
                        f"header name '{name}' contains '{shown}', whose handling "
                        "in a header name is undefined")
                    break

        # --- 20.10 / 20.11: the # and ## operators --------------------------
        for lineno, text in _logical_preproc(clean_lines):
            dm = _DEFINE_RE.match(text)
            if not dm:
                continue
            body = dm.group(4) or ""
            has_paste = _PASTE_RE.search(body)
            has_stringize = _STRINGIZE_RE.search(body)
            if has_paste or has_stringize:
                op = "##" if has_paste else "#"
                add("MISRA 20.10", lineno,
                    f"macro '{dm.group(1)}' uses the {op} preprocessor operator")
            if _HASH_THEN_PASTE_RE.search(body):
                add("MISRA 20.11", lineno,
                    f"macro '{dm.group(1)}': a # operand is immediately followed "
                    "by ##, and their evaluation order is unspecified")

    def _analyze_file(self, f: Path, src: str, root: Path) -> list[Finding]:
        out: list[Finding] = []
        raw_lines = src.splitlines()
        clean = strip_comments_strings(src)
        clean_lines = clean.splitlines()
        add = lambda rule, ln, msg: out.append(x) if (x := self._mk(rule, f, root, ln, raw_lines, msg)) else None

        # Current function is func_stack[-1]. Entries carry the state the
        # Mandatory checks need: whether the function returns a value (17.4) and
        # which of its parameters are declared in array form (12.5).
        func_stack: list[dict] = []
        pending_func: dict | None = None
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
                cur_name = func_stack[-1]["name"]
                if re.search(rf"(?<![\w.]){re.escape(cur_name)}\s*\(", line) and not _FUNC_DEF_RE.match(line):
                    add("MISRA 17.2", i, f"direct recursion: '{cur_name}' calls itself")

            # MISRA 17.6 (mandatory): static/qualifier in array parameter brackets
            qm = _ARRAY_PARAM_QUAL_RE.search(line)
            if qm and "(" in line:
                add("MISRA 17.6", i,
                    f"'{qm.group(1)}' inside array parameter brackets")

            # MISRA 13.6 (mandatory) and 12.5 (mandatory): sizeof operands
            for sm in _SIZEOF_RE.finditer(line):
                operand = sm.group(1)
                if _SIZEOF_SIDE_EFFECT_RE.search(operand):
                    add("MISRA 13.6", i,
                        f"side effect in sizeof operand '{operand.strip()}' "
                        "— sizeof does not evaluate it")
                if func_stack:
                    name = operand.strip()
                    if name in func_stack[-1]["array_params"]:
                        add("MISRA 12.5", i,
                            f"sizeof applied to array parameter '{name}' "
                            "— it decayed to a pointer")

            fm = _FUNC_DEF_RE.match(line)
            if fm and not line.strip().startswith(("if", "for", "while", "switch", "return", "else")):
                pending_func = {
                    "name": fm.group(1), "start": i,
                    "array_params": _array_param_names(line),
                }

            # float equality: crude but effective — == or != on a line mentioning float vars is
            # too noisy; instead flag literal float comparisons like `x == 0.1`
            if re.search(r"[!=]=\s*-?\d+\.\d+[fF]?\b", line) or re.search(r"-?\d+\.\d+[fF]?\s*[!=]=", line):
                add("CERT FLP37-C", i, "floating-point equality comparison")

            # switch/default tracking
            depth += line.count("{") - line.count("}")
            if pending_func is not None and "{" in line:
                pending_func["depth"] = depth
                func_stack.append(pending_func)
                pending_func = None
            while func_stack and func_stack[-1]["depth"] > depth:
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

        self._preprocessor_checks(raw_lines, clean_lines, add)

        return [f for f in out if f is not None]
