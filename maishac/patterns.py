"""Author-time compliant-pattern library (Mode 1).

The reactive scan tells you what's *wrong*. This tells you what to *reach for*
while writing — the compliant idiom for a recurring embedded-C decision, the
anti-pattern it replaces, and why — cross-linked to the MISRA/CERT/BARR-C rules
each idiom satisfies. Consumed by `compliance_guidance` (proactive lookup) and
attached to `check_snippet` findings (so the reactive path teaches the fix too).

Code samples are original, written for this project. Rule references use the
registry's fuzzy forms and are resolved to canonical ids at lookup time.
"""

from __future__ import annotations

from .rules import REGISTRY

# Each pattern: a recurring authoring concern, keywords to find it by, the rules
# it satisfies, the idiom to AVOID, the idiom to PREFER, and the reason.
PATTERNS: list[dict] = [
    {
        "concern": "dynamic memory allocation",
        "keywords": ["malloc", "calloc", "realloc", "free", "heap", "alloc",
                     "dynamic memory", "new"],
        "rules": ["MISRA 21.3", "MISRA Dir 4.12", "CERT MEM30-C", "BARR 5.6a"],
        "avoid": "uint8_t *buf = malloc(n);   /* heap: can fail, fragments, "
                 "worst-case unprovable */",
        "prefer": "static uint8_t buf[MAX_N];  /* fixed, compile-time sized */\n"
                  "/* or a project-approved static pool allocator carved once at init */",
        "why": "Dynamic allocation can fail at runtime, fragments the heap, and "
               "makes worst-case memory usage impossible to prove — forbidden in "
               "safety-critical profiles. Size everything statically.",
    },
    {
        "concern": "integer types (fixed-width)",
        "keywords": ["int", "short", "long", "char", "unsigned", "type", "width",
                     "stdint", "typedef"],
        "rules": ["MISRA Dir 4.6", "BARR 5.2a"],
        "avoid": "unsigned int count;   int   temperature;",
        "prefer": "#include <stdint.h>\nuint32_t count;   int16_t temperature;",
        "why": "Basic types have implementation-defined width. Fixed-width types "
               "from <stdint.h> make range and overflow behaviour portable and "
               "reviewable across compilers/targets.",
    },
    {
        "concern": "recursion",
        "keywords": ["recursion", "recursive", "call itself", "factorial",
                     "traverse", "tree"],
        "rules": ["MISRA 17.2", "BARR 6.1a"],
        "avoid": "uint32_t sum(node_t *n){ return n ? n->v + sum(n->next) : 0u; }",
        "prefer": "uint32_t sum(node_t *n){\n"
                  "    uint32_t acc = 0u;\n"
                  "    for (; n != NULL; n = n->next) { acc += n->v; }\n"
                  "    return acc;\n}",
        "why": "Recursion makes worst-case stack depth unbounded and unprovable. "
               "Rewrite as an explicit loop (or an explicit bounded stack) so "
               "stack usage is statically analysable.",
    },
    {
        "concern": "check library return values",
        "keywords": ["return value", "ignore", "errno", "check error", "unused result"],
        "rules": ["MISRA 17.7", "CERT ERR33-C"],
        "avoid": "memset(dst, 0, n);\n(void)fclose(fp);   /* discarding a real failure */",
        "prefer": "if (memcpy_s(dst, sizeof dst, src, n) != 0) { handle_error(); }\n"
                  "/* if a result truly cannot fail here, cast it away explicitly: */\n"
                  "(void)snprintf(buf, sizeof buf, \"%d\", x);",
        "why": "A non-void return often carries a failure code. Ignoring it hides "
               "faults; MISRA requires you to use it or make the discard explicit "
               "with a (void) cast so review sees the decision.",
    },
    {
        "concern": "string buffers and copying",
        "keywords": ["strcpy", "strcat", "sprintf", "gets", "buffer", "string",
                     "char array", "null terminator"],
        "rules": ["CERT STR31-C", "CERT STR32-C", "MISRA 21.6"],
        "avoid": "char name[16];\nstrcpy(name, input);   /* no bound: overflow */",
        "prefer": "char name[16];\n"
                  "(void)snprintf(name, sizeof name, \"%s\", input);  /* bounded, "
                  "always NUL-terminated */",
        "why": "Unbounded copies overflow the destination. Always bound by the "
               "destination size and guarantee NUL-termination.",
    },
    {
        "concern": "string to number conversion",
        "keywords": ["atoi", "atol", "atof", "parse int", "string to number", "strtol"],
        "rules": ["MISRA 21.7", "CERT ERR34-C"],
        "avoid": "int32_t v = atoi(s);   /* cannot report failure or overflow */",
        "prefer": "char *end;\nlong v = strtol(s, &end, 10);\n"
                  "if (end == s || *end != '\\0' || errno == ERANGE) { handle_error(); }",
        "why": "atoi/atol/atof cannot signal an invalid or out-of-range input. "
               "Use strtol/strtoul and check the end pointer and errno.",
    },
    {
        "concern": "braces on control-flow bodies",
        "keywords": ["if", "else", "while", "for", "brace", "single statement", "body"],
        "rules": ["MISRA 15.6", "BARR 1.3a"],
        "avoid": "if (ready)\n    start();   /* braceless: a later added line silently "
                 "escapes the if */",
        "prefer": "if (ready) {\n    start();\n}",
        "why": "A braceless body invites the classic 'goto fail' bug when a second "
               "statement is added later. Always compound-brace the body.",
    },
    {
        "concern": "switch default case",
        "keywords": ["switch", "case", "default", "enum", "state machine"],
        "rules": ["MISRA 16.4", "BARR 8.5a"],
        "avoid": "switch (state) {\n  case IDLE:  idle();  break;\n  case RUN:   run();   break;\n}",
        "prefer": "switch (state) {\n  case IDLE: idle(); break;\n  case RUN:  run();  break;\n"
                  "  default:   trap_unexpected(state); break;\n}",
        "why": "A missing default silently ignores unexpected/corrupted values. "
               "Every switch needs a default that traps the unexpected case.",
    },
    {
        "concern": "boolean conditions and assignment in conditions",
        "keywords": ["if condition", "boolean", "assignment", "= vs ==", "truthy",
                     "implicit"],
        "rules": ["MISRA 14.4", "MISRA 13.4", "CERT EXP45-C", "BARR 8.2a", "BARR 1.7c"],
        "avoid": "if (count)      { ... }   /* implicit int->bool */\n"
                 "if (p = next()) { ... }   /* assignment mistaken for comparison */",
        "prefer": "if (count != 0u) { ... }\np = next();\nif (p != NULL) { ... }",
        "why": "Controlling expressions should be explicitly Boolean, and an "
               "assignment must never masquerade as a condition — write the "
               "comparison out.",
    },
    {
        "concern": "null pointer checks",
        "keywords": ["null", "NULL", "pointer check", "dereference", "nullptr"],
        "rules": ["CERT EXP34-C", "BARR 8.3a"],
        "avoid": "cfg_t *c = find(id);\nc->flag = 1;   /* find() may have returned NULL */",
        "prefer": "cfg_t *c = find(id);\nif (c != NULL) {\n    c->flag = 1u;\n} else { handle_missing(); }",
        "why": "Dereferencing a possibly-null pointer is undefined behaviour. Test "
               "explicitly against NULL before use.",
    },
    {
        "concern": "integer conversion and overflow",
        "keywords": ["cast", "conversion", "overflow", "wrap", "truncate", "signed",
                     "unsigned", "essential type"],
        "rules": ["MISRA 10.1", "CERT INT31-C", "CERT INT30-C", "CERT INT32-C"],
        "avoid": "uint8_t b = (uint8_t)wide_value;   /* silent truncation */\n"
                 "sum = a + b;   /* may overflow before the assignment */",
        "prefer": "if (wide_value <= UINT8_MAX) { b = (uint8_t)wide_value; } else { handle_range(); }\n"
                  "/* check operands fit before arithmetic that can wrap/overflow */",
        "why": "Narrowing conversions lose data and unchecked arithmetic wraps or "
               "overflows (UB for signed). Range-check before converting or "
               "operating.",
    },
    {
        "concern": "format strings",
        "keywords": ["printf", "format", "fprintf", "snprintf", "%s", "user input",
                     "format string"],
        "rules": ["CERT FIO30-C", "MISRA 21.6"],
        "avoid": "printf(user_text);   /* user controls the format string */",
        "prefer": "printf(\"%s\", user_text);   /* data is data, never the format */",
        "why": "Passing externally-influenced data as the format string is a "
               "format-string vulnerability. The format literal must be fixed.",
    },
    {
        "concern": "bounded loops",
        "keywords": ["while", "loop", "infinite", "while(1)", "termination",
                     "bounded", "timeout"],
        "rules": ["BARR 8.6a", "CERT ARR30-C"],
        "avoid": "while (!ready) { }   /* may spin forever if ready never sets */",
        "prefer": "for (uint32_t i = 0u; (i < TIMEOUT) && !ready; ++i) { poll(); }\n"
                  "if (!ready) { handle_timeout(); }",
        "why": "Every loop must have a provable upper bound on iterations so it "
               "cannot hang the system; give hardware-wait loops an explicit "
               "timeout.",
    },
    {
        "concern": "goto and single exit",
        "keywords": ["goto", "label", "jump", "break", "continue", "single exit",
                     "multiple return", "early return"],
        "rules": ["MISRA 15.1", "MISRA 15.5", "BARR 1.7a"],
        "avoid": "if (err) goto cleanup;   /* ... */  cleanup: release();",
        "prefer": "/* structure with a status variable and a single return */\n"
                  "status_t st = OK;\nif (err) { st = FAIL; }\nif (st == OK) { work(); }\n"
                  "release();\nreturn st;",
        "why": "goto obscures control flow. Use structured control with a status "
               "variable so the path (and cleanup) is explicit and reviewable.",
    },
    {
        "concern": "free discipline (double-free, dangling, escaping addresses)",
        "keywords": ["free", "double free", "use after free", "dangling",
                     "return address", "return pointer", "local", "size overflow"],
        "rules": ["CERT MEM31-C", "CERT MEM34-C", "CERT MEM35-C", "CERT DCL30-C"],
        "avoid": "free(p);\nfree(p);          /* double free: heap corruption */\nreturn &local;    /* address escapes its lifetime */",
        "prefer": "free(p);\np = NULL;          /* free exactly once, then poison */\n"
                  "/* return by value, or write into a caller-owned buffer — never &local */",
        "why": "Freeing twice or freeing non-heap memory corrupts the allocator; "
               "a local's address dangles after return. Free once and null out; "
               "guard any allocation-size multiplication against overflow.",
    },
    {
        "concern": "uninitialized variables",
        "keywords": ["uninitialized", "garbage value", "read before write",
                     "initialize", "declaration"],
        "rules": ["CERT EXP33-C"],
        "avoid": "uint32_t crc;\nupdate(&crc);   /* update reads crc before any write */",
        "prefer": "uint32_t crc = 0u;   /* initialize at the point of declaration */",
        "why": "Reading uninitialized automatic storage is undefined behaviour and "
               "non-deterministic. Initialize every object where you declare it.",
    },
    {
        "concern": "pointer type punning and casts",
        "keywords": ["cast pointer", "type pun", "reinterpret", "aliasing", "union",
                     "incompatible type", "bit cast"],
        "rules": ["MISRA 11.3", "MISRA 19.2", "CERT EXP39-C"],
        "avoid": "float f = *(float *)&bits;   /* incompatible-type access: aliasing UB */",
        "prefer": "float f;\n(void)memcpy(&f, &bits, sizeof f);   /* copy the bytes, no aliasing */",
        "why": "Accessing an object through an incompatible pointer type (or a "
               "type-punning union) breaks strict aliasing. Copy the bytes with "
               "memcpy instead.",
    },
    {
        "concern": "variable-length arrays and array bounds",
        "keywords": ["vla", "variable length array", "array size", "buf[n]",
                     "stack array", "bounds"],
        "rules": ["MISRA 18.8", "CERT ARR32-C"],
        "avoid": "void f(size_t n){ uint8_t buf[n]; }   /* VLA: stack size unknown */",
        "prefer": "void f(size_t n){\n    uint8_t buf[MAX_N];\n"
                  "    if (n > MAX_N) { handle_range(); return; }\n    /* use buf[0..n) */\n}",
        "why": "VLAs make worst-case stack usage unprovable and overflow silently "
               "for large n. Use a fixed maximum size and bound n against it.",
    },
    {
        "concern": "division by zero",
        "keywords": ["divide", "division", "modulo", "remainder", "/", "%", "zero"],
        "rules": ["CERT INT33-C"],
        "avoid": "avg = sum / count;   /* count may be 0 -> UB */",
        "prefer": "if (count != 0u) { avg = sum / count; } else { handle_empty(); }",
        "why": "Integer division or remainder by zero is undefined behaviour. "
               "Check the divisor before every division.",
    },
    {
        "concern": "floating-point comparison and math errors",
        "keywords": ["float", "double", "==", "equality", "sqrt", "log", "nan",
                     "epsilon", "domain"],
        "rules": ["CERT FLP37-C", "CERT FLP32-C"],
        "avoid": "if (x == 0.0) { ... }   /* exact float equality is unreliable */\n"
                 "y = sqrt(v);            /* v may be negative -> domain error */",
        "prefer": "if (fabs(x) < EPSILON) { ... }\n"
                  "if (v >= 0.0) { y = sqrt(v); } else { handle_domain(); }",
        "why": "Floating-point values rarely compare exactly equal; test against a "
               "tolerance. Guard the domain before sqrt/log/etc.",
    },
    {
        "concern": "reading EOF from a file",
        "keywords": ["fgetc", "getc", "getchar", "eof", "read char", "file input"],
        "rules": ["CERT FIO34-C"],
        "avoid": "char c = fgetc(fp);\nif (c == EOF) { ... }   /* char can't hold EOF distinctly */",
        "prefer": "int ci = fgetc(fp);\nif (ci == EOF) { ... }\nelse { char c = (char)ci; /* use c */ }",
        "why": "fgetc returns int so EOF is distinguishable from a valid 0xFF byte. "
               "Store the result in an int before comparing to EOF.",
    },
    {
        "concern": "random number seeding",
        "keywords": ["rand", "random", "srand", "prng", "entropy", "nonce", "token"],
        "rules": ["CERT MSC32-C"],
        "avoid": "int r = rand();   /* unseeded, low quality, predictable */",
        "prefer": "/* seed a real PRNG once from a hardware entropy source at init; */\n"
                  "/* NEVER use rand() for keys, nonces, or tokens */",
        "why": "rand() is low quality and predictable, and unseeded it repeats. Use "
               "a vetted PRNG seeded from entropy; use a CSPRNG for anything "
               "security-relevant.",
    },
    {
        "concern": "unsafe function-like macros",
        "keywords": ["macro", "#define", "side effect", "double evaluation",
                     "function macro", "inline"],
        "rules": ["CERT PRE31-C"],
        "avoid": "#define SQ(x) ((x) * (x))\ny = SQ(i++);   /* i incremented twice */",
        "prefer": "static inline uint32_t sq(uint32_t x) { return x * x; }\ny = sq(i++);   /* argument evaluated once */",
        "why": "Function-like macros re-evaluate their arguments; a side-effecting "
               "argument runs more than once. Prefer a static inline function.",
    },
    {
        "concern": "reserved identifiers and naming",
        "keywords": ["identifier", "underscore", "reserved", "naming", "leading underscore",
                     "case", "guard"],
        "rules": ["CERT DCL37-C", "BARR 7.1e"],
        "avoid": "int _count;\n#define __MY_GUARD   /* leading underscores are reserved */",
        "prefer": "int count;\n#define MYMOD_GUARD_H   /* module-prefixed, no leading underscore */",
        "why": "Identifiers with leading underscores (and names differing only by "
               "case) collide with the implementation's reserved namespace. Use "
               "clear, module-prefixed names.",
    },
    {
        "concern": "internal linkage (static)",
        "keywords": ["static", "linkage", "internal", "file scope", "translation unit",
                     "private function"],
        "rules": ["MISRA 8.7", "BARR 6.2a"],
        "avoid": "void helper(void) { ... }   /* used only in this .c, but external */",
        "prefer": "static void helper(void) { ... }   /* file-local: no namespace pollution */",
        "why": "Objects/functions used in a single translation unit should have "
               "internal linkage — declare them static so they cannot clash or be "
               "misused elsewhere.",
    },
    {
        "concern": "visible declaration for externals",
        "keywords": ["extern", "header", "declaration", "global", "prototype",
                     "shared symbol"],
        "rules": ["MISRA 8.4", "BARR 4.2a"],
        "avoid": "/* foo.c */\nuint32_t g_ticks;   /* no header declares it */",
        "prefer": "/* foo.h */  extern uint32_t g_ticks;\n"
                  "/* foo.c */  #include \"foo.h\"\n             uint32_t g_ticks;",
        "why": "Every external object/function needs a compatible declaration in a "
               "header included by its defining file, so the compiler checks the "
               "definition against every use.",
    },
    {
        "concern": "numeric and lexical literals",
        "keywords": ["octal", "literal", "suffix", "0x", "hex", "trigraph",
                     "constant", "magic number"],
        "rules": ["MISRA 7.1", "MISRA 7.3", "MISRA 4.2", "BARR 5.4a"],
        "avoid": "int mask = 010;   /* octal = 8, not 10 */\nlong n = 100l;   /* 'l' looks like '1' */",
        "prefer": "int mask = 0x08;\nlong n = 100L;\nuint32_t flags = 1UL;   /* uppercase U/L suffixes */",
        "why": "Leading-zero octal surprises readers, a lowercase 'l' suffix reads "
               "as '1', and trigraphs (??=) mangle source. Use hex/decimal and "
               "uppercase U/L suffixes.",
    },
    {
        "concern": "macro naming and #undef",
        "keywords": ["#define", "#undef", "keyword", "macro name", "preprocessor"],
        "rules": ["MISRA 20.4", "MISRA 20.5"],
        "avoid": "#define int long   /* macro named like a keyword */\n#undef MAX",
        "prefer": "/* never #define a name that is a language keyword; */\n"
                  "/* avoid #undef — scope macros tightly instead of undefining them */",
        "why": "Redefining a keyword-named macro or using #undef makes the meaning "
               "of code position-dependent and hard to review.",
    },
    {
        "concern": "command processors (system)",
        "keywords": ["system", "shell", "exec", "command", "popen", "getenv", "exit", "abort"],
        "rules": ["MISRA 21.8", "CERT ENV33-C"],
        "avoid": "system(cmd);   /* command injection + non-deterministic */",
        "prefer": "/* call a fixed, vetted API directly; never invoke a command processor, */\n"
                  "/* and avoid abort/exit/getenv/system in production firmware */",
        "why": "Invoking a command processor is a classic injection vector and is "
               "non-deterministic; the environment/termination functions are "
               "banned in production embedded code.",
    },
    {
        "concern": "signal handlers",
        "keywords": ["signal", "handler", "sigint", "async", "sig_atomic_t", "interrupt"],
        "rules": ["MISRA 21.5", "CERT SIG30-C"],
        "avoid": "signal(SIGINT, h);   /* and h() calls printf()/malloc() */",
        "prefer": "/* avoid <signal.h> in production; if unavoidable, the handler may call */\n"
                  "/* ONLY async-signal-safe functions and just set a volatile sig_atomic_t flag */",
        "why": "Most library calls are not async-signal-safe; a handler that does "
               "real work can deadlock or corrupt state. Set a flag and handle it "
               "in the main loop.",
    },
    {
        "concern": "non-local jumps (setjmp/longjmp)",
        "keywords": ["setjmp", "longjmp", "non-local", "jump", "exception", "unwind"],
        "rules": ["MISRA 21.4"],
        "avoid": "if (setjmp(env) == 0) { work(); } /* ... */ longjmp(env, 1);",
        "prefer": "/* propagate a status_t return up the call chain; */\n"
                  "status_t st = work();\nif (st != OK) { cleanup(); return st; }",
        "why": "setjmp/longjmp bypass normal scope and cleanup, leaving resources "
               "leaked and state inconsistent. Thread an explicit status return.",
    },
    {
        "concern": "variadic functions (stdarg)",
        "keywords": ["varargs", "stdarg", "va_list", "...", "variadic", "printf-like"],
        "rules": ["MISRA 17.1"],
        "avoid": "void log_msg(const char *fmt, ...);   /* no compile-time type checking */",
        "prefer": "void log_u32(const char *tag, uint32_t v);   /* fixed, type-checked args */\n"
                  "/* or pass an explicit typed array + length */",
        "why": "Variadic functions defeat the compiler's argument type checking and "
               "are a frequent source of mismatched-format faults. Use fixed, "
               "typed parameters.",
    },
    {
        "concern": "date and time facilities",
        "keywords": ["time", "clock", "asctime", "ctime", "gmtime", "localtime", "rtc"],
        "rules": ["MISRA 21.10", "CERT MSC33-C"],
        "avoid": "char *s = asctime(tm);   /* shared static buffer, no bounds */",
        "prefer": "/* avoid <time.h> in production; read the hardware RTC and format into */\n"
                  "/* your own bounded buffer: snprintf(buf, sizeof buf, \"%04u-%02u-%02u\", ...) */",
        "why": "The <time.h> facilities use shared static buffers and "
               "implementation-defined behaviour. Read a hardware clock and format "
               "into a bounded buffer you own.",
    },
    {
        "concern": "standard-library sort and search",
        "keywords": ["qsort", "bsearch", "sort", "search", "stdlib"],
        "rules": ["MISRA 21.9"],
        "avoid": "qsort(a, n, sizeof a[0], cmp);   /* impl-defined, recursive, unprovable cost */",
        "prefer": "/* use a vetted in-house sort/search with a provable worst-case bound */",
        "why": "bsearch/qsort have implementation-defined internals (often "
               "recursive) with no worst-case guarantee — unacceptable where "
               "timing must be provable.",
    },
    {
        "concern": "reentrancy of library functions",
        "keywords": ["strtok", "reentrant", "thread safe", "static buffer", "race",
                     "gmtime", "asctime"],
        "rules": ["CERT CON33-C"],
        "avoid": "char *p = strtok(s, \",\");   /* hidden static state: not reentrant */",
        "prefer": "char *save;\nchar *p = strtok_r(s, \",\", &save);   /* caller holds the state */\n"
                  "/* or pass all state explicitly and avoid the libc function entirely */",
        "why": "Library functions that keep static internal state race across "
               "threads/interrupts. Use the reentrant variant or pass state "
               "explicitly.",
    },
    {
        "concern": "dead and commented-out code",
        "keywords": ["comment", "commented out", "dead code", "disabled", "#if 0", "todo"],
        "rules": ["MISRA Dir 4.4", "BARR 2.2", "BARR 2.1a"],
        "avoid": "// x = compute_old(a, b);   /* commented-out code left behind */",
        "prefer": "/* delete it — version control preserves the history; keep only */\n"
                  "/* comments that explain intent, using /* */ or // consistently */",
        "why": "Commented-out code rots, misleads reviewers, and hides intent. "
               "Delete it and rely on version control.",
    },
    {
        "concern": "formatting and readability hygiene",
        "keywords": ["line width", "80 columns", "tabs", "indentation", "function length",
                     "warnings", "style", "readable"],
        "rules": ["BARR 3.1a", "BARR 3.2a", "BARR 6.3a", "BARR 1.1a"],
        "avoid": "/* 200-char lines, hard tabs, a 900-line function, warnings ignored */",
        "prefer": "/* keep lines within the column limit, indent with spaces not tabs, */\n"
                  "/* keep functions review-sized, and build at the strictest warning */\n"
                  "/* level with zero warnings */",
        "why": "Consistent width, spaces-not-tabs, review-sized functions and a "
               "clean strict-warning build keep code reviewable and catch defects "
               "the standards can't.",
    },
]


# rule_id (canonical) -> patterns that satisfy it. Built once, lazily.
_BY_RULE: dict[str, list[dict]] | None = None


def _index() -> dict[str, list[dict]]:
    global _BY_RULE
    if _BY_RULE is None:
        idx: dict[str, list[dict]] = {}
        for p in PATTERNS:
            for ref in p["rules"]:
                meta = REGISTRY.resolve(ref)
                if meta:
                    idx.setdefault(meta["id"], []).append(p)
        _BY_RULE = idx
    return _BY_RULE


def for_rule(rule_id: str) -> list[dict]:
    """Patterns whose compliant idiom satisfies this (canonical) rule id."""
    return _index().get(rule_id, [])


def guidance(query: str, limit: int = 5) -> list[dict]:
    """Proactive lookup: what to reach for when writing code about `query`.
    Matches the concern text, keywords, and referenced rule ids. Returns the
    best-scoring patterns with their resolved canonical rule ids."""
    q = (query or "").strip().lower()
    if not q:
        return []
    scored: list[tuple[int, dict]] = []
    for p in PATTERNS:
        score = 0
        if q in p["concern"].lower():
            score += 5
        for kw in p["keywords"]:
            if kw in q or q in kw:
                score += 2
        for ref in p["rules"]:
            meta = REGISTRY.resolve(ref)
            if meta and (q in ref.lower() or q in meta["id"].lower()):
                score += 3
        if score:
            scored.append((score, p))
    scored.sort(key=lambda t: t[0], reverse=True)
    out = []
    for _, p in scored[:limit]:
        canon = [REGISTRY.resolve(r)["id"] for r in p["rules"] if REGISTRY.resolve(r)]
        out.append({**{k: p[k] for k in ("concern", "avoid", "prefer", "why")},
                    "rules": canon})
    return out
