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
        "keywords": ["goto", "label", "jump", "break", "continue", "single exit"],
        "rules": ["MISRA 15.1", "BARR 1.7a"],
        "avoid": "if (err) goto cleanup;   /* ... */  cleanup: release();",
        "prefer": "/* structure with a status variable and a single return */\n"
                  "status_t st = OK;\nif (err) { st = FAIL; }\nif (st == OK) { work(); }\n"
                  "release();\nreturn st;",
        "why": "goto obscures control flow. Use structured control with a status "
               "variable so the path (and cleanup) is explicit and reviewable.",
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
