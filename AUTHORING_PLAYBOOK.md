# Maisha Authoring Playbook (Mode 1 — writing new code)

This is the protocol for an LLM agent **writing new C** that must be MISRA
C:2012 / BARR-C:2018 / CERT C compliant. It is the proactive companion to
`AGENT_PLAYBOOK.md` (which drives remediation of *existing* code). Paste it into
your IDE's rules/system file (`CLAUDE.md`, `.cursorrules`, …) or hand it to the
agent at the start of an authoring task.

The goal: write it compliant on the **first draft**, instead of writing it and
fixing it on a later scan.

---

## The loop

```
about to write code ─► guidance(topic) ─► write draft ─► check_snippet(draft) ─┐
                            ▲                                                   │
                            └────────── while findings remain, rewrite ◄────────┘
                                                    │
                                        clean ─► write file ─► (later) full scan
```

### 1. Before writing — ask what to reach for

When you are about to write code for a recurring embedded-C concern, call
`compliance_guidance(topic=...)` **first**. Good topics: `"dynamic memory"`,
`"string copy"`, `"check return value"`, `"switch"`, `"recursion"`,
`"integer overflow"`, `"null pointer"`, `"loop"`, `"format string"`,
`"fixed-width types"`, `"goto"`.

Each returned pattern gives you:

- `prefer` — the compliant idiom to write (a code sample), and `avoid` — the
  anti-pattern it replaces.
- `why` — the reason, so you apply it correctly rather than by rote.
- `rules` — the MISRA/CERT/BARR-C guidelines the idiom satisfies.

Write from `prefer`. This is cheaper than writing the obvious (non-compliant)
version and having it flagged later.

### 2. After drafting — check before it hits disk

Call `compliance_check_snippet(code=...)` on the draft **before writing it to a
file**. Nothing is scanned or stored. For each violation you get the rule, a
`fix_hint`, and — when available — a `compliant_pattern` with the exact idiom to
swap in. Rewrite the offending lines and check again until `clean` is `true`.

### 3. Then write the file

Once the snippet is clean, write it. Run a full `compliance_scan` on the
committed file at a natural checkpoint.

---

## Two honest limits — do not skip step 3

- **`check_snippet` is native (lexical) only.** It catches the *syntactic*
  subset — dynamic allocation, recursion, banned functions, unbraced bodies,
  magic literals, unchecked returns, etc. It does **not** catch whole-program
  rules (data flow, value ranges, aliasing) that need a build model. A `clean`
  snippet is *not* a compliance guarantee.
- **Certification still needs a qualified engine.** For evidence an assessor
  accepts, run a qualified engine (Polyspace / Helix QAC / Astrée) on the
  committed code and `compliance_import_sarif` its results. Author-time checking
  reduces the rework; it does not replace the qualified run.

So: `guidance` and `check_snippet` make the *first draft* compliant and cheap to
review — `scan`, the fix loop (`AGENT_PLAYBOOK.md`), and a qualified engine
close the loop for certification.
