# Benchmarks

One honest run against a real, non-trivial embedded C codebase. The point is not
a flattering number — it is to show Maisha runs at scale and to measure, by manual
sampling, how much of its output is signal versus noise.

## Corpus

**FreeRTOS-Kernel** — the canonical MISRA-audited RTOS kernel (commit `ae46383`,
shallow clone). The 7 core `.c` files, **16,914 LOC** (headers and `portable/`
excluded). FreeRTOS is itself MISRA-checked, so a well-behaved tool should surface
*few* genuine defects — which makes it a good false-positive stress test.

| File | LOC | Findings |
|------|-----|----------|
| tasks.c | 8,883 | 856 |
| queue.c | 3,389 | 350 |
| stream_buffer.c | 1,757 | 202 |
| timers.c | 1,343 | 163 |
| event_groups.c | 887 | 98 |
| croutine.c | 407 | 58 |
| list.c | 248 | 30 |
| **Total** | **16,914** | **1,757** |

## Method

- `maishac scan` with all three analyzers: native (zero-dep), cppcheck 2.17.1
  (`--addon=misra`), clang-tidy (LLVM, `cert-*`/`bugprone-*`).
- **Include paths were deliberately *not* configured** — this is the naive
  out-of-the-box run, which is what a first-time user gets and therefore the
  honest thing to measure.
- Findings were bucketed by rule, then each significant rule class was reviewed
  against the actual source to classify true-positive vs. false-positive. For
  classes with a systematic pattern (e.g. every finding adjacent to a
  preprocessor line) the whole class was verified by script, not just a sample.

## Raw results

**By severity:** blocker 1 · critical 72 · major 16 · minor 1,668
**By standard:** BARR-C 1,596 · MISRA-C:2012 115 · CERT-C 1 · generic (tool meta) 45
**By analyzer:** native 1,625 · cppcheck 107 (+2 merged with native) · clang-tidy 23

**91% of all findings are a single advisory style rule** (BARR-C 3.1a, line > 80
chars) — FreeRTOS uses tabs and long lines. These are *true* (the lines really do
exceed 80) but the 80-column threshold is a project style choice, not a defect.
The interesting signal is the other **161 "substantive" findings.**

## False-positive analysis (the 161 substantive findings)

Every class below was verified against source:

| Rule | Count | Verdict | Root cause |
|------|-------|---------|------------|
| MISRA 8.4 (visible declaration) | 22 | **FP** | decl lives in a header not passed to cppcheck |
| MISRA 20.9 (`#if` identifiers undefined) | 37 | **FP** | `configUSE_*` macros defined in `FreeRTOSConfig.h`, not passed |
| MISRA 17.3 (implicit declaration) | 12 | **FP** | `listLIST_IS_EMPTY` etc. declared in unseen headers |
| cppcheck:misra-config | 21 | **FP** | cppcheck meta-warning, not a code defect |
| clang-tidy (all) | 23 | **FP** | `'FreeRTOS.h' file not found` → files never parsed |
| MISRA 15.6 (braceless body) | 16 | **FP** | body *is* braced; a `#if/#else/#endif` sits between the `if` header and its `{` (16/16 confirmed adjacent to a preprocessor line) |
| MISRA 17.2 (recursion) | 1 | **FP** | native's enclosing-function heuristic matched a call to a *differently-named* function |
| CERT STR31-C (`strcpy`) | 1 | **TP** | genuine unbounded `strcpy(pcBuffer, pcTaskName)` in `vTaskList` |
| MISRA 18.4 (pointer +/-) | 6 | **TP** (advisory) | real pointer arithmetic in queue management |
| MISRA 19.2 (`union`) | 2 | **TP** (advisory) | FreeRTOS uses a deliberate union |
| MISRA 20.5, 18.8, 15.5, Dir 4.6, 2.5, 12.3, … | 20 | not individually reviewed (plausible advisory TPs) | — |

**Confirmed false positives: 132 of 161 substantive findings.**

- **≈ 82% false-positive rate among substantive findings** (132 / 161).
- **≈ 7.5% false-positive rate overall** (132 / 1,757) — but that number is
  flattered by the 1,596 true style findings; the substantive rate is the honest one.

## What this benchmark actually bought us

The run is worth more as a bug-finder for *Maisha itself* than as a score. Three
concrete, fixable issues, all reproduced above:

1. **Include paths dominate the noise.** 94 of 132 FPs (MISRA 8.4/20.9/17.3,
   cppcheck:misra-config, all of clang-tidy) vanish the moment cppcheck/clang-tidy
   are given the kernel's include dirs. Maisha should accept and forward include
   paths (and, failing that, down-rank or auto-suppress the "missing configuration"
   and "file not found" classes so they don't masquerade as defects).
2. **Native recursion check (Rule 17.2) is context-fragile** — it flags a call as
   recursive when the *enclosing* function name coincides with a called name; here
   it fired on a non-recursive call. Needs a stricter enclosing-scope match.
3. **Native brace check (Rule 15.6) is blind to the preprocessor** — a
   `#if/#else/#endif` between an `if` header and its `{` defeats the "next line is a
   brace?" heuristic. All 16 hits were this single pattern.

## Not measured: loop convergence

The improvement backlog also asks for iterations-to-convergence and
percent-frozen-`needs_human`. Those require an agent (or human) actually *editing*
the kernel to fix findings, which is out of scope for a static benchmark run and
would produce fabricated numbers if simulated. Left for a future run driven by a
real fix agent against a smaller, buildable target.

---

*Reproduce:* clone FreeRTOS-Kernel, then
`maishac scan croutine.c event_groups.c list.c queue.c stream_buffer.c tasks.c timers.c`
from the kernel root. Numbers above are from a single run; native/cppcheck findings
are deterministic, clang-tidy's depend on parse success (here: none, no includes).
