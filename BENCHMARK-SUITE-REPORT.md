# Maisha Full Benchmark Suite — Report

**What this is:** a from-scratch, hands-on test suite built specifically to answer
one question honestly: *is Maisha ready to launch and use, and what exactly are
its capabilities and limits?* Unlike `BENCHMARKS.md` (one real-world corpus run,
FreeRTOS), this suite is purpose-built: realistic synthetic C fixtures with
**hand-verified ground truth**, a full **end-to-end fix-loop simulation** against
a synthetic firmware module (not a unit test — a real multi-iteration session
driven exactly the way `AGENT_PLAYBOOK.md` describes), SARIF import validation,
CLI-as-subprocess smoke tests, edge cases, and a performance stress test. All
three real analyzers were used — **cppcheck 2.17.1** (with the MISRA addon) and
**clang-tidy 22.1.7 (LLVM)** were installed via pip wheels for this run, alongside
the native zero-dependency analyzer — so this reflects the tool's actual
multi-analyzer behavior, not a native-only approximation.

Everything here is reproducible and checked into `benchmark/`: fixtures,
ground truth, harness scripts, and raw results.

---

## Executive summary

**Verdict: yes, ready to use — with the same caveats the project already states
about itself (not a certified tool, ~80-rule curated coverage), plus four real
bugs this suite found and fixed, and one important behavioral finding about the
verification gate that changes how adopters should plan their review workload.**

| Dimension | Result |
|---|---|
| Detection recall (32 deliberately seeded defects across 7 fixtures) | **100%** (32/32) |
| Detection precision (all in-scope findings, post-fix) | **100%** (0 confirmed false positives) |
| Fix-loop mechanics (gate, oscillation, stall, budget) | All 4 mechanisms independently verified working correctly |
| Verification gate vs. the README's sentinel-cast trap | Caught correctly, end-to-end, with a real engine (not a mock) |
| SARIF import (foreign rule-id formats, survival across rescans, codeFlows into briefing, relationships + round-trip) | All 8 checks passed |
| CLI end-to-end (14 subprocess invocations, real argparse wiring) | All passed (after 1 fix) |
| Edge cases (empty file, BOM, non-UTF-8, CRLF, long lines, spaces-in-path) | All passed |
| Performance (2000-function / 12k-line file) | **0.44s** (was 374s before a fix found by this suite) |
| Bugs found | **4**, all fixed and regression-tested this cycle |

The single most important finding isn't a bug — it's a behavioral discovery about the
verification gate (see "The gate is more conservative than it looks" below): in a
realistic fix session, **zero findings were auto-resolved by a passing test
suite**. Every MISRA rule category the fixtures touched (10.x/11.x/13-16.x, plus
CERT FLP/INT rules) is broadly classified as semantic-risk, so `test_gated`
sessions on typical MISRA work end up behaving almost identically to
`human_gated` in practice. That's a defensible safety posture, but it means
teams should budget for **human review of nearly every fix**, not assume
`test_gated` will meaningfully cut review load.

---

## 1. Environment & methodology

- OS: Windows (Git Bash shell). Python 3.10.
- `cppcheck` 2.17.1 and `clang-tidy` 22.1.7 installed via `pip install cppcheck
  clang-tidy` (prebuilt wheels — the same install path the README recommends
  for users without root/a system package manager).
- Because this is a from-scratch fixture set (not real headers), a small set
  of stub headers (`benchmark/stubs/`) stands in for `<stdint.h>`,
  `<string.h>`, etc., so `clang-tidy` can fully type-check the files rather
  than degrade on missing system headers.
- All fixtures, ground truth, harness scripts, and raw JSON/text results are
  committed under `benchmark/` — nothing here is a one-off scratch run.

```
benchmark/
  fixtures/                    7 standalone C files, hand-annotated ground truth
  ground_truth.json            seeded defects + known-true-extra + false-positive log
  run_accuracy_benchmark.py    scans fixtures, computes recall/precision
  firmware/                    2-file synthetic firmware module + headers
  run_loop_simulation.py       drives 4 real Maisha sessions end-to-end
  synthetic_qualified_engine.sarif.json   synthetic "external engine" SARIF
  run_sarif_import_test.py     validates the SARIF import path
  run_cli_and_edge_cases.py    CLI subprocess smoke test + edge cases + perf
  stubs/                       minimal libc stand-ins so clang-tidy can parse
  results/                     raw output from every run above
```

Reproduce any part with, e.g.:
```bash
python benchmark/run_accuracy_benchmark.py
python benchmark/run_loop_simulation.py
python benchmark/run_sarif_import_test.py
python benchmark/run_cli_and_edge_cases.py
```

---

## 2. Detection accuracy

### 2.1 Fixtures

Seven realistic C files (`benchmark/fixtures/`), each modeling a common
embedded pattern, each seeded with a known set of defects **and** deliberate
false-positive traps (patterns that look risky but are correct):

| Fixture | Pattern | Seeded defects |
|---|---|---|
| `01_string_handling.c` | log/format buffer handling | 7 (strcpy/strcat/sprintf, malloc, printf) |
| `02_register_driver.c` | memory-mapped peripheral driver | 6 (union overlay, goto, switch, octal, assign-in-if) |
| `03_state_machine.c` | event-driven state machine | 2 (genuine recursion + a braceless if), plus 2 dedicated false-positive traps for the recursion/multi-line-signature bug fixed last cycle |
| `04_memory_and_signals.c` | library-heavy legacy code | 11 (setjmp/longjmp, signal/raise, malloc/free, atoi, strtok, rand, system, qsort) |
| `05_float_and_int_edge_cases.c` | numeric edge cases | 3 (float equality x2, lowercase-l suffix), plus the README's sentinel-cast pattern for documentation |
| `06_preprocessor_heavy.c` | feature-flagged code | 3 (a genuine braceless-if next to preprocessor noise, 2x `#undef`) |
| `07_clean_reference.c` | deliberately well-written code | 0 (measures the false-positive rate on **good** code) |

**32 seeded defects total.** Ground truth (`benchmark/ground_truth.json`) also
tracks which additional findings are legitimate-but-not-deliberately-seeded
("incidental true positives" — e.g. MISRA 15.5 firing correctly on every
early-return function) versus confirmed analyzer mistakes, so the precision
number isn't inflated by waving away real findings.

### 2.2 Results

| Metric | Without `--include` | With `--include benchmark/stubs` |
|---|---|---|
| Seeded-defect recall | 32/32 (100%) | 32/32 (100%) |
| Incidental true positives | 74 | 83 |
| Confirmed false positives | 0 | 0 |
| Unclassified (needs review) | 0 | 0 |
| **Precision** | **100%** | **100%** |

**100% recall, 100% precision** on this corpus, after two rounds of fixes this
suite drove (see §5). The `--include` comparison is smaller than in the
FreeRTOS run because these fixtures use minimal local stub headers rather than
a large real config header — but it still measurably increases clang-tidy's
useful output (9 more genuine findings) with zero added noise, confirming the
include-path-forwarding fix from last cycle works as intended on a second,
independent corpus.

### 2.3 What "100% precision" does and doesn't mean

Two confirmed false positives were found in the *first* run of this suite and
are now fixed (§5.4): native's MISRA 18.8 (possible VLA) check flagged a fixed
array sized by an `ALL_CAPS` macro constant — a textbook-common embedded
pattern (`uint8_t buf[BUF_SIZE];`) — as a variable-length array, because the
native analyzer doesn't preprocess and can't resolve the macro's value. This
was confirmed on **two independent fixtures**, so it wasn't a one-off.

100% is a real, clean number on *this* corpus, not a universal claim — a
larger/more diverse corpus (like the FreeRTOS run in `BENCHMARKS.md`, which
measured 82% FP among substantive findings on unfamiliar real-world code
*before* the config/include-path fixes) is a better estimate of the "day
one, unfamiliar codebase" false-positive rate. What this run adds is
**confirmation that specific, previously-identified failure classes are
actually fixed**, on fixtures purpose-built to reproduce them.

---

## 3. Fix-loop simulation (the core value proposition, tested end-to-end)

`benchmark/firmware/` is a small 2-file synthetic driver (`motor_control.c`,
`uart_driver.c`, ~100 lines) with 24 real findings across severities,
including the **exact sentinel-cast scenario from the README**:
`g_configured_current_limit_ma = -1` means "no limit configured"; a naive fix
to the resulting signed/unsigned comparison warning casts it to `uint32_t`,
turning "no limit" into "4,294,967,295" — silently disabling the shutdown
behavior it was supposed to trigger.

`benchmark/run_loop_simulation.py` plays the agent role from
`AGENT_PLAYBOOK.md` for real: `begin_session` → `next_batch` → apply a
scripted fix per finding → `record_attempt` → `verify` → repeat, against a
live `LoopEngine` and real analyzer output (not mocked).

### 3.1 What happened

1. **Baseline scan**: 24 findings. Two were suppressed immediately as
   confirmed false positives (a bare function-prototype mistaken for a call;
   the VLA-in-struct issue from §2.3) — demonstrating `compliance_suppress_finding`
   used exactly as intended.
2. **6 real defects fixed correctly** (switch-default, braceless-if,
   float-equality tolerance, bounded string copy, decimal literal, goto
   removal) across 3 batches.
3. **3 advisory rule categories deviated** (single-point-of-exit, block-scope
   suggestion, const-correctness) with real per-rule justifications —
   `compliance_add_deviation` used exactly as intended, including one case
   (MISRA 8.9 on a buffer that must persist across calls) where the rule's
   suggested fix would have been actively wrong.
4. **The sentinel-cast trap was applied exactly as in the README** — and
   caught. A `test_gated` session with an always-passing fake test command
   (simulating a real test suite that happens not to exercise the `-1`
   sentinel case — the realistic failure mode) put the fix in
   `pending_verification` and required a human decision anyway.
5. **The human reviewer role in the script recognized the bug, rejected the
   dangerous fix, and applied the correct one** (an explicit sentinel guard
   before the cast) — the loop correctly required a second approval on the
   corrected version too (same rule category, same policy).
6. **Session converged.** Final state: `converged`, 0 open, 0 pending.

### 3.2 The gate is more conservative than it looks

Across the whole session, **the passing test command auto-resolved exactly
zero findings.** Every one of the 8 pending findings — including the 6 that
were fixed *correctly*, with no behavioral risk at all — required human
`approve_finding` sign-off, because:

- 4 were `critical`/`blocker` severity (always human-gated, by design).
- The rest matched `semantic_risk`'s rule-category list — and that list is
  broad: substrings `" 10."`, `" 11."`, `" 13."`, `" 14."`, `" 15."`, `" 16."`
  cover most of MISRA's essential-type, control-flow, and switch-statement
  rules, plus `FLP`/`INT30-33` for CERT. In practice this means **most common
  MISRA rule categories are semantic-risk by category, not just by the
  presence of a cast** — a stronger, more conservative check than the
  README's cast-detection framing suggests (confirmed by reading
  `memory/__init__.py::semantic_risk` and observing it trigger on `motor_should_shutdown`'s
  finding **the moment it was first detected**, before any fix was even attempted).

**Practical implication for adopters:** `verification_policy=test_gated` will
not meaningfully reduce human review load on typical MISRA-heavy findings —
plan for a human to review nearly every fix, same as `human_gated`. This is
arguably the *correct* safety trade-off for the tool's stated audience
(safety-critical/embedded), but it's a real planning number, not a marketing
claim, and the README doesn't currently say this explicitly.

### 3.3 Guard-rail mechanics, verified independently

Run on fresh copies of the same fixture with `verification_policy=analyzer_only`
to isolate each mechanic from gate complexity:

| Mechanic | Test | Result |
|---|---|---|
| **Oscillation freezing** | Fix → verify (resolved) → regress → verify → repeat once more | Correctly froze as `needs_human` after the 2nd regression; excluded from `next_batch` thereafter |
| **Stall detection** | No-op edits across `stall_limit=2` verifies | Correctly reached `stalled` |
| **Budget exhaustion** | `max_iterations=2`, kept editing | Correctly reached `budget_exhausted` at iteration 2, regardless of remaining open findings |

All three terminal states are reachable and correct — the "the loop must
terminate" design invariant holds under direct testing, not just unit tests.

---

## 4. SARIF import

`benchmark/synthetic_qualified_engine.sarif.json` simulates a third-party
qualified-engine SARIF export (a **synthetic** file — not real output from any
named commercial tool) with three results: a MISRA id in a foreign format
(`misra-c2012-10.1`), a CERT id in a foreign format (`CERT-ERR33-C`), and one
proprietary rule id with no Maisha mapping (`PROPRIETARY-STACK-DEPTH-001`)
carrying a three-step call-graph `codeFlow` — the kind of data-flow path a
qualified engine emits and a naive importer throws away.

All 8 checks passed (`python benchmark/run_sarif_import_test.py`):
- Both recognized ids correctly mapped onto the knowledge base
  (`MISRA-C:2012 Rule 10.1`, `CERT ERR33-C`).
- The unrecognized id was preserved as `sarif:PROPRIETARY-STACK-DEPTH-001`
  rather than silently dropped.
- All 3 imported findings coexisted with the 23 native-scan findings with no
  fingerprint collisions.
- **A subsequent native rescan did not clear any imported finding** — the
  producer-set isolation documented in the README holds under a real test,
  not just the existing unit test.
- All of the above surfaced correctly in `compliance_report`.
- **The `codeFlow` was parsed and reached the agent fix briefing intact** — all
  3 steps (`motor_should_shutdown` → `uart_log_fault` → `strcpy`, spanning two
  files), so a fixer sees *how* the defect flows, not just where it lands.
- **Export emitted 8 cross-standard equivalences as SARIF rule
  `relationships`** (e.g. `CERT STR31-C` ↔ `MISRA-C:2012 Rule 21.6`), every
  relationship target resolving to a descriptor in the same run, and the
  imported `codeFlow` + `startColumn` round-tripped losslessly back out to
  SARIF.

---

## 5. Bugs found and fixed this cycle

This suite found **4 real, previously-unknown bugs** — 2 of them serious
(a near-total loss of clang-tidy's value on Windows, and a 374-second stall
that would make the tool impractical on any sizeable single file). All 4 are
fixed, regression-tested (`tests/test_benchmark_fixes.py`, 31 tests total
across both benchmark cycles), and documented in `CHANGELOG.md`.

### 5.1 clang-tidy silently dropped almost all findings on Windows

`ClangTidyAnalyzer`'s diagnostic regex assumed Unix-style paths
(`[^:\n]+:line:col:`). clang-tidy always emits **absolute, drive-letter
paths** in its diagnostics on Windows (`D:\proj\src\a.c:20:5: warning: ...`)
regardless of how the path was passed on the command line. The drive-letter
colon broke the file/line-number split, so the regex matched **zero**
diagnostics on this platform — confirmed by direct comparison: raw
`clang-tidy` output on the fixture set had dozens of real findings
(`cert-err34-c`, `bugprone-*`, `clang-analyzer-security.*`), while Maisha's
parsed output had exactly one (a diagnostic that happened to use a relative
path). **Fixed**: non-greedy file-path group. Every finding class now parses
correctly.

### 5.2 The native recursion check was O(functions × lines)

For every line, the check looped over *every function name seen so far in the
file* with a fresh regex compile each time. A synthetic 2000-function,
12,288-line file (207 KB — a large but not absurd "god file," which do exist
in real vendor/legacy embedded code) took **374 seconds** to scan. **Fixed**:
replaced the O(n²) scan with an O(1)-per-line check against only the
*current* enclosing function, tracked incrementally via the same brace-depth
counter already used for switch-statement tracking. Same file now scans in
**0.44 seconds** (≈850x). Verified no regression in detection (same 572
findings, full accuracy-suite recall unchanged at 100%).

### 5.3 `maishac report --format markdown` crashed on a default Windows console

The standards-matrix table used ✅/❌ emoji, and the "no open findings" message
used 🎉. Neither is representable in `cp1252`, the default Windows console
codepage — printing the report crashed the whole CLI command with
`UnicodeEncodeError`. **Fixed**: replaced with plain ASCII (`yes`/`no`), and
additionally hardened the CLI's stdout/stderr with `errors="replace"` so no
single unprintable character (in a finding message, a user's note, a
justification string) can crash any command's output again — a compliance
tool's core reporting command should never be one non-ASCII character away
from an unhandled crash.

### 5.4 MISRA 18.8 (VLA) false-positive on macro-sized fixed arrays

See §2.3. **Fixed**: the VLA check now skips array-size identifiers written
in `ALL_CAPS` (the near-universal C convention for macro constants), while
still catching genuine variable-sized arrays (lowercase/mixed-case
identifiers) — verified with both a macro-sized-array case (no longer
flagged) and a genuine runtime-sized array (still flagged).

---

## 6. CLI end-to-end and edge cases

`run_cli_and_edge_cases.py` invokes the **actual CLI as a subprocess**
(`python -m maishac.cli ...`), not the engine directly — this is the only part
of this suite that exercises real argparse wiring, and it's what caught §5.3.

- **14 CLI invocations** (scan, findings ×2, rule ×2, session begin/batch/status/verify,
  approve, suppress, deviate ×2, note, report ×3, import, scan-of-nonexistent-path):
  all pass, including confirming a second concurrent `session begin` is
  correctly refused and an unknown rule lookup exits non-zero with suggestions.
- **Edge cases**, all pass without crashing: empty file, UTF-8 BOM, non-UTF-8
  (Latin-1) bytes, CRLF line endings (still detects violations correctly),
  a 500-character single line, a file path containing spaces.

---

## 7. Performance

| Scenario | Before this cycle | After |
|---|---|---|
| 2000 functions / 12,288 lines / 207 KB (native analyzer only) | 374.0s | **0.44s** |

A regression test (`test_recursion_check_is_linear_not_quadratic`) bounds this
at under 5 seconds for 400 functions in CI, so this can't silently regress.

No large-scale multi-analyzer (cppcheck + clang-tidy) timing was captured
here since subprocess-per-file overhead for those tools dominates and is
outside Maisha's own code — the native analyzer is the part whose performance
is Maisha's responsibility, and that's what this measures.

---

## 8. Known limitations (confirmed or reconfirmed by this suite)

These are not new — most are already documented in `README.md` and
`BENCHMARKS.md` — but this suite independently reconfirms them:

- **Not a certified/qualified analysis tool.** Still true; nothing here
  changes that. Use SARIF import to layer on a qualified engine for
  certification evidence, as documented.
- **~80 curated rules.** Still true; `COVERAGE.md` remains the honest account
  of exactly what's covered.
- **The verification gate trades human effort for safety, more than the
  README's framing suggests** (§3.2) — this is the main *new* piece of
  clarity from this suite, not a limitation to fix, but a planning
  expectation to set correctly.
- **Native analyzer false positives are a real, non-zero category** — this
  run found and fixed 2 (from 1 root cause); there is no reason to believe
  every such class has now been found. A regex/lexical analyzer without a
  real preprocessor or type system will always have some.
- **This suite's 100% precision is corpus-specific**, not a universal claim
  — see §2.3.

## 9. What wasn't covered in this cycle

- No fuzz-testing of the native analyzer against malformed/adversarial C
  syntax (only realistic and a handful of edge-case inputs).
- No test of the MCP server's actual stdio protocol surface end-to-end
  (only the underlying engine calls the MCP tools wrap were exercised, via
  the CLI and direct engine tests) — a real MCP-client-driven session would
  be the natural next benchmark.
- No multi-user/concurrent-session stress test beyond the existing
  single-assertion unit test for the `session begin` lock.
- Convergence statistics (iterations-to-converge, %-frozen-`needs_human`)
  were measured on one small synthetic module, not a large real corpus —
  `BENCHMARKS.md` already flags this as a natural follow-up requiring a real
  agent driving a real, larger codebase to fix.

---

## Bottom line

Maisha does what it says it does. Detection is accurate on realistic code
(100% recall, 100% precision on this corpus), the loop mechanics
(gate/oscillation/stall/budget) all work exactly as designed under direct
testing — not just unit tests — and the SARIF import and CLI surfaces are
solid. This cycle found and fixed 4 real bugs, two of which (the Windows
clang-tidy regex and the O(n²) recursion check) were serious enough to
significantly affect real-world usability, and produced one important
behavioral clarification (§3.2) that adopters should know going in. The
project's own honest framing about certification and coverage scope remains
correct and doesn't need softening or hedging further.
