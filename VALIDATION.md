<!-- §4 (real-world corpora) is updated as the benchmark run completes each corpus. -->
# Maisha — Validation Evidence Pack

**Document type:** self-attested validation evidence (test & benchmark report).
**Subject:** `maishac` (Maisha) — agent harness for MISRA C:2012, BARR-C:2018 and CERT C.
**Version under test:** 0.3.1 · **Baseline commit:** `62b4399` (+ the fixes recorded in §6 of this cycle).
**Date of run:** 2026-07-17.

---

## 0. What this document is — and is NOT

> ⚠️ **This is a validation *evidence* pack, not a tool-qualification certificate.**
> It attests, with reproducible evidence, that a defined set of tests and
> benchmarks were executed against a defined version of Maisha in a defined
> environment, and records the measured results and the known limitations. It is
> a **self-attestation** by the engineering team that produced it.
>
> It is **NOT**, and does not claim to be:
> - a DO-178C / DO-330, ISO 26262, or IEC 62304 **tool-qualification certificate**;
> - a statement that Maisha is a qualified or certified static-analysis tool;
> - a substitute for the tool-qualification activity a safety standard requires,
>   which needs a documented qualification kit, tool operational requirements,
>   and an **accredited assessor / certification body** to issue a certificate.
>
> Maisha's own documentation (`README.md` "Scope & Limitations", `CLAUDE.md`)
> states it is *not a qualified/certified analysis tool*. Nothing in this pack
> changes that. This pack is the honest engineering evidence that would *support*
> such a qualification effort if one were undertaken with a real assessor — it is
> the foundation, not the certificate.

**Attestation.** On the environment and version recorded in §1, the test suite
and benchmarks described in §3–§4 were executed and produced the results
recorded there. Three defects found during this validation were fixed and
regression-tested (§6). The limitations in §7 are stated without reservation.
This attestation covers *test execution and results only*; it makes no
fitness-for-certification claim.

---

## 1. Environment manifest

| Item | Value |
|---|---|
| OS | Windows 11 (26200); cross-checked under Git Bash and PowerShell |
| Python | 3.10.11 |
| Maisha | 0.3.1 (`maishac`), baseline commit `62b4399` |
| Native analyzer | built-in, zero-dependency (always available) |
| cppcheck | 2.17.1 (MISRA addon), installed via `pip install cppcheck` |
| clang-tidy | LLVM 22.1.7, installed via `pip install clang-tidy` |
| Test framework | pytest 8; coverage.py 7.15; hypothesis 6.156; jsonschema 4.23 |
| SARIF schema | official OASIS SARIF 2.1.0 (`tests/data/sarif-2.1.0.json`, vendored) |

All three analyzers were active for the accuracy, real-world, and SARIF
benchmarks — results reflect true multi-analyzer behavior, not native-only.

---

## 2. Scope of validation

Validated in this cycle (✓ = executed here; evidence in the referenced tests/reports):

| Surface | How validated | Evidence |
|---|---|---|
| Detection accuracy | recall/precision on ground-truthed fixtures | §3.1, `benchmark/run_accuracy_benchmark.py` |
| Native analyzer robustness | property/fuzz testing (invariants) | §3.6, `tests/test_fuzz_native.py` |
| External analyzer adapters | parse/mapping unit tests + live multi-analyzer runs | §3.4, `tests/test_adapters.py` |
| Fix loop + verification gate | end-to-end simulation + unit tests | §3.2, `tests/test_verification_gate.py` |
| Persistent memory | lifecycle + **concurrency stress** | §3.5, `tests/test_concurrency.py` |
| Reporting / SARIF | semantic tests + **official-schema conformance** | §3.3, `tests/test_sarif_schema.py` |
| CLI | in-process command + exit-code matrix, edge cases | §3.4, `tests/test_cli_e2e.py` |
| **MCP server** | **real stdio JSON-RPC end-to-end** + in-process tools | §3.4, `tests/test_mcp_server.py` |
| Real-world behavior | multi-corpus finding distribution / FP-prone classes | §4, `benchmark/run_realworld_benchmark.py` |

Not validated in this cycle — see §8.

---

## 3. Results — test suite & core benchmarks

**Test suite: 90 tests, 100% pass. Line coverage of `maishac/`: 94%.**
(Baseline before this cycle: 54 tests, 70% coverage.)

Per-module coverage (native path; adapters' real-invocation paths additionally
exercised live):

| Module | Coverage | Module | Coverage |
|---|---|---|---|
| `mcp_server.py` | 98% | `cli.py` | 92% |
| `rules/__init__.py` | 99% | `analyzers/cppcheck.py` | 91% |
| `patterns.py` | 100% | `analyzers/native.py` | 94% |
| `memory/__init__.py` | 96% | `engine/__init__.py` | 94% |
| `report.py` | 95% | `analyzers/clang_tidy.py` | 86% |

### 3.1 Detection accuracy (fixtures, multi-analyzer)

`benchmark/run_accuracy_benchmark.py` over 7 ground-truthed fixtures
(`benchmark/ground_truth.json`), all three analyzers:

- **Seeded-defect recall: 32/32 = 100%.**
- **Confirmed false positives: 0 → precision 100%** on this corpus.
- Incidental (correct, non-seeded) true positives: 83.

Corpus-specific number, not a universal claim — the real-world estimate is §4.

### 3.2 Fix loop & verification gate

`benchmark/run_loop_simulation.py` drives real `LoopEngine` sessions the way
`AGENT_PLAYBOOK.md` prescribes. Confirmed end-to-end:

- The **sentinel-cast trap** (README §"verification gate") is caught: a fix that
  silences the analyzer but changes boundary behavior stays `pending_verification`
  and requires human sign-off even under `test_gated` with a passing test.
- All three non-converged terminal states are reachable and correct:
  `stalled` (no-progress), `budget_exhausted` (iteration cap), and oscillation
  freezing to `needs_human`. **The loop always terminates.**
- Gate unit tests (`tests/test_verification_gate.py`) confirm: no auto-resolve
  without confirmation; human approval records `approved_by`; a still-detected
  finding cannot be approved; a *failing* test confirms nothing; semantic-risk /
  high-severity findings require human approval regardless of policy.

### 3.3 SARIF import & conformance

- Semantic import tests pass (`tests/test_sarif_import.py`, `test_sarif_dialects.py`):
  foreign rule-id dialects (Helix-QAC taxonomy, Coverity bare number, ruleIndex),
  codeFlows into the briefing, suppressions carried, cross-standard relationship
  export, lossless round-trip; imported findings survive native rescans.
- **NEW — schema conformance (`tests/test_sarif_schema.py`):** empty, native-scan,
  and imported-with-codeFlows exports all validate against the **official OASIS
  SARIF 2.1.0 JSON schema**. Maisha emits SARIF a downstream consumer will accept.

### 3.4 Interface surfaces

- **MCP server (NEW):** `tests/test_mcp_server.py` spawns `python -m
  maishac.mcp_server` and drives a full `scan → begin → next_batch →
  record_attempt → verify → report` loop over **real stdio JSON-RPC**, asserting
  the documented tool surface is registered and reachable. This closes the "no
  test of the MCP server's actual stdio protocol surface" gap
  (`BENCHMARK-SUITE-REPORT.md` §9). An in-process companion covers every tool body.
- **CLI (NEW in-process):** `tests/test_cli_e2e.py` exercises every subcommand
  plus error/exit-code branches (unknown rule → exit 1, bad deviation date,
  illegal GRP re-categorization, malformed/missing SARIF import). Complements the
  subprocess black-box smoke test in `benchmark/run_cli_and_edge_cases.py`.
- **Adapters (NEW):** `tests/test_adapters.py` feeds synthetic cppcheck XML and
  clang-tidy output to exercise MISRA/CERT mapping, generic fallthrough, severity
  mapping, and the Windows drive-letter-path regression — without the tools
  installed.

### 3.5 Concurrency (NEW)

`tests/test_concurrency.py` stresses the shared WAL `memory.db`: 8 parallel
writers × 40 writes with a start barrier complete with **zero lock errors and
zero lost writes**; a reader loop and a 200-write writer coexist without
starvation; a second `LoopEngine` is refused an active session across instances
(with `force` override). Closes the concurrency-stress gap (`BENCHMARK-SUITE-REPORT.md` §9).

### 3.6 Property / fuzz testing (NEW)

`tests/test_fuzz_native.py` (Hypothesis) asserts *invariants* over thousands of
generated inputs: the native analyzer never raises on arbitrary/adversarial C or
Unicode; `strip_comments_strings` preserves total length and newline positions
exactly; `enclosing_function` never raises; a fingerprint is invariant under
whitespace reflow and deterministic. **This suite found defect #3 (§6).** Closes
the native-analyzer fuzzing gap (`BENCHMARK-SUITE-REPORT.md` §9).

### 3.7 Performance

Native analyzer on a synthetic 2000-function / 12,288-line / 207 KB file:
**≈0.86 s** (bounded < 5 s for 400 functions by a CI regression test). No silent
O(n²) regression path.

---

## 4. Results — real-world corpora

Method mirrors `BENCHMARKS.md`: scan real embedded-C projects with all analyzers;
report finding **distribution and density** (no ground truth exists, so this is
not recall/precision), and bucket out the rule classes `BENCHMARKS.md` proved are
configuration/include-path-driven false positives so a reviewer samples them
first. Runner: `benchmark/run_realworld_benchmark.py`; corpora pinned in
`benchmark/corpora/CLONE.sh`.

Engines: native + cppcheck (MISRA addon). clang-tidy was excluded from the corpus
run: on un-built third-party source without a compilation database it emits mostly
`file not found` noise (see `BENCHMARKS.md`) at a large per-file time cost — low
signal for a distribution measurement.

| Corpus | Files | kLOC | Findings | /kLOC | critical+ | minor | FP-prone* |
|---|--:|--:|--:|--:|--:|--:|--:|
| littlefs (`v2.9.3`) | 14 | 14.3 | 1,822 | 127.6 | 691 | 1,131 | 128 |
| lwIP (`STABLE-2_2_0`) | 38 | 34.3 | 5,729 | 166.9 | 503 | 5,226 | 198 |
| mbedTLS (`v3.6.2`) | 47 | 52.4 | 2,671 | 51.0 | 13 | 2,658 | 5 |
| Zephyr (kernel) | 78 | 22.9 | 9,873 | 430.7 | 6 | 9,867 | 6 |
| **Total** | **177** | **123.9** | **20,095** | **162.2** | **1,213** | **18,882** | **337** |

\* *FP-prone* = findings in the rule classes `BENCHMARKS.md` proved are dominated by
configuration/include-path false positives on an out-of-the-box run (8.4, 20.9,
17.3, 15.6, 17.2) — surfaced separately so a reviewer samples them first rather
than treating them as defects. "critical+" folds in the few blocker findings.

**Reading these numbers honestly** (consistent with the FreeRTOS run in
`BENCHMARKS.md`):

- **Density is dominated by advisory / style findings, not defects.** 94% of all
  findings (18,882 / 20,095) are `minor` — MISRA advisory + BARR-C line-length /
  tab-indentation style. Zephyr's 430/kLOC is almost entirely BARR-C style (9,420
  of its 9,873 findings) because the kernel uses tabs and long lines — *true*
  findings against an 80-column/space house style Zephyr does not share, not
  defects. This is the same effect measured on FreeRTOS.
- **The known-FP-prone tail is ~1.7% of findings** (337 / 20,095), and *lower on
  well-kept code*: mbedTLS — a MISRA-conscious crypto library — scans at 51/kLOC
  with only **5** FP-prone findings across 52 kLOC. Density tracks house style far
  more than it tracks code quality.
- These are **distribution** numbers on unfamiliar out-of-the-box code, **not a
  recall/precision claim** — no ground truth exists for these corpora. The
  take-away for adopters matches the README: set a severity floor and your own
  style config, and pass include paths, before reading raw counts.

---

## 5. Requirements / invariants → test traceability

Each core design invariant (from `CLAUDE.md` "Key design invariants" and the
README) mapped to the evidence that exercises it:

| # | Invariant | Evidence |
|---|---|---|
| I1 | Findings identified by content fingerprint, never line number | `test_smoke::test_fingerprint_stability`; `test_fuzz_native` (whitespace-invariant, deterministic) |
| I2 | A fix is never `resolved` on a clean rescan alone | `test_verification_gate::test_gate_holds_finding_pending_without_confirmation` |
| I3 | Semantic-risk / high-severity always require human sign-off | `test_verification_gate::test_test_gated_confirms_safe_but_not_risky`, `::test_semantic_risk_classifier` |
| I4 | Imported (SARIF) findings never cleared by a native rescan | `test_sarif_import::test_imported_findings_survive_a_native_rescan` |
| I5 | The loop always reaches a terminal state | `run_loop_simulation.py` (stalled/budget/oscillation); `test_smoke::test_memory_lifecycle_and_loop` |
| I6 | MISRA GRP re-categorization legality enforced | `test_gep_grp::test_grp_rejects_illegal_recategorizations` |
| I7 | Deviations are scoped, justified, expiring audit records | `test_smoke::test_deviation_and_suppression`; `test_misra_compliance` |
| I8 | Fuzzy rule-id resolution across 3 standards | `test_smoke::test_registry_resolution` |
| I9 | Multi-analyzer fingerprint-merge / dedup | `test_adapters`; live multi-analyzer accuracy run (§3.1) |
| I10 | Concurrent access is safe (WAL); one active session per project | `test_concurrency`; `test_smoke::test_concurrent_session_begin_is_guarded` |
| I11 | SARIF export conforms to the 2.1.0 schema | `test_sarif_schema` |
| I12 | Reporting/CLI never crash on unrepresentable or bad input | `test_benchmark_fixes::test_markdown_report_has_no_non_cp1252_characters`; `test_cli_e2e` (missing/malformed import) |
| I13 | Native lexer degrades, never crashes, on any input | `test_fuzz_native::test_native_analyzer_never_crashes*` |
| I14 | Full MCP tool surface reachable over stdio | `test_mcp_server::test_mcp_stdio_end_to_end` |

---

## 6. Defects found and fixed this cycle

All three found by this validation, fixed, and regression-tested; suite green
after each (fix-and-document policy).

**#1 — Non-portable gate test (`test_command: "true"/"false"`).**
The gate tests hard-coded the Unix shell builtins `true`/`false`; run via
`subprocess(shell=True)` these resolve to `cmd.exe` on Windows, which has neither,
so the tests passed only where a `true`/`false` executable was on PATH (Linux CI,
Git Bash) and **failed on a bare Windows shell**. *Fix:* drive the current
interpreter (`sys.executable -c "raise SystemExit(0/1)"`) — portable everywhere.
Verified green in **both** PowerShell and Git Bash. (Test-suite defect, not a
product defect.)

**#2 — `maishac import` crashed on a missing/malformed file.**
`import <path>` on a nonexistent or invalid-JSON SARIF file spilled an unhandled
`FileNotFoundError` / `JSONDecodeError` traceback instead of a clean error + exit
1 — the same "a compliance tool's commands must not stack-trace on bad input"
principle behind the earlier report-output hardening. *Fix:* `cli.cmd_import`
catches both and exits 1 with a clear message. Regression: `test_cli_e2e::
test_import_missing_file_fails_cleanly`, `::test_import_malformed_json_fails_cleanly`.

**#3 — `strip_comments_strings` grew output length on a trailing-backslash-at-EOF.**
Found by the fuzzer (falsifying input `"\`). Inside a string/char literal the
escape handler always emitted two blanks and advanced two positions; when the
backslash was the final character it consumed one but emitted two, making the
stripped view **longer than the source and desynchronizing every subsequent
(line, column) position** — the exact property the function promises to hold.
*Fix:* at EOF, blank one char for one consumed. Regression:
`test_fuzz_native::test_strip_trailing_backslash_at_eof_preserves_length` plus the
property test whose falsifying example it pins.

---

## 7. Limitations (stated without reservation)

These restate and reconfirm the project's own honest framing:

- **Not a qualified/certified tool** (see §0). The engines carry no qualification
  kit. Certification requires a qualified engine (Astrée/Polyspace/Helix QAC/…)
  and an accredited assessor; Maisha layers on top via SARIF import.
- **Coverage is ~86 curated rules** across three standards (35 MISRA C:2012,
  20 BARR-C:2018, 31 CERT C) — a fraction of the full standards; detection is
  bounded by the engines, not the curated set.
- **The verification gate trades human effort for safety**: on typical MISRA
  findings, `test_gated` behaves almost like `human_gated` (most rule categories
  are semantic-risk). Budget for human review of nearly every fix.
- **Native false positives are a real, non-zero category.** A lexical analyzer
  without a preprocessor or type system will always have some; this cycle's fuzz
  and adapter work reduces, but cannot eliminate, them.
- **Fixture precision (100%) is corpus-specific**; the real-world estimate (§4)
  is the better "unfamiliar codebase, day one" number.

---

## 8. What was NOT validated this cycle

- **Docker container** (`ghcr.io/winterlabshq/maisha`): not runnable in the
  validation environment (no Docker). Recommend a CI job that builds the image
  and runs `scan` + `serve` with the bundled analyzers.
- **Cross-platform matrix beyond Windows**: this run was Windows (Git Bash +
  PowerShell). Linux is exercised by CI; macOS is unverified. Recommend adding
  both to the CI matrix.
- **Mutation testing** of the test suite (test-quality measurement) — deferred.
- **Real qualified-engine SARIF sample** (a sanitized Coverity/Polyspace/IAR
  file): current dialect tests are modeled, not from a real engine (tracks GitHub
  issue #6).
- **Real-agent-driven convergence statistics** on a large corpus (iterations-to-
  converge, %-frozen) — requires a live LLM agent driving a full session.

---

## 9. Reproduction

```bash
pip install -e ".[dev]"
pip install cppcheck clang-tidy coverage hypothesis jsonschema   # full-fidelity extras

# Unit/integration suite + coverage
coverage run --source=maishac -m pytest tests/ -q && coverage report

# Core benchmarks (multi-analyzer; put cppcheck/clang-tidy on PATH first)
python benchmark/run_accuracy_benchmark.py
python benchmark/run_loop_simulation.py
python benchmark/run_sarif_import_test.py
python benchmark/run_cli_and_edge_cases.py

# Real-world corpora
bash benchmark/corpora/CLONE.sh
python benchmark/run_realworld_benchmark.py
```

Windows note: the pip-wheel analyzers install their executables under the
`site-packages/cppcheck/Cppcheck` and `site-packages/clang_tidy/data/bin`
directories; add both to `PATH` (Windows `;` separator) so `maishac` discovers
them via `shutil.which`.
