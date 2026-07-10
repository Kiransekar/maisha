# Changelog

All notable changes to Maisha are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **Author-time compliant-pattern library (Mode 1)** — a curated set of
  recurring embedded-C authoring concerns (`maishac/patterns.py`: dynamic
  memory, fixed-width types, recursion, checked returns, string buffers,
  string→number, control-flow braces, switch default, boolean/assignment
  conditions, null checks, integer conversion/overflow, format strings, bounded
  loops, goto), each cross-linked to the MISRA/CERT/BARR-C rules it satisfies.
  Exposed proactively via `compliance_guidance` (MCP) / `maishac guide "<topic>"`
  (CLI) — get the idiom to *prefer*, the anti-pattern to *avoid*, and *why*,
  before writing code — and attached to `check_snippet` findings so the reactive
  path also shows the compliant idiom to swap in. New `AUTHORING_PLAYBOOK.md`
  documents the guidance → draft → check → rewrite loop for an IDE agent.
- **Proactive authoring aid** — `compliance_check_snippet` MCP tool and
  `maishac check <file|->` CLI lint a draft C snippet *in memory, before it is
  written to a file*, returning violations + fix hints so an agent writes the
  compliant version on the first pass instead of fixing it on a later scan.
  Nothing is scanned or stored; native lexical checks only (the syntactic
  subset, not whole-program rules). This is the first *proactive* surface —
  the rest of the harness is reactive (scan → fix → verify).
- **Bring-your-own-triage on SARIF import** — `import_sarif` now honors
  `result.suppressions` (SARIF 2.1.0 §3.27.23): a finding a qualified engine
  already marked suppressed/baselined is imported as *suppressed* with its
  justification preserved, instead of resurfacing as a fresh open violation. A
  `rejected` suppression does not suppress. Import result reports
  `suppressions_carried`.
- **MISRA Compliance:2020 Guideline Compliance Summary** — a new report format
  (`maishac report --format misra-compliance`, plus the MCP `compliance_report`
  tool) that produces the artifact a functional-safety assessor actually asks
  for: every enforced guideline classified Compliant / Deviations / Pending /
  Violations, tied to deviation permits (scope, justification, approver,
  expiry), with the legality checks the framework mandates (a Mandatory
  guideline may not be deviated → flagged audit-blocking) and honest disclosure
  of how many guidelines are enforced vs. *not checked* by this configuration.
  Layer a qualified engine's findings via `maishac import` first for the
  guidelines Maisha doesn't check natively.
- `maishac deviate --expires YYYY-MM-DD` — record a deviation permit's expiry as
  an absolute date (what an auditor thinks in), alongside the existing
  `--expires-days`.

### Fixed
- Recording a deviation now retroactively re-buckets already-open findings that
  fall under the permit's scope to `deviated`, so a compliance report reflects
  the permit immediately instead of only after the next rescan (previously an
  approved, on-record deviation could still show as an open violation).

## [0.2.0] - 2026-07-10

### Added
- **Richer SARIF field mapping.** SARIF import/export is no longer lossy:
  - Import parses a qualified engine's `codeFlows` → `threadFlows` →
    `locations` into an ordered data-flow path (new `findings.code_flow`
    column + migration) and surfaces it in the agent fix briefing, so a fixer
    sees *how* a defect flows, not just where it lands.
  - Export emits cross-standard equivalences as SARIF
    `reportingDescriptor.relationships` (e.g. a MISRA rule linked to its CERT
    equivalent), with every relationship target added as a descriptor so it
    resolves.
  - `startColumn` and imported `codeFlows` now survive an import → export
    round-trip, alongside the existing `maishac/v1` `partialFingerprints`
    identity. Benchmarked end-to-end (`run_sarif_import_test.py`, 8/8 checks;
    see `BENCHMARK-SUITE-REPORT.md` §4).
- **Full benchmark suite** (`benchmark/`, see `BENCHMARK-SUITE-REPORT.md`) —
  7 hand-annotated synthetic fixtures (100% seeded-defect recall, 100%
  precision after fixes), a real multi-analyzer install (cppcheck +
  clang-tidy, not native-only), an end-to-end fix-loop simulation against a
  synthetic firmware module exercising the verification gate, oscillation
  freezing, stall detection and budget exhaustion, a SARIF-import validation
  against a synthetic external-engine file, CLI-as-subprocess end-to-end
  tests, edge cases, and a performance stress test. Found and fixed 4 real
  bugs (see below). README's verification-gate section now sets explicit
  expectations about how often `test_gated` actually auto-resolves fixes in
  practice (answer: rarely, for typical MISRA rule categories).

### Fixed
- **Four bugs found by the full benchmark suite (`benchmark/`, see
  BENCHMARK-SUITE-REPORT.md).**
  - `clang-tidy`'s diagnostic-parsing regex assumed Unix-style paths; a
    Windows drive-letter colon (`D:\...`) broke the `file:line:col:` split,
    silently dropping nearly every clang-tidy finding on Windows. Fixed in
    `analyzers/clang_tidy.py` (`_DIAG` now uses a non-greedy file group).
  - The native analyzer's MISRA 17.2 (recursion) check looped over every
    function name seen so far in the file, for every line — O(functions x
    lines). A 2000-function/12k-line synthetic file took 374s to scan; now
    tracks only the current enclosing function via a brace-depth stack and
    scans the same file in ~0.4s (native.py).
  - `maishac report --format markdown` crashed with `UnicodeEncodeError` on
    a default Windows console (cp1252 can't encode the checkmark/cross/party
    emoji the standards-matrix table used). Replaced with plain ASCII
    (report.py); the CLI also now hardens stdout/stderr with
    `errors="replace"` so no single unprintable character can crash any
    command's output again.
  - The native MISRA 18.8 (possible VLA) check misidentified a fixed array
    sized by an `ALL_CAPS` macro constant (e.g. `uint8_t buf[BUF_SIZE];`) as
    a variable-length array — confirmed on two independent fixtures. Now
    skips `ALL_CAPS` size identifiers (the near-universal macro-constant
    convention) while still catching genuine runtime-sized arrays
    (native.py).
- **The three bugs the FreeRTOS benchmark run surfaced (§8 follow-up).**
  - `maishac scan`/`session begin` now accept `--include`/`-I` (repeatable;
    MCP: `include_paths`), forwarded as `-I<path>` to cppcheck and clang-tidy.
    Previously there was no way to give either analyzer the project's own
    header search path, which was the root cause of 94 of the 132 confirmed
    false positives in the FreeRTOS run (missing-declaration/undefined-macro
    noise and clang-tidy never parsing a file at all).
  - `enclosing_function()` (`model.py`) is now brace-nesting-aware: it walks
    upward tracking block depth so it finds the function that actually
    encloses a line, skipping over control-flow blocks (if/for/while/switch)
    instead of matching the first line anywhere above that merely looks like
    a header. It also reconstructs signatures split across multiple lines
    (common with long parameter lists). This fixes the MISRA 17.2 (recursion)
    false positive where a call from inside a function with a multi-line
    signature was mis-attributed to an unrelated earlier function of the same
    name as the callee.
  - The native MISRA 15.6 (braceless control-statement body) check no longer
    mistakes a `#if`/`#else`/`#endif` sitting between a control header and its
    body for a missing brace — it now looks past preprocessor/blank lines to
    the real next line before judging. All 16 FreeRTOS hits for this rule
    were this exact pattern.
  - Regression tests for all three: `tests/test_benchmark_fixes.py`.

### Added
- **Benchmark run (§8).** `BENCHMARKS.md` — Maisha scanned the FreeRTOS kernel
  (16,914 LOC, 7 core files), 1,757 findings, with a manually-verified
  false-positive analysis (≈82% FP among substantive findings, dominated by
  missing include-path configuration) and the three tool bugs the run surfaced.
- **Rule coverage table (§9).** `COVERAGE.md`, generated by
  `tools/gen_coverage.py` from the rule knowledge base and the analyzers' rule
  maps, lists every covered rule per standard, its MISRA category, and which
  analyzer (native / cppcheck / clang-tidy) backs it. A test fails if the doc
  drifts from the code. Honestly framed as a curated subset, so gaps are
  explicit rather than discovered later.
- **Concurrency (§10).** SQLite runs in WAL mode with a busy-timeout so a CI
  scan and a local session don't hard-block; `session begin` refuses a second
  active session on a project (`--force` to override); README documents
  gitignoring `.maishac/memory.db`.
- **SARIF import.** `maishac import findings.sarif` (and MCP
  `compliance_import_sarif`) ingests any SARIF 2.1.0 engine's findings — a
  qualified engine (Helix QAC, Polyspace, Parasoft, IAR C-STAT) or cppcheck's
  own `--output-format=sarif` — into the same loop/memory/gate. Recognized
  MISRA/CERT ruleIds map onto the knowledge base; others are kept as
  `sarif:<ruleId>`. Imported findings are scoped by producer so a native rescan
  never silently clears them.
- **Verification gate.** A fix is no longer marked `resolved` just because the
  analyzer stopped flagging it. Findings enter `pending_verification` and leave
  only via a session `verification_policy`: `analyzer_only`, `test_gated` (a
  `test_command` must exit 0), or `human_gated` (`approve_finding`). Default:
  `test_gated` if a test command is set, else `human_gated`.
- Semantic-risk detection (casts, comparisons, sign conversions, control-flow
  rules) and high-severity findings always require human approval, even on a
  passing test suite.
- Audit fields per finding: `verification_method`, `approved_by`, `approved_at`,
  `analyzer_cleared_at`, `semantic_risk`; SQLite schema migrated in place.
- New session state `awaiting_verification`; compliance report gained a
  `Pending` column so gated findings stay visible.
- CLI: `maishac approve <fp> --by NAME`; `session begin --verification-policy`
  and `--test-command`. MCP: `compliance_approve_finding` plus policy arguments
  on `compliance_begin_session`.
- `README` install path for cppcheck/clang-tidy via pip wheels (no root needed).
- Graceful error when the `mcp` package is missing on `maishac serve`.
- `LICENSE` (MIT) and this changelog.

### Fixed
- Removed a stray directory left by a botched brace-expansion `mkdir`.

## [0.1.0]

### Added
- Initial release: native + cppcheck (MISRA addon) + clang-tidy (`cert-*`)
  analyzers, fingerprint-merged findings, SQLite project memory, the engineered
  fix loop with budgets/stall/oscillation guards, deviation/suppression records,
  and Markdown/JSON/SARIF reporting. MCP server for agentic IDEs.
