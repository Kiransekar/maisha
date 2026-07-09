# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Maisha (package/CLI: `maishac`) is an agent harness for MISRA C:2012, BARR-C:2018
and CERT C compliance work on C codebases. It is explicitly **not** a linter and
**not** a certified static-analysis tool — it's a deterministic orchestration
layer (scanning, fingerprinting, memory, prioritization, verification gate)
that sits underneath an LLM agent, exposed both as a CLI and as an MCP server
so any agentic IDE can drive it. Read `README.md` for the full pitch and
`AGENT_PLAYBOOK.md` for the exact protocol an agent should follow when driving
a compliance session (begin → next_batch → fix → record_attempt → verify loop,
with stall/oscillation guards and a human/test verification gate).

## Commands

```bash
pip install -e ".[dev]"        # install with dev deps (pytest)
python -m pytest tests/ -q     # run the full test suite
python -m pytest tests/test_verification_gate.py -q   # run a single test file
python -m pytest tests/test_smoke.py::test_name -q     # run a single test

python tools/gen_coverage.py   # regenerate COVERAGE.md from the rule registry
```

CLI entry point (`maishac`, defined in `maishac/cli.py`):

```bash
maishac scan src/                 # one-shot scan, syncs memory
maishac findings --limit 20       # ranked open findings
maishac rule "MISRA 21.3"         # explain a rule + cross-standard refs
maishac session begin src/        # start an engineered fix session
maishac session batch <id>        # next prioritized batch (JSON briefings)
maishac session verify <id>       # rescan, diff, grade attempts, run test gate
maishac approve <fingerprint> --by lead@example.com
maishac deviate "MISRA 19.2" -s "drivers/**" -j "..." --approver lead@example.com --expires 2027-01-01
maishac suppress <fingerprint> -r "false positive: ..."
maishac note "..." -t <tag>
maishac report --format sarif > compliance.sarif
maishac import findings.sarif     # ingest an external qualified engine's SARIF
maishac serve                     # run the MCP server over stdio
```

`examples/bad.c` is a deliberately non-compliant fixture (~18 rules) — use it
as a manual test/demo target. Optional external analyzers (`cppcheck`,
`clang-tidy`) are auto-detected on `PATH`; the native analyzer always works
with zero dependencies, so tests must pass whether or not those tools are
installed.

## Architecture

```
maishac/model.py       Finding dataclass + stable fingerprinting (rule + file +
                        normalized line content + enclosing function — NOT line
                        number, so findings survive edits/refactors)
maishac/analyzers/     Analyzer protocol (base.py) + native.py (0-dep regex/AST-
                        lite checks), cppcheck.py, clang_tidy.py adapters.
                        __init__.py's run_scan() runs all available analyzers
                        and fingerprint-merges overlapping findings, recording
                        reinforcing evidence as e.g. "native+cppcheck".
maishac/rules/         RuleRegistry: loads the three JSON knowledge bases
                        (misra_c_2012.json, barr_c_2018.json, cert_c.json),
                        fuzzy-resolves rule ids ("21.3", "STR31-C", "barr 1.3a"),
                        and exposes the cross-standard equivalence graph.
maishac/memory/        SQLite store at <project>/.maishac/memory.db (WAL mode,
                        gitignored — it's local state, not source). Tracks
                        finding lifecycle (open/resolved/regressed), fix
                        attempts and their grading, MISRA-style deviations,
                        suppressions, free-form project notes, and sessions.
maishac/engine/        LoopEngine: the deterministic half of the fix loop —
                        session lifecycle, severity-floored/file-grouped
                        batching, the verification-gate state machine, iteration
                        budgets, stall detection, oscillation freezing
                        (a finding regressing twice becomes `needs_human`).
maishac/report.py       Compliance matrices, markdown report, SARIF 2.1.0
                        export/import (parse_sarif maps external tool ruleIds
                        onto the registry).
maishac/mcp_server.py   MCP tool surface (stdio) wrapping LoopEngine/MemoryStore
                        for agentic IDEs — same operations as the CLI.
maishac/cli.py          argparse CLI wrapping the same LoopEngine.
```

Key design invariants (see README's "Design principles" and the verification
gate section for the full rationale — don't relitigate these without reading
that first):

- **Findings are identities, not line numbers.** `compute_fingerprint()` in
  `model.py` is `sha1(rule + file + normalized_line + enclosing_function)`.
  Never key anything on raw line numbers.
- **A fix is never `resolved` on a clean rescan alone.** It passes through
  `pending_verification` and needs either a passing `test_command` or a human
  `approve_finding` call — see `_policy()` and `verify()` in `engine/__init__.py`
  and `semantic_risk()` in `memory/__init__.py`. Semantic-risk rules (casts,
  sign/comparison changes — `_RISK_RULES`/`_CAST_RE`) and high-severity findings
  *always* require human sign-off regardless of policy. Don't weaken this to
  make a test pass.
- **Imported (SARIF) findings are never cleared by a native rescan** — they're
  tracked with an empty `producers` set in `sync_scan`, distinct from
  natively-scanned findings.
- **The loop must terminate.** Every session state machine transition
  (`active` → `converged`/`stalled`/`budget_exhausted`/`awaiting_verification`)
  is driven by `engine/__init__.py::verify()`; if you touch it, preserve the
  guarantee that some terminal state is always reachable.
- Rule knowledge base text (`maishac/rules/*.json`) must stay original
  paraphrase, never reproduced standard text — see README's license section.
