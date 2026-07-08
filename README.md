# Sentinel-C

**An agent harness for MISRA C:2012, BARR-C:2018 and CERT C compliance — usable from any agentic IDE.**

Sentinel-C is not another linter. It is the *deterministic half* of an autonomous
compliance workflow. Your IDE's LLM (Claude Code, Cursor, Windsurf, Zed, anything
that speaks [MCP](https://modelcontextprotocol.io)) does the code edits; Sentinel-C
does everything that must never hallucinate:

- **Scanning & evidence merging** — a zero-dependency native analyzer plus adapters
  for `cppcheck` (with its MISRA addon) and `clang-tidy` (`cert-*` checks). Findings
  from multiple analyzers that hit the same defect are fingerprint-merged into a
  single finding with reinforcing evidence (`analyzer: native+cppcheck`).
- **Stable fingerprints** — findings are identified by
  `sha1(rule + file + normalized line content + enclosing function)`, *not* line
  numbers, so they survive edits, insertions and refactors across sessions.
- **Persistent memory** — a SQLite store per project (`.sentinelc/memory.db`)
  tracking finding lifecycle (open → resolved → regressed), every fix attempt and
  its outcome, false-positive suppressions, MISRA-style deviation records with
  justification/approver/expiry, and free-form project convention notes.
- **An engineered fix loop** — sessions with severity-ranked, file-grouped batches;
  regressions always jump the queue; each finding is briefed with the rule summary,
  a fix hint, strategies that *already failed* on it, relevant memory notes and
  cross-standard equivalents. Guard rails: iteration budgets, stall detection, and
  oscillation freezing (a finding that regresses twice is frozen as `needs_human`).
- **Reporting** — per-standard compliance matrices, a markdown report with a
  deviation register, and SARIF 2.1.0 export with `partialFingerprints` for CI.

The three rule knowledge bases (~80 rules) contain **original paraphrased
summaries** written for this project — no standard text is reproduced. For
authoritative wording you still need the official MISRA / BARR / SEI CERT documents.

---

## Install

Requires Python 3.10+.

```bash
pip install ./sentinel-c          # or: pip install -e ./sentinel-c for development
```

Optional but strongly recommended external analyzers:

```bash
# Debian/Ubuntu
apt install cppcheck clang-tidy

# or, without root (prebuilt wheels)
pip install cppcheck clang-tidy
```

Sentinel-C degrades gracefully: any analyzer not on `PATH` is skipped and the
native analyzer always works.

## Quickstart (CLI)

```bash
cd your-firmware-project

sentinelc scan src/                  # one-shot scan, syncs memory
sentinelc findings --limit 20        # ranked open findings
sentinelc rule "MISRA 21.3"          # explain a rule + cross-standard refs

# The engineered loop (what an agent drives via MCP):
sentinelc session begin src/
sentinelc session batch              # next prioritized batch with briefings
# ...edit code (you or your agent)...
sentinelc session verify             # rescan, diff, grade attempts
sentinelc session status

sentinelc deviate "MISRA 19.2" --scope "drivers/**" \
    --justification "Union required for hardware register overlay mapping" \
    --approver lead@example.com --expires 2027-01-01
sentinelc suppress <fingerprint> --reason "false positive: macro expansion"
sentinelc note "This codebase uses FreeRTOS; heap_4 allocator is approved" --tags misra-21.3
sentinelc report --format sarif > compliance.sarif
```

## Quickstart (any agentic IDE, via MCP)

Add the server to your IDE's MCP configuration (ready-made snippets in
[`integrations/`](integrations/)):

```json
{
  "mcpServers": {
    "sentinel-c": {
      "command": "sentinelc",
      "args": ["serve"],
      "env": { "SENTINELC_PROJECT": "/path/to/your/project" }
    }
  }
}
```

Then tell your agent something like:

> Begin a Sentinel-C compliance session on `src/`, work through batches until
> converged, record every attempt, and add deviations only where a fix is
> genuinely impossible.

The recommended agent protocol is documented in
[`AGENT_PLAYBOOK.md`](AGENT_PLAYBOOK.md).

## MCP tools

| Tool | Purpose |
|---|---|
| `compliance_scan` | Scan paths, merge analyzers, sync memory, return diff (new/persisting/resolved/regressed) |
| `compliance_list_findings` | Ranked open findings above a severity floor |
| `compliance_get_finding` | Full briefing for one fingerprint (history, failed strategies, notes) |
| `compliance_explain_rule` | Rule summary, severity, fix hint, cross-standard equivalents |
| `compliance_search_rules` | Keyword search across all three standards |
| `compliance_begin_session` | Baseline scan + session with budgets (`max_iterations`, `batch_size`) |
| `compliance_next_batch` | Next prioritized batch, regressions first, with per-finding briefings |
| `compliance_record_attempt` | Log the strategy used on a finding (auto-graded on verify) |
| `compliance_verify` | Rescan, diff, grade attempts, advance state machine |
| `compliance_session_status` | Progress, iteration budget, state (`active`/`converged`/`stalled`/`budget_exhausted`) |
| `compliance_add_deviation` | MISRA-style deviation record (justification ≥ 15 chars enforced) |
| `compliance_suppress_finding` | Mark a fingerprint as false positive (reason required) |
| `memory_note` / `memory_search` / `memory_stats` | Project convention memory |
| `compliance_report` | Markdown, JSON or SARIF 2.1.0 |

## Architecture

```
┌──────────────────────────── your agentic IDE ───────────────────────────┐
│  LLM agent: reads briefings, edits code, records attempts               │
└──────────────▲──────────────────────────────────────────────────────────┘
               │ MCP (stdio)
┌──────────────┴──────────────  sentinel-c  ──────────────────────────────┐
│ engine/    LoopEngine: sessions, batching, budgets, stall/oscillation   │
│ memory/    SQLite: findings, fix_attempts, deviations, suppressions,    │
│            notes, sessions  (.sentinelc/memory.db)                      │
│ analyzers/ native (0-dep) + cppcheck(+MISRA addon) + clang-tidy(cert-*) │
│            → fingerprint-deduped, severity-sorted evidence               │
│ rules/     MISRA C:2012 + BARR-C:2018 + CERT C KBs, fuzzy resolver,     │
│            cross-standard references                                     │
│ report.py  compliance matrix, markdown, SARIF 2.1.0                     │
└──────────────────────────────────────────────────────────────────────────┘
```

Design principles:

1. **Determinism where it matters.** Prioritization, verification, memory and
   budgets are code, not prompts. The LLM only does what LLMs are good at.
2. **Findings are identities, not line numbers.** Fingerprints keep history
   attached to the defect through refactors.
3. **The loop must terminate.** Iteration budgets, stall limits and oscillation
   freezing guarantee a session always ends in a well-defined state.
4. **Compliance is a process, not a scan.** Deviations and suppressions are
   first-class, auditable records — exactly as MISRA compliance expects.

## Development

```bash
pip install -e . && python -m pytest tests/ -q
```

`examples/bad.c` is a deliberately non-compliant fixture exercising ~18 rules —
useful as a demo target.

## License / disclaimer

Rule summaries are original paraphrases; MISRA®, BARR-C and SEI CERT C are the
property of their respective owners. Sentinel-C output does not constitute a
formal compliance certification.
