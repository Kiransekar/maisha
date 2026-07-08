# Maisha Agent Playbook

This is the recommended protocol for an LLM agent driving Maisha through MCP.
Paste it into your IDE's rules/system file (e.g. `CLAUDE.md`, `.cursorrules`) or
hand it to the agent at the start of a compliance task.

---

## The loop

```
begin_session ─► next_batch ─► edit code ─► record_attempt(s) ─► verify ─┐
                     ▲                                                    │
                     └──────────── while state == "active" ◄──────────────┘
```

### 1. Start

Call `compliance_begin_session(paths=["src/"])`. Note the `session_id` and the
baseline counts. Do **not** start editing before this — the baseline is what
verification diffs against.

### 2. Get a batch

Call `compliance_next_batch(session_id)`. Each finding briefing contains:

- `fingerprint` — the identity you must use in `record_attempt`
- `rule`, `summary`, `fix_hint` — what to do and why
- `failed_strategies` — approaches that already failed on this finding. **Never
  repeat one of these.**
- `notes` — project conventions from memory that apply here
- `cross_refs` — the same requirement in the other standards (fixing one often
  clears several)

Batches are file-grouped: make all edits to one file together, in one pass.

### 3. Fix

Rules of engagement:

- Make the **minimal compliant change**. Do not refactor beyond the finding.
- Preserve behavior. If a fix would change observable behavior, stop and record
  the attempt with strategy `"needs-behavioral-decision"` and move on.
- Regressions in the batch (marked `REGRESSED`) take priority over everything.
- If the finding is a false positive, call `compliance_suppress_finding` with a
  concrete reason — do not silently skip it.
- If the code is genuinely correct but non-compliant for a documented hardware
  or platform reason, call `compliance_add_deviation` with a real justification
  (≥ 15 chars enforced), a tight `scope` glob, and an approver. Deviations are
  audit records, not escape hatches.

### 4. Record

After editing, call `compliance_record_attempt(session_id, fingerprint,
strategy=...)` **for every finding you touched**, with a short strategy label
like `"replace strcpy with bounded strlcpy"` or `"add default case to switch"`.
Attempts are auto-graded at verify time; ungraded work is invisible to the loop
and will be re-briefed as if untried.

### 5. Verify

Call `compliance_verify(session_id)`. Read the diff:

- `resolved` — your graded successes.
- `regressed` — previously-resolved findings you broke. They lead the next batch.
- `new` — findings your edits introduced. Treat these as your own bugs.

Then check `state`:

| state | meaning | what you do |
|---|---|---|
| `active` | progress possible | go to step 2 |
| `converged` | no open findings above the floor | write the report, stop |
| `stalled` | two verifies with no progress | stop; summarize blockers for the human |
| `budget_exhausted` | `max_iterations` reached | stop; summarize remaining work |

Findings frozen as `needs_human` (regressed twice) must be listed in your final
summary — never keep retrying them.

### 6. Finish

On any terminal state, call `compliance_report(format="markdown")` and present
it, along with: findings you suppressed (and why), deviations you added, and
anything frozen for human review.

## Memory etiquette

- When you learn a project convention ("this codebase wraps malloc in
  `os_alloc`, approved under deviation D-3"), store it with `memory_note` and
  tag it with the rule id. Future sessions get it in their briefings.
- Before inventing a fix approach for a recurring rule, `memory_search` the rule
  id — a working strategy may already be recorded.

## Anti-patterns

- ❌ Editing before `begin_session` (corrupts the baseline diff).
- ❌ Fixing findings not in the current batch (defeats prioritization; do it via
  extra iterations instead).
- ❌ Repeating a strategy listed in `failed_strategies`.
- ❌ Broad deviations (`scope: "**"`) or vague justifications.
- ❌ Suppressing real findings to force convergence. `verify` diffs are
  persistent and auditable; the memory database remembers.
