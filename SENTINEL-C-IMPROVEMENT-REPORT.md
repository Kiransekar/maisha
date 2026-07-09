# Sentinel-C — Improvement Report & Action Backlog

**Audience:** This document is written for an AI coding agent (or human maintainer) working directly in the Sentinel-C codebase. Each issue below is self-contained: problem, why it matters, a concrete example, a fix recommendation, and acceptance criteria you can check your work against. Work top-to-bottom within each quadrant; quadrants are ordered by priority.

**How to use this backlog:** Issues are scored on two axes:
- **Severity** — how much damage this causes if left unfixed, given the project's safety-critical/embedded positioning.
- **Effort** — how much implementation work is required.

Fix in this order: **High Severity / Low Effort → High Severity / High Effort → Low Severity / Low Effort → Low Severity / High Effort.**

---

## Priority Matrix (quick reference)

| # | Issue | Severity | Effort | Quadrant |
|---|---|---|---|---|
| 1 | No human/test-based verification gate before `resolved` | Critical | Low | Q1 |
| 2 | Framing overclaims safety-critical readiness | High | Low | Q1 |
| 3 | Project naming collision (`Sentinel-C`) | Low | Low | Q1 |
| 4 | No license/version/CI hygiene on the project itself | Low | Low | Q1 |
| 5 | Verification loop only re-runs the same static analyzer ("the loop problem") | Critical | Medium-High | Q2 |
| 6 | Unqualified analysis engine for safety-critical claims | Critical | High | Q2 |
| 7 | No SARIF *import* / can't layer on top of qualified engines | High | Medium | Q2 |
| 8 | No published benchmarks (FP/FN rate, convergence stats) | Medium | Medium | Q2 |
| 9 | Thin rule coverage (~80 rules across 3 standards) | Medium | High | Q2 |
| 10 | SQLite memory concurrency / multi-user / CI merge story unaddressed | Medium | Medium | Q3/Q4 (see notes) |

---

## Q1 — High Severity, Low Effort (fix first)

### 1. No mandatory human/test-based gate before a finding is marked `resolved`
**Severity: Critical — Effort: Low**

**Problem:** `compliance_verify` currently marks a finding `resolved` purely by rescanning and checking whether its fingerprint disappeared. There is no requirement that the project's own test suite still passes, and no requirement for a human to approve the diff before the finding leaves the queue.

**Why it matters:** This is the root cause of "the loop problem" (see Q2 §5) — the only judge of a fix's correctness is the same analyzer whose blind spots created the finding. See the worked example in §5 for what this looks like in practice.

**Fix recommendation:**
- Add a `verification_policy` config with at least three levels: `analyzer_only` (current behavior, clearly labeled "not recommended for compliance work"), `test_gated` (require a configurable test/build command to exit 0 with no new test failures before `resolved` is set), `human_gated` (require an `approved_by` field to be set via a new `compliance_approve_finding` tool before `resolved` is set).
- Default to `test_gated` if a test command is configured, else `human_gated`.
- For severity ≥ `required` (MISRA) or CERT `L1`/high-priority findings, always require `human_gated` regardless of the project-wide default.
- Store `approved_by`, `approved_at`, and `verification_policy_used` per finding in the memory schema so the audit trail is inspectable later (this also strengthens the deviation-register story for real compliance work).

**Acceptance criteria:** A finding cannot transition to `resolved` state in the state machine without either (a) a passing test-command run recorded against that fix attempt, or (b) a non-null `approved_by`. Write a test that asserts a finding whose fix passes the analyzer rescan but has no test run or approval stays in a `pending_verification` state, not `resolved`.

---

### 2. Framing overclaims safety-critical readiness
**Severity: High — Effort: Low**

**Problem:** The project pitch ("protecting the physical assets and the lives that depend on that hardware") sits above the codebase's actual capabilities: an unqualified analyzer (§6), ~80 rules total (§9), and no built-in human gate (§1, pre-fix). The one honest caveat — "Sentinel-C output does not constitute a formal compliance certification" — is currently buried in the license section at the bottom of the README.

**Why it matters:** Users evaluating this for actual certification pipelines (DO-178C, ISO 26262, IEC 62304) may over-trust the tool based on framing, then discover the qualification gap only after building process around it. In a life-critical context, that's a trust and safety issue, not just a marketing nitpick.

**Fix recommendation:** Move the compliance-certification caveat to the top of the README, directly under the tagline. Add an explicit "What this is / What this is not" section: *is* a workflow orchestrator and audit-trail layer; *is not* a qualified/certified analysis tool and does not by itself satisfy tool-qualification requirements for DO-178C/ISO 26262/IEC 62304. Reframe "protecting lives" language to describe the goal the tool works toward rather than a guarantee it currently provides.

**Acceptance criteria:** The caveat appears before the first code block in README.md. A new `## Scope & Limitations` section exists and is linked from the top.

---

### 3. Project naming collision
**Severity: Low — Effort: Low**

**Problem:** "Sentinel-C" is already used by at least two unrelated public repos (a file-integrity monitor, and Alibaba's `sentinel-cpp` rate-limiting library), which hurts discoverability and search/SEO, and could cause confusion in issue trackers, package indexes, and MCP registries.

**Fix recommendation:** Rename before wider launch (e.g. something combining "compliance" + "loop"/"harness" that isn't already taken — check PyPI, GitHub, and the MCP registry namespace before settling). Update `pip install`, MCP server name, and CLI binary name (`sentinelc`) consistently.

**Acceptance criteria:** New name has zero exact-match collisions on GitHub, PyPI, and the MCP community registry.

---

### 4. No license file, version tag, or CI hygiene on the project itself
**Severity: Low — Effort: Low**

**Problem:** No `LICENSE` file is referenced, no version number is stated, and there's no indication of the project's own test/CI status (ironic for a compliance tool). This matters for adoption trust — teams evaluating a compliance tool will check whether the tool itself is well-maintained.

**Fix recommendation:** Add `LICENSE` (state which OSS license applies to Sentinel-C itself, separate from the "MISRA/BARR-C/CERT are property of their respective owners" disclaimer already present), add a `CHANGELOG.md`, tag a `v0.x` release, and add a CI badge showing `pytest tests/` passing.

**Acceptance criteria:** `LICENSE`, `CHANGELOG.md`, and a passing CI badge all present at repo root.

---

## Q2 — High Severity, Higher Effort (plan carefully)

### 5. The verification loop only checks "did the pattern disappear," not "did behavior change" — ("the loop problem")
**Severity: Critical — Effort: Medium-High**

**Problem:** The fix loop is: agent edits code → rescan with the same static analyzers → if the finding's fingerprint is gone, mark `resolved`. This means the loop's only success signal is *the analyzer stopped complaining*, which rewards the syntactically minimal edit — often exactly the edit most likely to silently change behavior at edge cases (sentinel values, saturation limits, error paths).

**Worked example:**

```c
int32_t threshold = get_configured_threshold(); /* -1 means "no limit configured" */
uint32_t sensor_val = read_sensor();

if (sensor_val > threshold) {          /* flagged: implicit signed->unsigned conversion */
    trigger_shutdown();
}
```

A static analyzer correctly flags the signed/unsigned comparison (MISRA Rule 10.x territory, CERT INT31-C). The fastest way for an agent to silence the rule:

```c
if (sensor_val > (uint32_t)threshold) {   /* warning gone, rescan passes */
    trigger_shutdown();
}
```

Rescan passes, fingerprint disappears, loop marks it `resolved`. But when `threshold == -1` (the sentinel for "no limit"), the cast produces `4294967295` — the "no limit configured" case now behaves as "an enormous limit," which may silently disable shutdown behavior exactly when no limit was configured. **No static rescan will ever catch this** — the rule only checks for the presence of an implicit conversion, never whether the specific fix preserves the sentinel's intended meaning. Only a test that exercises `threshold == -1`, or a human who recognizes the sentinel pattern, would catch it.

**Why it matters:** This is the single biggest risk in the whole design for the safety-critical use case the project targets. It's not a hypothetical edge case — sentinel values, saturation clamps, and boundary conditions are exactly the code embedded/safety-critical systems rely on most, and exactly the code a "does the warning still fire" check is blind to.

**Fix recommendation:**
- This item is largely satisfied by implementing §1 (test-gated / human-gated verification) — do not treat them as fully separate work items; §1 is the mechanism, this entry documents *why* §1 is non-negotiable rather than a nice-to-have.
- Additionally: have the briefing given to the agent for any finding touching a comparison, cast, or boundary condition explicitly prompt it to identify and preserve sentinel/special values, rather than relying on generic "fix this MISRA violation" instructions.
- Log a `semantic_risk` flag on findings whose fix involves a cast, comparison operator change, or removed/added conditional branch, and force `human_gated` verification (see §1) for any finding with that flag, regardless of project-wide policy.

**Acceptance criteria:** A regression test exists that reproduces the example above (a comparison fix that passes analyzer rescan but changes behavior for a sentinel value) and asserts the finding does NOT reach `resolved` under the new verification policy without a test run or approval.

---

### 6. Unqualified analysis engine underlying a safety-critical positioning
**Severity: Critical — Effort: High**

**Problem:** The engine stack is cppcheck (pattern-based) + clang-tidy `cert-*` checks + a native zero-dependency analyzer. None of these are qualified/certified tools. Certification frameworks (DO-178C, ISO 26262, IEC 62304) generally require the analysis tool itself to be qualified or "proven in use" — not just that it checks the right rule names.

**Why it matters:** Commercial competitors in this exact space (agentic MCP-based compliance remediation) lead with TÜV/SGS-certified engines specifically because of this requirement. Positioning Sentinel-C for propulsion/life-critical work while relying solely on cppcheck/clang-tidy creates a gap between the marketing claim and what a certification auditor will actually accept as evidence.

**Fix recommendation:** Don't attempt to build or certify a new analysis engine — that's out of scope for an OSS orchestration project. Instead, pursue §7 (SARIF import) so Sentinel-C can sit *on top of* an already-qualified engine (Astrée, Polyspace, Helix QAC, Parasoft C/C++test) when a project needs certification-grade evidence, while continuing to offer the free cppcheck/clang-tidy path for non-certification use (personal projects, hobbyist embedded work, pre-certification cleanup).

**Acceptance criteria:** Documentation clearly states which engine configuration is "certification-evidence-appropriate" (external qualified engine via SARIF import) versus "best-effort / pre-certification" (native + cppcheck + clang-tidy).

---

### 7. No SARIF import — can't layer on top of a qualified engine
**Severity: High — Effort: Medium**

**Problem:** Sentinel-C exports SARIF (for CI/reporting) but has no importer. Teams that already run a certified engine (Astrée, Helix QAC, Parasoft, IAR C-STAT — all of which can emit SARIF) currently cannot feed those findings into Sentinel-C's memory/loop/deviation-tracking layer; they're locked into Sentinel-C's own (unqualified) scan.

**Why it matters:** This is the single most valuable differentiator available to Sentinel-C given it can't out-qualify the commercial engines (§6). The loop engine, fingerprinting, memory, and deviation-register are genuinely useful independent of which engine produced the findings — but only if findings can come from any SARIF-emitting source.

**Fix recommendation:** Add a `sentinelc import --format sarif <file>` command that maps `partialFingerprints` (or computes Sentinel-C's own fingerprint scheme from the SARIF result's location + rule + message) into the existing memory schema, so imported findings get the same session/batch/verify/deviation treatment as natively-scanned ones.

**Acceptance criteria:** A SARIF file from at least one external tool (cppcheck's own SARIF output is a reasonable first test case) can be imported and immediately appears in `sentinelc findings`.

---

### 8. No published benchmarks or evaluation numbers
**Severity: Medium — Effort: Medium**

**Problem:** No false-positive/false-negative rates, no session convergence statistics, no measurement of how many iterations/batches a typical project needs to reach a `converged` state. The only demo fixture is `examples/bad.c`, a single deliberately-broken file exercising ~18 rules.

**Why it matters:** Anyone evaluating this against commercial tools (which publish or can demonstrate accuracy numbers) will ask for this, and "no data" reads as "untested at scale."

**Fix recommendation:** Run Sentinel-C against a handful of real or realistic mid-size open-source embedded C codebases (e.g. FreeRTOS kernel, a driver library). Publish: total findings by rule/severity, estimated false-positive rate (manually sampled and reviewed), average iterations-to-convergence, percentage of findings that reached `needs_human` (oscillation-frozen) vs. cleanly resolved.

**Acceptance criteria:** A `BENCHMARKS.md` exists with at least one non-trivial (>5k LOC) codebase run, methodology described, and raw numbers included.

---

### 9. Thin rule coverage (~80 rules across three standards)
**Severity: Medium — Effort: High**

**Problem:** MISRA C:2012 (with amendments) alone has 180+ rules/directives; CERT C has hundreds of guidelines. ~80 rules split across MISRA + BARR-C + CERT combined is a small fraction of either standard, especially if any *mandatory* MISRA rules are among the uncovered set.

**Why it matters:** Coverage completeness is the first thing a compliance-focused user checks. Silent gaps (a rule you don't know isn't covered) are worse than known gaps.

**Fix recommendation:** Do not silently claim "MISRA C:2012... CERT C compliance" — instead, publish an explicit coverage table (rule ID → covered/not covered → which analyzer backs it) so gaps are visible rather than discovered the hard way. Prioritize adding *mandatory* MISRA rules first, since those cannot be waived via deviation.

**Acceptance criteria:** A `COVERAGE.md` or equivalent lists every rule in each standard and its coverage status; mandatory MISRA rules are covered before advisory ones.

---

## Q3/Q4 — Lower Severity (address as time allows)

### 10. SQLite memory concurrency / multi-user / CI story
**Severity: Medium — Effort: Medium**

**Problem:** `.sentinelc/memory.db` is a per-project SQLite file. Behavior under concurrent sessions (two developers running sessions locally, or a CI job and a local session both writing) is undocumented. SQLite's file-level locking will cause writer contention or, if the file is naively committed to version control, merge conflicts on a binary file.

**Why it matters:** Lower severity than the above because it's a workflow/tooling annoyance rather than a correctness or safety risk — but it will surface quickly in any team (not solo-hobbyist) adoption.

**Fix recommendation:** Document that `.sentinelc/memory.db` should be gitignored (or provide an export/import path so state can be shared deliberately rather than via raw file diffs). Consider WAL mode for SQLite to reduce lock contention, and a `sentinelc session lock` mechanism to prevent two concurrent sessions on the same project path.

**Acceptance criteria:** README documents the recommended `.gitignore` entry and concurrency behavior; a lock file prevents two simultaneous `session begin` calls on the same project path.

---

## References

Context gathered while researching the competitive landscape and standards background for this review (July 2026):

- Perforce — AI-assisted code remediation via MCP connecting to Helix QAC for MISRA/CERT findings: https://www.perforce.com/blog/sca/ai-remediation-mcp-server
- Perforce — MISRA Compliance:2020 and the role of static analysis tooling in MISRA compliance: https://www.perforce.com/blog/qac/misra-compliance-static-analysis
- Axivion — MCP-connected static analysis (MISRA C:2025/C++:2023, AUTOSAR, CERT, CWE), TÜV/SGS certification for ASIL D / SIL 4 / IEC 62304 Class C: https://www.qt.io/quality-assurance/axivion-static-code-analysis
- Parasoft — AI agents and MCP server for C/C++test, ~4,000 checkers, MISRA/AUTOSAR/CERT/CWE: https://www.parasoft.com/blog/ai-agents-mcp-servers-software-quality/ and https://www.parasoft.com/products/parasoft-c-ctest/c-c-static-analysis/
- QA Systems — QA-MISRA, 900+ checks, TÜV certification kit for tool qualification: https://www.qa-systems.com/tools/qa-misra/
- IAR Systems — C-STAT, MISRA C/C++, CERT C/C++, CWE, SARIF export, TÜV SÜD-certified editions: https://www.iar.com/embedded-development-tools/iar-c-stat
- analysis-tools-dev curated static analysis list (Astrée, clang-tidy, and other engines referenced above): https://github.com/analysis-tools-dev/static-analysis
- cppcheck (open source engine referenced in Sentinel-C's own stack): https://github.com/cppcheck-opensource/cppcheck
- Model Context Protocol servers reference repository: https://github.com/modelcontextprotocol/servers

---

## Summary for the agent

If you can only do one thing from this document: **implement §1 (verification gate) before anything else.** It is low effort, critical severity, and it is also the concrete fix for §5 (the loop problem) — they are the same piece of work described from two angles. Everything else in Q1 is cheap trust/hygiene fixes. Q2 items are real engineering investments (SARIF import in particular is the highest-leverage one, since it lets the project coexist with qualified engines instead of competing with them on engine quality it cannot win). Q3/Q4 items are safe to defer.
