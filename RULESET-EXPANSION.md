# Rule Set Expansion — Research & Plan

Status: **proposal, not yet implemented.** Research conducted 2026-07-18 against
primary sources (MISRA Amendment PDFs, SEI CERT site, BARR-C:2018 PDF, cppcheck
`addons/misra.py`, clang-tidy check lists).

---

## 1. Where we actually stand

| KB | Ships | Full standard | Coverage |
|---|---:|---:|---:|
| MISRA C:2012 | 35 | 143 rules + 16 directives (**223 guidelines** as MISRA C:2023) | ~22% of base |
| CERT C | 31 | **122 rules** (+ recommendations, not normative) | 25% |
| BARR-C:2018 | 20 | **143 rules** | 14% |

The native analyzer detects 28 of the 86 with zero dependencies. The rest are
mapped to cppcheck / clang-tidy.

---

## 2. The ceiling: what a lexical analyzer can honestly implement

MISRA classifies every rule **Decidable/Undecidable** and **Single-TU/System**.
This is the single most important constraint on expansion — it tells us what
`native.py` can ever claim.

Base MISRA C:2012 splits **117 Decidable / 26 Undecidable** and
**104 Single-TU / 39 System**. All 26 Undecidable rules are System, leaving
exactly 13 Decidable-but-System rules (2.3, 2.4, 2.5, 5.1, 5.6–5.9, 8.3–8.7).
That arithmetic closes exactly, which is a good consistency check.

**So the implementable universe for a single-file analyzer is ~104 base rules**
(Decidable + Single-TU), plus most AMD3/AMD4 additions, which are heavily D/STU.

Permanently out of reach without real dataflow — do **not** promise these,
carry them as KB-only entries mapped to external engines:

> 1.2, 1.3, 2.1, 2.2, 8.13, 9.1, 12.2, 13.1, 13.2, 13.5, 14.1, 14.2, 14.3,
> 17.2, 17.5, 18.1, 18.2, 18.3, 18.6, 19.1, 22.1–22.6

Note "Decidable + Single-TU" is an *upper bound on eligibility*, not a promise
of a cheap regex. Rule 10.x (essential type model) is D/STU but needs a real
type model. Realistically the lexically-cheap subset is §3, §4, §7, §15, §16,
§20, §21 — see Phase 2.

> **Errata caught:** HCL's widely-mirrored table marks Rule 17.8 Undecidable.
> MISRA Appendix B classifies it **Decidable/Single-TU** (it's purely
> syntactic), and HCL's count yields 27 undecidables against MISRA's stated 26 —
> which pins the error on 17.8. Treat 17.8 as A/D/STU; it's implementable.

---

## 3. Blockers to fix *before* adding rules

These are ordered first because expansion makes each one worse.

### 3.1 `gen_coverage.py` makes two blanket claims (honesty bug)

```python
# tools/gen_coverage.py:51-56
if std == "MISRA-C:2012" and rid.startswith("MISRA-C:2012 Rule "):
    out.append("cppcheck")     # claims the addon implements EVERY MISRA Rule
if std == "CERT-C":
    out.append("clang-tidy")   # claims cert-* covers EVERY CERT rule
```

- **clang-tidy**: ships 22 `cert-*` checks, of which only ~18 map to CERT
  *Rules* (4 map to Recommendations). We assert coverage on all 31.
- **cppcheck**: currently ~accurate (154/156 implemented; missing 1.1, 3.2,
  12.5) — but *only for MISRA C:2012+AMD1+AMD2*. The free addon implements
  **none** of AMD3/AMD4. The moment Phase 1 adds mandatory rules like 7.5 or
  21.22, this claim becomes false.

**Fix:** replace both blankets with explicit per-rule maps
(`CLANG_TIDY_CERT_CHECKS`, `CPPCHECK_MISRA_IMPLEMENTED`), derived from the
tools' published check lists. This is a prerequisite, not a nice-to-have —
`COVERAGE.md`'s entire stated purpose is "no silent *we cover MISRA* claim."

### 3.2 Mandatory guidelines can be deviated (compliance bug, currently dormant)

MISRA Compliance:2020 is unambiguous: **Mandatory guidelines admit no
deviations.** Our `recategorize()` correctly locks this
(`engine/__init__.py:185`, `"mandatory": set()`), but
`memory.add_deviation()` has **no category check** — a mandatory finding could
be waived via `maishac deviate`.

This is dormant today *only because the KB contains zero mandatory rules*
(all 35 MISRA entries are required/advisory). `report.py:440`'s
`is_blocking = cat == "mandatory"` is likewise dead code. Phase 1 activates
both — so the guard must land in the same change.

### 3.3 The one-pattern-per-rule invariant will not survive expansion

`tests/test_patterns.py:16` requires **every** KB rule to be covered by an
authoring pattern in `patterns.py`. Good gate at 86 rules; unworkable at 400+.

Patterns are already many-to-one (the integer-conversion pattern covers 4
rules), so the answer is coarsening plus a tier split:

- **Tier A — enforced rules** (something can detect them): keep the strict
  1:1-or-better pattern requirement.
- **Tier B — reference rules** (KB-only, for cross-referencing, GEP rows and
  SARIF import mapping): require `summary` + `fix` but not a pattern.

Add a `tier` field to the JSON schema and relax the test to Tier A. Without
this, Phases 2–4 are gated on writing hundreds of idioms.

### 3.4 Schema gaps

Add to the rule JSON schema before bulk-loading data:

- `category` on CERT and BARR-C entries (currently MISRA-only).
- `decidable` (bool) and `scope` (`stu`|`system`) on MISRA entries — this is
  what lets `COVERAGE.md` explain *why* a rule isn't natively detected, instead
  of a bare "not detected".
- `lifecycle` (`active`|`disapplied`|`deleted`) — MISRA C:2025 introduces
  disapplied and deleted rules (15.5 is now **disapplied**), and deleted rule
  numbers are never reused. A boolean won't model this.
- CERT `priority` / `level` (L1–L3) — already published, useful for ranking.

Good news: `RuleRegistry._canonical` and its resolver regexes are
number-agnostic, so new sections (**Dir 5.x** concurrency, **Rule §23** generic
selections) load without registry changes.

---

## 4. Phased plan

### Phase 0 — Make current claims true
Fix 3.1 (per-rule analyzer maps) and 3.4 (schema fields). Regenerate
`COVERAGE.md`. No new rules. Net effect: coverage numbers go *down* and get
honest.

### Phase 1 — The Mandatory set (highest value per rule)
MISRA's mandatory guidelines are the only category that can never be waived,
and we currently model none of them.

Full mandatory set (16 rules): 7.5, 9.1, 9.7, 12.5, 13.6, 17.3, 17.4, 17.6,
17.9, 18.10, 19.1, 21.13, 21.17–21.20, 21.22, 22.2, 22.4–22.6, 22.12, 22.14,
22.20.

Of these, **8 are Decidable + Single-TU and genuinely implementable natively**:

| Rule | Detection sketch |
|---|---|
| 12.5 | `sizeof` applied to an array-typed parameter — syntactic |
| 13.6 | side effects inside a `sizeof` operand — syntactic |
| 17.3 | call with no visible prototype — needs a declaration table per file |
| 17.4 | non-void function with a fall-off-end path — brace/return tracking |
| 17.6 | `static`/qualifiers inside array-parameter brackets — regex |
| 7.5 | malformed integer-constant-macro arguments — regex |
| 18.10 | pointer to variably-modified array type — regex |
| 21.22 | `<tgmath.h>` type-generic macro argument types — partial |

Ship all 16 in the KB; implement detectors for the tractable subset; carry the
rest as Tier B mapped to external engines. **Must land with the mandatory
deviation guard from 3.2.**

### Phase 2 — MISRA required, lexically cheap
Highest yield-per-effort, in order:

1. **§20 preprocessor (14 rules, all D/STU, all lexical)** — the single juiciest
   block in the standard for a text-based analyzer. 20.1–20.14.
2. **§16 switch (7 rules)** — we already track switch state for 16.4; 16.2,
   16.3, 16.5, 16.6, 16.7 are incremental on existing machinery.
3. **§15 control flow** — 15.2, 15.3, 15.4, 15.7 join the existing 15.1/15.6.
4. **§21 library bans** — 21.1, 21.2, 21.21, 21.24 extend `BANNED_CALLS`, which
   is a dictionary entry each.
5. **§7 literals** (7.2, 7.4), **§2** (2.6, 2.7), **§3** (3.1, 3.2), **§4.1**,
   **§11.9**, **§12.3**, **§18.4, 18.5, 18.7**, **§17.1, 17.8**.

Explicitly deferred: §10 essential types and §11 pointer conversions — D/STU but
they need a type model, so they stay Tier B mapped to cppcheck.

### Phase 3 — CERT C to full rule coverage (31 → 122)
Bulk KB load. Add the missing 91 rules with section, priority/level, and the
Detectable/Repairable columns. Wire the accurate clang-tidy check map from
Phase 0.

Two live issues to encode:
- The SEI wiki **migrated**: `wiki.sei.cmu.edu/confluence/display/c/...` now
  301-redirects to `cmu-sei.github.io/secure-coding-standards/`. Any stored URLs
  need updating.
- cppcheck **deleted its CERT addon** in 2022 (moved to Cppcheck Premium). Our
  `CPPCHECK_TO_CERT` never depended on it — it maps cppcheck's *native* error
  IDs onto CERT rules — so we're unaffected and arguably more robust than the
  thing that was removed. Worth stating in `COVERAGE.md`.

### Phase 4 — BARR-C to full coverage (20 → 143)
Load all 143 with chapter structure. Encode the **Bagnara/Barr/Hill mapping**
(arXiv:2003.06893, co-authored by Michael Barr) as cross-references: 47 of the
64 language-subsetting rules have MISRA counterparts across exact/non-exact/
related tiers; 17 have none. The other 79 rules are stylistic with no MISRA
counterpart by construction.

Encode honestly: because that category-D set is non-empty, **BARR-C:2018 does
not fully achieve its stated "never more restrictive than MISRA" goal**. If our
docs imply MISRA ⊆ BARR-C, that needs qualifying.

Parsing trap: rules 1.8.b, 1.8.c, 2.1.c, 4.2.c, 5.4.b, 6.3.b contain roman
sub-items that are *not* separate rules. A naive letter-regex yields 146, not
143.

### Phase 5 — Optional: user-supplied rule texts
Adopt cppcheck's `--rule-texts` pattern: users who own MISRA can inject official
text locally; we ship numbers, categories and our own paraphrases only. This is
the mechanism MISRA has tolerated from cppcheck for years, and it lets a
licensed user get normative wording without us distributing it.

---

## 5. Licensing posture — one change recommended

| Standard | License | Verbatim text? |
|---|---|---|
| MISRA C:2012 | Proprietary, single-user PDF | **No** — paraphrase only |
| BARR-C:2018 | Free download, all rights reserved; **derivatives restricted to private use** | **No** — paraphrase *independently* |
| SEI CERT C | **CC BY 4.0** (examples MIT) | **Yes**, with attribution |

Two findings:

1. **Our blanket paraphrase-only rule is stricter than necessary for CERT C.**
   CERT is CC BY 4.0 — reproduction and adaptation are permitted with credit to
   Carnegie Mellon University / SEI, a license link, and a changes notice. No
   share-alike, so it cannot infect Maisha's MIT license. Recommend scoping the
   CLAUDE.md invariant explicitly to MISRA and BARR-C rather than stating it
   globally over `maishac/rules/*.json`.
   *Caveat:* the CC BY statement is sourced from a third-party vendored copy
   (github/codeql-coding-standards); the new SEI site renders only a bare
   copyright footer. **Confirm with SEI before relying on it.** Avoid implying
   CMU/SEI endorsement — CERT® is a registered trademark.

2. **BARR-C is stricter than assumed and needs a review of existing content.**
   Its Document License restricts *derivative works* to private/internal use —
   which reaches beyond verbatim copying. Our 20 existing BARR-C summaries
   should get an independence pass before we add 123 more. The sanctioned path
   is attribution-by-name: Barr explicitly *requests* that tools detecting
   violations refer to the standard as "BARR-C:2018".

MISRA's own position is settled by precedent: cppcheck ships rule numbers,
categories and full checker logic under GPL-3.0 while shipping **zero** rule
text, stating in `misra.py`'s header that it is "not allowed by MISRA to
distribute rule texts openly." Numbers, categories and decidability are facts;
only the expression is protected. Our approach matches.

---

## 6. Validation requirement for every new detector

Non-negotiable, and we already have the harness for it: `benchmark/corpora/`
carries littlefs, lwip, mbedtls and zephyr-kernel, with `ground_truth.json` and
`run_accuracy_benchmark.py`.

Every new native check must report its false-positive rate against all four
before merge. The existing checks carry scar tissue from exactly this process —
the VLA macro-constant heuristic and the `#if`-between-header-and-body brace
case were both real FPs caught on this corpus.

---

## 7. Docs that hardcode counts

`README.md:82`, `README.md:107`, `VALIDATION.md:286` state "86 rules". Any phase
must update all three, plus `CHANGELOG.md`.

---

## 8. Open decisions

1. **Scope target** — MISRA C:2012+AMD1/2 (matches cppcheck, 156 rules), or go
   to MISRA C:2023/2025 (223/225 guidelines) and accept that AMD3/AMD4 rules are
   native-or-nothing?
2. **Tier split** — adopt the Tier A/B model in 3.3, or hold the strict
   one-pattern-per-rule invariant and cap expansion accordingly?
3. **CERT verbatim** — pursue SEI confirmation and switch `cert_c.json` to
   attributed verbatim text, or keep paraphrases everywhere for uniformity?
4. **Phase 0 first?** — recommended, since it makes existing claims true and its
   per-rule maps are a prerequisite for honest reporting in every later phase.
