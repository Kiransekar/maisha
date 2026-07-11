# Contributing to Maisha

Thanks for helping make embedded C compliance less painful. Maisha is
deliberately built to be **extended by the community** — most valuable
contributions don't touch the engine at all; they add rules, authoring
patterns, or analyzer adapters. This guide shows you where.

## Quick start

```bash
git clone https://github.com/Kiransekar/maisha.git
cd maisha
pip install -e ".[dev]"        # editable install + pytest
python -m pytest -q            # 44 tests, should be green before you start
```

`python` may not be on your PATH — use `python3`. Optional analyzers
(`cppcheck`, `clang-tidy`) increase coverage but are never required: the native
analyzer runs with zero dependencies and the suite passes without them.

## Before you open a PR

- Run `python -m pytest -q` — all tests must pass.
- If you touched the rule registry, run `python tools/gen_coverage.py` to
  regenerate `COVERAGE.md` (a test fails if it drifts).
- Keep the diff focused; one concern per PR.
- Add a line to `CHANGELOG.md` under `## [Unreleased]`.

## The three things most contributions add

### 1. A rule (knowledge base)

Rules live in `maishac/rules/{misra_c_2012,barr_c_2018,cert_c}.json`, keyed by
canonical id. Add an entry:

```json
"Rule 21.3": {
  "severity": "critical",
  "category": "required",
  "summary": "malloc/calloc/realloc/free from <stdlib.h> shall not be used.",
  "fix": "Use static allocation, memory pools, or stack buffers sized at compile time.",
  "cross": ["CERT MEM30-C", "BARR-C 5.6a"]
}
```

- **`summary`/`fix` must be your own original paraphrase.** MISRA®, BARR-C and
  CERT C are copyrighted — never paste normative standard text. See the
  License section of the README.
- `cross` lists equivalent rules in other standards (any form the resolver
  accepts, e.g. `"MISRA 21.3"`, `"CERT MEM30-C"`, `"BARR-C 5.6a"`).
- Regenerate `COVERAGE.md` and add a matching **authoring pattern** (below) —
  a test asserts every rule has one.

### 2. An authoring pattern (the "compliant idiom" library)

Patterns power `maishac guide` and enrich `maishac check`. Add an entry to
`PATTERNS` in `maishac/patterns.py`:

```python
{
    "concern": "dynamic memory allocation",
    "keywords": ["malloc", "free", "heap", "alloc"],
    "rules": ["MISRA 21.3", "CERT MEM30-C", "BARR 5.6a"],
    "avoid": "uint8_t *buf = malloc(n);",
    "prefer": "static uint8_t buf[MAX_N];   /* fixed, compile-time sized */",
    "why": "Dynamic allocation can fail, fragments, and makes worst-case memory unprovable.",
},
```

Every id in `rules` must resolve in the registry (a test enforces it), and
`avoid`/`prefer` are your own code samples.

### 3. An analyzer adapter (a new evidence source)

To wire in another tool (a linter, compiler warnings, another engine), subclass
`Analyzer` in `maishac/analyzers/base.py` and return `Finding`s (see
`native.py`, `cppcheck.py`, `clang_tidy.py` for examples). Map the tool's rule
ids onto the registry with `REGISTRY.resolve(...)`. Register it in
`analyzers/__init__.py::run_scan`. It should degrade gracefully when the tool
isn't installed.

For a tool that emits **SARIF**, you usually don't need an adapter at all — just
`maishac import findings.sarif`. Improving `report.parse_sarif` to handle a real
engine's SARIF dialect (rule-id mapping via taxonomies/relationships,
suppressions, code flows) is a high-value contribution — attach a small sample
SARIF as a test fixture.

## Design invariants — please don't break these

These are load-bearing; a PR that weakens one will be asked to change (see
`CLAUDE.md` for the full rationale):

- **Findings are identities, not line numbers.** `compute_fingerprint()` is
  `sha1(rule + file + normalized line + enclosing function)`. Never key on raw
  line numbers.
- **A fix is never `resolved` on a clean rescan alone.** It passes through
  `pending_verification` until a passing test or a human approval; semantic-risk
  and high-severity findings always require human sign-off. The verification
  gate is the point of the tool — don't weaken it to make a test pass.
- **Imported (SARIF) findings are never cleared by a native rescan.**
- **The fix loop must always reach a terminal state** (converged / stalled /
  budget_exhausted / awaiting_verification).
- **Rule knowledge-base text stays original paraphrase**, never reproduced
  standard text.

## Commit / PR conventions

- Small, reviewable commits; imperative subject lines.
- Every non-trivial change ships with a test (`tests/test_*.py`, assert-based,
  no heavy fixtures).
- By contributing you agree your work is licensed under the project's MIT
  License.

## Good first contributions

- Add an authoring pattern for a concern not yet covered well.
- Add a real qualified-engine SARIF sample as a test fixture and harden the
  importer for its dialect.
- Improve a rule's `fix` hint with a clearer remediation.
- Add an analyzer adapter for a tool you already use.

Questions or a bigger idea? Open an issue first so we can shape it together.
