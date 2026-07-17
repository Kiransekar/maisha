# Security Policy

## Supported Versions

Maisha is pre-1.0 (current release: `0.1.0`) and does not yet maintain
parallel supported release lines. Security fixes are made against `main` and
shipped in the next release.

| Version         | Supported          |
| --------------- | ------------------- |
| `main` (latest) | :white_check_mark: |
| `0.1.0`         | :white_check_mark: |
| < `0.1.0`       | :x:                 |

Once Maisha reaches 1.0, this table will track supported minor lines and this
policy will be updated accordingly.

## Scope

Maisha is a compliance-workflow orchestrator, not a sandboxed service. Its
relevant attack surface is local, not network-facing:

- **Subprocess execution** — `maishac scan`/`session verify` shell out to
  `cppcheck` and `clang-tidy` on files you point it at, and `session begin
  --test-command` runs an arbitrary shell command you configure. Treat
  `test_command` and scanned paths as trusted input, the same as any other
  local build tooling.
- **SARIF import** (`maishac import`, `compliance_import_sarif`) parses
  external JSON/XML. Only import SARIF files from analyzers you trust.
- **Project memory** (`.maishac/memory.db`) is a local SQLite file with no
  access control beyond the filesystem; do not commit it, and treat it as
  sensitive if your findings/notes contain proprietary code excerpts.
- The **MCP server** (`maishac serve`) runs over stdio for a single local
  agentic IDE session — it is not designed or hardened to be exposed over a
  network transport.

If you find an issue outside this scope (e.g. in a bundled dependency), please
still report it — we'll help route it upstream if needed.

## Reporting a Vulnerability

Please report security issues privately using **GitHub Security Advisories**:

**https://github.com/WinterLabsHQ/maisha/security/advisories/new**

Do not open a public issue for a suspected vulnerability.

Include, if possible:

- A description of the issue and its potential impact
- Steps to reproduce (a minimal repro project/command is ideal)
- The Maisha version / commit SHA you tested against

### What to expect

- **Acknowledgement:** within 5 business days.
- **Status updates:** at least every 2 weeks while the report is triaged and
  fixed.
- **If accepted:** we'll agree a disclosure timeline with you, prepare a fix
  and a patched release, and credit you in the advisory (unless you prefer
  otherwise).
- **If declined:** we'll explain why (e.g. out of scope, not exploitable,
  working as intended) and remain open to discussion if you disagree.

Given the tool's disclaimed scope — Maisha is a workflow/orchestration layer,
not a certified static-analysis engine (see [README's Scope &
Limitations](README.md#scope--limitations)) — findings about *missed*
MISRA/CERT/BARR-C violations are a quality/coverage issue (see
[COVERAGE.md](COVERAGE.md) and [BENCHMARKS.md](BENCHMARKS.md)), not a security
vulnerability; please file those as a regular issue instead.
