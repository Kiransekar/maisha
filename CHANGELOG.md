# Changelog

All notable changes to Sentinel-C are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses [SemVer](https://semver.org/).

## [Unreleased]

### Added
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
- CLI: `sentinelc approve <fp> --by NAME`; `session begin --verification-policy`
  and `--test-command`. MCP: `compliance_approve_finding` plus policy arguments
  on `compliance_begin_session`.
- `README` install path for cppcheck/clang-tidy via pip wheels (no root needed).
- Graceful error when the `mcp` package is missing on `sentinelc serve`.
- `LICENSE` (MIT) and this changelog.

### Fixed
- Removed a stray directory left by a botched brace-expansion `mkdir`.

## [0.1.0]

### Added
- Initial release: native + cppcheck (MISRA addon) + clang-tidy (`cert-*`)
  analyzers, fingerprint-merged findings, SQLite project memory, the engineered
  fix loop with budgets/stall/oscillation guards, deviation/suppression records,
  and Markdown/JSON/SARIF reporting. MCP server for agentic IDEs.
