# Maisha vs. proprietary compliance tools

**Short version:** Maisha is the open-source **compliance-workflow layer** for
MISRA / CERT / BARR-C — the orchestration, agentic fix loop, verification gate,
deviation & audit-evidence workflow, and author-time guidance that proprietary
vendors now sell as paid "agentic toolkits." It is **not** a replacement for a
*qualified static-analysis engine*, and it does not claim to be. Instead it runs
on free engines (cppcheck's MISRA addon + clang-tidy) **and** layers on top of a
qualified engine (Polyspace, Helix QAC, Coverity, Parasoft, CodeSonar) by
importing its SARIF.

So the honest positioning is two claims, both true:

1. **The OSS alternative to the paid compliance *workflow*** (fix loops,
   deviation management, MISRA Compliance:2020 evidence, agentic MCP toolkits).
2. **A genuinely free MISRA/CERT path** for pre-certification and
   budget-constrained embedded teams, via the best open-source analyzers,
   wrapped in a real workflow.

What it is **not**: a certified/qualified analyzer, and not a whole-program
engine that decides undecidable rules. Those you buy — and then point Maisha at.

## Feature comparison

Legend: ✓ yes · ◑ partial · ✗ no · ⤴ via layering (import the paid engine's SARIF)

| Capability | **Maisha** (MIT) | cppcheck / clang-tidy alone | Proprietary engines (Polyspace, Helix QAC, Coverity, Parasoft, CodeSonar) | Their new agentic toolkits (Polyspace Agentic Toolkit, Klocwork/QAC AI, CodeSonar MCP) |
|---|---|---|---|---|
| **Price / license** | Free, MIT, open source | Free / OSS | $$$ per-seat, closed | $$$ (bundled with the paid engine) |
| **Detection engine depth** | ◑ native lexical + free engines; ⤴ imports a qualified engine's findings | ◑ real but unqualified | ✓ deep whole-program, qualified | ✓ (the engine's) |
| **Tool-qualified (ISO 26262 / DO-330)** | ✗ by design — orchestration layer, not the detector | ✗ | ✓ | ✓ (engine) |
| **Vendor-neutral: aggregate *any/multiple* engines** | ✓ core design (SARIF in) | ✗ | ✗ single vendor | ✗ locked to own engine |
| **Agentic fix loop (any IDE via MCP)** | ✓ engine-agnostic | ✗ | ✗ | ◑ locked to own engine |
| **Verification gate** (fix not "resolved" on a clean rescan alone) | ✓ + human/test sign-off, oscillation freeze | ✗ | ◑ re-analysis | ◑ re-analysis |
| **Deviation permits / justification workflow** | ✓ 5-element records, approver, expiry | ✗ | ◑ | ◑ justification catalog |
| **MISRA Compliance:2020 evidence (GEP / GRP / GCS)** | ◑ GCS today; GEP/GRP on roadmap | ✗ | ◑ report only | ✗ |
| **Author-time proactive guidance** (compliant idiom before you write) | ✓ 37-pattern library, `guide`/`check` | ✗ | ✗ | ◑ fix suggestions |
| **Persistent project memory** (findings survive edits, track lifecycle) | ✓ fingerprint-stable | ✗ | ◑ | ◑ |
| **Runs fully offline / on-prem, no data leaves** | ✓ | ✓ | ◑ | depends |
| **Import an existing team's triage / baseline** | ✓ SARIF suppressions | ✗ | n/a | ◑ |

## "Is Maisha an alternative to X?"

- **…to Polyspace / Helix QAC / Coverity / Parasoft / CodeSonar (the engines)?**
  No — those *detect*. Maisha *orchestrates* and can import their SARIF. If you
  own one, Maisha adds the fix loop, verification gate, deviation register and
  compliance report around it, from any agentic IDE, for free.
- **…to their agentic toolkits (Polyspace Agentic Toolkit, Klocwork/QAC AI
  remediation, CodeSonar MCP)?** Yes — this is the closest head-to-head. Those
  are excellent but each is locked to its own paid engine. Maisha is free and
  works across *any* engine (including free ones), so a heterogeneous or
  budget-limited toolchain gets one unified workflow.
- **…to buying a commercial tool at all, for a pre-cert / hobby / startup team?**
  Partly — Maisha + cppcheck (MISRA addon) + clang-tidy is a real, free MISRA/CERT
  cleanup path with a proper workflow. It is *not* certification evidence; when
  you need that, add a qualified engine and keep the same Maisha workflow.

## Why this positioning is honest (and defensible)

Whole-program MISRA/CERT rules are undecidable by lightweight analysis, and the
commercial engines are *qualified* for safety standards — Maisha competing on
detection would be a worse, unqualified analyzer nobody should trust. The
defensible ground is the layer the vendors themselves just started charging for
via agentic toolkits, but which none of them offer **vendor-neutrally, for free,
across any engine**. That gap is Maisha's to own.

*Comparison reflects publicly documented capabilities as of 2026 and will drift;
corrections via PR are welcome (see [CONTRIBUTING.md](CONTRIBUTING.md)).*
