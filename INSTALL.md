# Installing Maisha

From nothing to a fully-working install, then connected to your editor, agent
or CI.

Read this in order the first time. The one section you should not skip is
[step 3](#3-verify-with-maishac-doctor) — Maisha runs happily with almost
nothing installed, and quietly checks far fewer rules when it does.

- [1. Install `maishac`](#1-install-maishac)
- [2. Install the analyzers](#2-install-the-analyzers-this-is-the-important-part)
- [3. Verify with `maishac doctor`](#3-verify-with-maishac-doctor)
- [4. First scan](#4-first-scan)
- [5. Connect it to your tools](#5-connect-it-to-your-tools)
- [6. CI](#6-ci)
- [Troubleshooting](#troubleshooting)

---

## Requirements

| | |
|---|---|
| **Python** | 3.10 or newer |
| **OS** | Linux, macOS, Windows — no platform-specific code |
| **Hardware** | Nothing special. This is static text analysis: no GPU, no large memory footprint, fine on a laptop or a small CI runner |
| **Your C code** | Does **not** need to compile, and Maisha never builds or runs it |

---

## 1. Install `maishac`

```bash
pip install maishac
maishac --version
```

Prefer an isolated install so it is not tangled up with a project's own
dependencies:

```bash
pipx install maishac          # recommended if you have pipx
```

<details>
<summary>From source (for contributing, or to get unreleased changes)</summary>

```bash
git clone https://github.com/WinterLabsHQ/maisha.git
cd maisha
pip install -e ".[dev]"
python -m pytest tests/ -q
```
</details>

<details>
<summary>Docker (everything pre-installed, nothing to configure)</summary>

The image bundles cppcheck **with its MISRA addon** and clang-tidy, which is
the fiddliest part of a manual setup:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/winterlabshq/maisha scan src/
docker run --rm -v "$PWD:/work" ghcr.io/winterlabshq/maisha doctor
```

`-v "$PWD:/work"` mounts your project; the container works in `/work`. Nothing
is uploaded anywhere — the container runs entirely on your machine.
</details>

At this point Maisha works, but only with its built-in checks. Keep going.

---

## 2. Install the analyzers (this is the important part)

Maisha has a **zero-dependency native analyzer** that always runs, so a scan
will succeed right now. But the native analyzer is lexical — it reads the token
stream one file at a time. The rules that need a type model or data flow are
delegated to external engines.

**Concretely: with nothing else installed you reach about 42% of the
detectable rules (37 of 89).** Scans still pass. They just check less, and that is why
[step 3](#3-verify-with-maishac-doctor) exists.

| Tool | What it adds | Priority |
|---|---|---|
| **cppcheck** + MISRA addon | The bulk of MISRA C — 49 rules | **Install this one** |
| **clang-tidy** | CERT C via its `cert-*` checks | Recommended |
| **gcc / clang** | A handful of rules from compiler warnings | Nice to have |
| A qualified engine | Certification-grade evidence, imported via SARIF | Only if you need certification |

### cppcheck

> **The trap:** several distributions ship cppcheck *without* its MISRA addon,
> in a separate package. In that state cppcheck runs fine and contributes
> **zero** MISRA findings, with no error. `maishac doctor` probes for exactly
> this. If you take one thing from this guide, take this.

```bash
# Debian / Ubuntu
sudo apt install cppcheck

# Fedora
sudo dnf install cppcheck

# macOS
brew install cppcheck

# Windows
winget install Cppcheck.Cppcheck
```

Confirm the addon is really there:

```bash
maishac doctor | grep -i "misra addon"
#   [ ok ] cppcheck MISRA addon: MISRA addon responds
```

If it reports the addon missing, look for a `cppcheck-addons` package, install
cppcheck from source, or just use the Docker image above.

### clang-tidy

```bash
sudo apt install clang-tidy      # Debian / Ubuntu
sudo dnf install clang-tools-extra
brew install llvm                # macOS (may need to add it to PATH)
winget install LLVM.LLVM         # Windows
```

### A C compiler

Any of `gcc`, `clang` or `cc` on `PATH`. Most systems already have one.

---

## 3. Verify with `maishac doctor`

```bash
cd your-firmware-project
maishac doctor
```

```
maishac 0.3.2 at /home/you/firmware

Analyzers
  [ ok ] analyzer: native: maishac 0.3.2
  [ ok ] analyzer: cppcheck: Cppcheck 2.17.1
  [ ok ] cppcheck MISRA addon: MISRA addon responds
  [warn] analyzer: clang-tidy: not installed (needs clang-tidy on PATH)

Rule coverage on this machine
  [warn] reachable rules: 85/89 detectable rules active (96%)
  [warn]   lost without clang-tidy: 4 rule(s) unreachable, e.g. CERT DCL37-C...
```

**Read the "Rule coverage on this machine" section.** It is the honest answer
to what your setup will and will not find. `doctor` exits non-zero only on real
errors, so a deliberately minimal install still passes CI — narrow is a warning,
not a failure.

Run it again any time results look surprising.

---

## 4. First scan

```bash
maishac scan src/
```

If headers live outside the scanned path — a vendor SDK, `FreeRTOSConfig.h` —
pass them, or cppcheck and clang-tidy will report "file not found" noise instead
of real defects:

```bash
maishac scan src/ --include include/ --include vendor/sdk/inc
```

Then:

```bash
maishac findings --limit 20                 # ranked open findings
maishac rule "MISRA 21.3"                   # explain a rule + equivalents
maishac guide "dynamic memory"              # the compliant idiom, before you write it
maishac report --format misra-compliance    # the auditor-facing summary
```

Maisha stores state in `.maishac/` inside your project. **Add it to
`.gitignore`** — it is local state, not source:

```bash
echo ".maishac/" >> .gitignore
```

> If a scan prints a `WARNING: Reduced coverage` block, that is deliberate: a
> clean result on a partial toolchain does not mean the code is compliant with
> the rules that were never checked.

---

## 5. Connect it to your tools

Maisha speaks **MCP** (Model Context Protocol) over stdio, so any MCP-capable
editor or agent can drive the whole compliance loop. The server command is the
same everywhere:

```bash
maishac --project /path/to/your/project serve
```

### Claude Code

```bash
claude mcp add maisha -- maishac --project . serve
```

Or add it to `.mcp.json` in your project root to share it with your team:

```json
{
  "mcpServers": {
    "maisha": {
      "command": "maishac",
      "args": ["--project", ".", "serve"]
    }
  }
}
```

### Cursor

`.cursor/mcp.json` in the project (or `~/.cursor/mcp.json` globally):

```json
{
  "mcpServers": {
    "maisha": {
      "command": "maishac",
      "args": ["--project", ".", "serve"]
    }
  }
}
```

### VS Code (GitHub Copilot agent mode)

`.vscode/mcp.json`:

```json
{
  "servers": {
    "maisha": {
      "type": "stdio",
      "command": "maishac",
      "args": ["--project", ".", "serve"]
    }
  }
}
```

### Windsurf

`~/.codeium/windsurf/mcp_config.json`, same `mcpServers` shape as Cursor.

### Zed

`settings.json` → `context_servers`:

```json
{
  "context_servers": {
    "maisha": {
      "command": { "path": "maishac", "args": ["--project", ".", "serve"] }
    }
  }
}
```

### Claude Desktop

`claude_desktop_config.json` (Settings → Developer → Edit Config). Use an
**absolute** project path — the desktop app does not inherit your shell's
working directory:

```json
{
  "mcpServers": {
    "maisha": {
      "command": "maishac",
      "args": ["--project", "/absolute/path/to/project", "serve"]
    }
  }
}
```

### Anything else that speaks MCP

Continue, JetBrains AI Assistant, Cline, and others take the same three
ingredients: command `maishac`, args `["--project", ".", "serve"]`, transport
stdio. If a client wants a single string, `maishac --project . serve` works.
`--project` is a **global** flag, so it must come *before* `serve` —
`maishac serve --project .` is rejected by the argument parser. Setting
the `MAISHAC_PROJECT` environment variable instead works with any client.

### Using it from an agent

Once connected, ask the agent to drive the loop in plain language — *"bring
`src/drivers` into MISRA compliance"*. It should call
`compliance_begin_session`, then `next_batch` → fix → `record_attempt` →
`verify` until the session converges. `AGENT_PLAYBOOK.md` documents the exact
protocol, including the stall and oscillation guards.

Two things worth telling your agent explicitly:

- Call `compliance_doctor` first, and relay any coverage warning. A converged
  session on a partial toolchain is not a compliance claim.
- Use `compliance_guidance` *before* writing new C, not just after. Getting the
  compliant idiom first is cheaper than fixing a finding later.

### Verifying the connection

Start the server by hand:

```bash
maishac --project . serve
```

A healthy server **prints nothing and does not exit** — it is waiting for JSON-RPC
on stdin. That silence is success; press Ctrl-C to stop it. If instead you get a
traceback, a `command not found`, or an argparse usage message, the fault is in
your setup rather than in the client.

(Driving it further by hand needs a full MCP `initialize` handshake, so it is not
worth doing from a shell — let the client do it.)

Most failures are simply that `maishac` is not on the `PATH` your editor sees,
which often differs from your shell's. Run `which maishac` (`where maishac` on
Windows) and put the absolute path in the config:

```json
{ "command": "/home/you/.local/bin/maishac", "args": ["--project", ".", "serve"] }
```

---

## 6. CI

```yaml
name: compliance
on: [push, pull_request]

jobs:
  misra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }

      - run: sudo apt-get update && sudo apt-get install -y cppcheck clang-tidy
      - run: pip install maishac

      # Fails the build on a broken install; a narrow one only warns.
      - run: maishac doctor

      - run: maishac scan src/ --include include/
      - run: maishac report --format sarif > compliance.sarif

      # Surfaces findings in the Security tab and on the PR diff
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: compliance.sarif }
```

Because SARIF is standard, the same file works with GitLab, Azure DevOps,
SonarQube and most code-quality dashboards.

### Layering a qualified engine

Maisha is **not** a qualified static-analysis tool and cannot by itself satisfy
DO-178C, ISO 26262 or IEC 62304 tool qualification. The supported path is to run
a qualified engine (Polyspace, Helix QAC, Coverity, Parasoft) and import its
results, so Maisha becomes the workflow and audit-evidence layer around it:

```bash
maishac import qac-results.sarif
```

Imported findings are never cleared by a native rescan, and they flow through
the same memory, verification gate and reports.

---

## Troubleshooting

**`maishac: command not found`** — the install went to a directory not on your
`PATH`. Try `python -m maishac` instead, or `pipx install maishac`.

**Editor can't start the MCP server** — the editor's `PATH` usually differs from
your shell's. Run `which maishac` (`where maishac` on Windows) and use the
absolute path in the config.

**cppcheck contributes no MISRA findings** — the addon is missing. See
[step 2](#cppcheck); confirm with `maishac doctor`.

**Findings look like nonsense: "file not found", "undefined identifier"** —
missing include paths. Pass `--include` for every directory holding headers your
code needs.

**A scan warns about reduced coverage** — working as intended. Install the named
analyzer, or accept the narrower scope knowingly.

**Scanning is slow on a huge tree** — scan directories separately, and exclude
vendored third-party code you are not trying to bring into compliance.

**Everything is broken and I want to start over** — `rm -rf .maishac/` discards
all local state (findings, deviations, sessions, sign-offs) and starts fresh.
There is no undo, so export a report first if any of it mattered.

---

## Where to go next

| Document | What it covers |
|---|---|
| `README.md` | What Maisha is, and what it deliberately is not |
| `AGENT_PLAYBOOK.md` | The exact protocol an agent should follow |
| `AUTHORING_PLAYBOOK.md` | Writing compliant C in the first place |
| `COVERAGE.md` | Every rule carried, and which analyzer backs it |
| `VALIDATION.md` | Self-attested validation evidence, and its limits |
