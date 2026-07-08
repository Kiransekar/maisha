# IDE integration snippets

All hosts use the same stdio MCP server: command `sentinelc`, args `["serve"]`,
env `SENTINELC_PROJECT` pointing at the project root to scan.

- **Claude Code** — copy `claude-code.mcp.json` contents into `.mcp.json` at your
  project root (Claude Code substitutes the workspace path automatically; if your
  version doesn't support `${workspaceFolder}`, use an absolute path).
- **Cursor** — merge `cursor.mcp.json` into `~/.cursor/mcp.json` (or the
  per-project `.cursor/mcp.json`), with an absolute project path.
- **Anything else (Windsurf, Zed, custom hosts)** — `generic-mcp.json` shows the
  three fields every MCP host asks for.

After connecting, paste `AGENT_PLAYBOOK.md` into your agent's rules file and ask
it to begin a compliance session.
