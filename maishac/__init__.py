"""Maisha: agent harness for MISRA C, BARR-C and CERT C compliance.

Architecture (all IDE-agnostic, exposed over MCP or CLI):

  analyzers/   pluggable evidence sources (native lexer checks, cppcheck,
               clang-tidy, gcc) that all emit normalized Finding objects
  rules/       standards knowledge base + cross-standard rule mapping
  memory/      SQLite-backed persistent memory: finding fingerprints,
               fix history, deviations, suppressions, project conventions
  engine/      the engineered agent loop: baseline -> prioritize -> fix ->
               verify -> converge, with budgets and oscillation detection
  mcp_server   FastMCP stdio server exposing the harness to any agentic IDE
  cli          standalone command line interface (scan/fix-session/report)
"""

__version__ = "0.3.1"
