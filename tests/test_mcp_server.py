"""End-to-end test of the MCP server over its real stdio JSON-RPC transport.

Everything else drives the LoopEngine directly; this is the only test that
exercises maishac/mcp_server.py through an actual MCP client talking to a
freshly-spawned `python -m maishac.mcp_server` subprocess — the exact surface an
agentic IDE (Claude Code, Cursor, Zed, ...) connects to. It closes the "no test
of the MCP server's actual stdio protocol surface" gap called out in
BENCHMARK-SUITE-REPORT.md §9.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

mcp_client = pytest.importorskip("mcp.client.stdio")
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

BAD_C = """\
#include <string.h>
void copy_it(char *dst, const char *src)
{
    strcpy(dst, src);
    if (dst[0] == 0)
        dst[0] = 1;
}
"""


def _text(result) -> dict:
    """Unwrap a FastMCP tool result (TextContent list) into the parsed JSON."""
    assert result.content, "tool returned no content"
    return json.loads(result.content[0].text)


async def _drive(project_dir: str) -> dict:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "maishac.mcp_server"],
        # Full env so the child can import maishac + find its interpreter; the
        # server reads the project root from MAISHAC_PROJECT.
        env={**os.environ, "MAISHAC_PROJECT": project_dir},
    )
    out: dict = {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = {t.name for t in (await session.list_tools()).tools}
            out["tools"] = tools

            out["scan"] = _text(await session.call_tool(
                "compliance_scan", {"paths": ["src"], "analyzers": ["native"]}))

            out["list"] = _text(await session.call_tool(
                "compliance_list_findings", {"limit": 50}))

            out["rule"] = _text(await session.call_tool(
                "compliance_explain_rule", {"rule": "STR31-C"}))

            begin = _text(await session.call_tool(
                "compliance_begin_session",
                {"paths": ["src"], "analyzers": ["native"]}))
            out["begin"] = begin
            sid = begin["session_id"]

            batch = _text(await session.call_tool(
                "compliance_next_batch", {"session_id": sid}))
            out["batch"] = batch
            fp = batch["batch"][0]["fingerprint"]

            out["record"] = _text(await session.call_tool(
                "compliance_record_attempt",
                {"session_id": sid, "fingerprint": fp, "strategy": "bounded copy"}))

            out["verify"] = _text(await session.call_tool(
                "compliance_verify", {"session_id": sid}))

            out["report"] = (await session.call_tool(
                "compliance_report", {"format": "markdown"})).content[0].text
    return out


def test_mcp_tools_in_process(tmp_path, monkeypatch):
    """Drive the @mcp.tool() functions directly (they stay plain callables), so
    the server module's tool bodies are covered and their JSON contracts checked
    in-process. The stdio test below is the true protocol check; this is the
    fast, coverage-bearing companion."""
    from maishac import mcp_server as m

    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "m.c").write_text(BAD_C)
    monkeypatch.setenv("MAISHAC_PROJECT", str(proj))
    monkeypatch.setattr(m, "_ENGINE", None)  # force re-init against this project

    scan = json.loads(m.compliance_scan(["src"], analyzers=["native"]))
    assert scan["total_findings"] >= 1

    listed = json.loads(m.compliance_list_findings(limit=50))
    fp = listed["findings"][0]["fingerprint"]
    assert json.loads(m.compliance_get_finding(fp))["fingerprint"] == fp
    assert "error" in json.loads(m.compliance_get_finding("deadbeef"))

    assert json.loads(m.compliance_explain_rule("STR31-C"))["id"] == "CERT STR31-C"
    assert "error" in json.loads(m.compliance_explain_rule("nope-xyz"))
    assert json.loads(m.compliance_search_rules("recursion"))
    assert json.loads(m.compliance_guidance("dynamic memory"))["patterns"]
    assert json.loads(m.compliance_check_snippet("char b[4]; strcpy(b, s);"))["findings"]

    begin = json.loads(m.compliance_begin_session(["src"], verification_policy="human_gated"))
    sid = begin["session_id"]
    batch = json.loads(m.compliance_next_batch(sid))
    bfp = batch["batch"][0]["fingerprint"]
    assert json.loads(m.compliance_record_attempt(sid, bfp, "bounded copy"))["recorded"]
    assert "state" in json.loads(m.compliance_verify(sid))
    assert json.loads(m.compliance_session_status(sid))["state"]

    # approving a still-open finding is refused
    assert "error" in json.loads(m.compliance_approve_finding(bfp, "lead"))

    # deviation guards: unknown rule + too-short justification
    assert "error" in json.loads(m.compliance_add_deviation("nope", "*", "x" * 20))
    assert "error" in json.loads(m.compliance_add_deviation("MISRA 21.3", "src/*", "short"))
    assert "deviation_id" in json.loads(
        m.compliance_add_deviation("MISRA 21.3", "src/*", "heap_4 allocator approved here"))

    # GRP legality enforced through the tool
    assert "error" in json.loads(m.compliance_recategorize("MISRA 21.3", "advisory", "why"))

    # suppress guards + success
    assert "error" in json.loads(m.compliance_suppress_finding("deadbeef", "reason enough here"))
    assert "error" in json.loads(m.compliance_suppress_finding(fp, "short"))
    assert json.loads(m.compliance_suppress_finding(fp, "false positive: macro noise"))["suppressed"]

    assert "note_id" in json.loads(m.memory_note("uses pool_alloc", topic="alloc"))
    assert isinstance(json.loads(m.memory_search("pool")), list)
    assert "findings_by_status" in json.loads(m.memory_stats())

    for fmt in ("markdown", "json", "sarif", "misra-compliance", "gep", "grp"):
        assert m.compliance_report(fmt)

    # SARIF import through the tool
    imp = json.loads(m.compliance_import_sarif(
        str(REPO / "benchmark" / "synthetic_qualified_engine.sarif.json")))
    assert imp["imported"] >= 1


def test_mcp_stdio_end_to_end(tmp_path):
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "m.c").write_text(BAD_C)

    out = asyncio.run(_drive(str(proj)))

    # The full documented tool surface is actually registered and reachable.
    for expected in ("compliance_scan", "compliance_begin_session",
                     "compliance_next_batch", "compliance_verify",
                     "compliance_approve_finding", "compliance_report",
                     "compliance_import_sarif", "memory_note"):
        assert expected in out["tools"], f"missing MCP tool {expected}"

    # Scan found the seeded strcpy (CERT STR31-C) via real JSON-RPC round-trips.
    assert out["scan"]["total_findings"] >= 1
    assert out["scan"]["analyzers_used"] == ["native"]
    assert any("STR31" in f["rule_id"] for f in out["list"]["findings"])

    # Rule intel resolved the fuzzy id.
    assert out["rule"]["id"] == "CERT STR31-C"

    # A real session/batch/record/verify loop turn completed over the wire.
    assert out["begin"]["state"] == "active"
    assert out["batch"]["batch"], "next_batch returned no findings"
    assert out["record"]["recorded"] is True
    assert out["verify"]["state"] in (
        "active", "awaiting_verification", "converged", "stalled",
        "budget_exhausted")

    # The report is real markdown, not an error blob.
    assert "# " in out["report"]
