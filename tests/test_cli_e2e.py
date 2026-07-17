"""In-process end-to-end tests of the argparse CLI (maishac/cli.py).

Calls cli.main(argv) directly (not as a subprocess) so the coverage run sees
every command path, including the error/exit-code branches. The benchmark's
run_cli_and_edge_cases.py exercises the CLI as a real subprocess for a true
black-box smoke test; this complements it by driving the same surface in-process
so cli.py stops being a 0%-coverage blind spot.
"""

from __future__ import annotations

import json

import pytest

from maishac import cli

BAD_C = """\
#include <string.h>
#include <stdlib.h>

char *make(const char *s)
{
    char *p = malloc(64);
    strcpy(p, s);
    return p;
}
"""


def run(argv, capsys):
    """Run the CLI in-process; return (parsed_or_raw_stdout, stderr, exit_code)."""
    code = 0
    try:
        cli.main(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    cap = capsys.readouterr()
    out = cap.out
    try:
        out = json.loads(out)
    except (json.JSONDecodeError, ValueError):
        pass
    return out, cap.err, code


@pytest.fixture()
def proj(tmp_path):
    p = tmp_path / "proj"
    (p / "src").mkdir(parents=True)
    (p / "src" / "m.c").write_text(BAD_C)
    return p


def _P(proj):
    return ["-p", str(proj)]


def test_version_flag(capsys):
    """`maishac --version` prints the version and exits 0 (issue #2)."""
    from maishac import __version__
    out, _, code = run(["--version"], capsys)
    assert code == 0
    assert __version__ in (out if isinstance(out, str) else "")


def test_scan_and_findings(proj, capsys):
    out, _, code = run(_P(proj) + ["scan", "src", "--analyzers", "native"], capsys)
    assert code == 0
    assert out["total_findings"] >= 2
    assert out["analyzers_used"] == ["native"]

    # text listing
    out, _, code = run(_P(proj) + ["findings"], capsys)
    assert code == 0

    # json listing yields at least one fingerprint we can act on
    fps, _, code = run(_P(proj) + ["findings", "--json"], capsys)
    assert code == 0 and fps
    assert all("fingerprint" in f for f in fps)


def test_rule_lookup_and_not_found(proj, capsys):
    out, _, code = run(_P(proj) + ["rule", "STR31-C"], capsys)
    assert code == 0 and out["id"] == "CERT STR31-C"

    out, err, code = run(_P(proj) + ["rule", "definitely-not-a-rule-xyz"], capsys)
    assert code == 1
    assert "not found" in err.lower()


def test_check_from_file_and_guide(proj, capsys):
    draft = proj / "draft.c"
    draft.write_text(BAD_C)
    out, _, code = run(_P(proj) + ["check", str(draft)], capsys)
    assert code == 0
    assert out["clean"] is False and out["findings"]

    out, _, code = run(_P(proj) + ["guide", "dynamic memory"], capsys)
    assert code == 0 and out["patterns"]


def test_full_session_flow(proj, capsys):
    begin, _, code = run(_P(proj) + ["session", "begin", "src", "--verification-policy",
                                     "human_gated"], capsys)
    assert code == 0
    sid = begin["session_id"]

    batch, _, code = run(_P(proj) + ["session", "batch", sid], capsys)
    assert code == 0 and batch["batch"]

    status, _, code = run(_P(proj) + ["session", "status", sid], capsys)
    assert code == 0 and status["state"] == "active"

    verify, _, code = run(_P(proj) + ["session", "verify", sid], capsys)
    assert code == 0 and "state" in verify


def test_approve_suppress_note(proj, capsys):
    run(_P(proj) + ["scan", "src", "--analyzers", "native"], capsys)
    fps, _, _ = run(_P(proj) + ["findings", "--json"], capsys)
    fp = fps[0]["fingerprint"]

    # approving an open (still-detected) finding is refused, not silently done
    out, _, code = run(_P(proj) + ["approve", fp, "--by", "lead"], capsys)
    assert "error" in out

    out, _, code = run(_P(proj) + ["suppress", fp, "-r", "false positive: macro noise"], capsys)
    assert code == 0 and out["suppressed"] == fp

    out, _, code = run(_P(proj) + ["note", "uses pool_alloc", "-t", "allocator"], capsys)
    assert code == 0 and "note_id" in out


def test_deviate_valid_and_bad_date(proj, capsys):
    out, _, code = run(_P(proj) + ["deviate", "MISRA 21.3", "-s", "src/*",
                                   "-j", "heap_4 allocator approved for this project"], capsys)
    assert code == 0 and "deviation_id" in out

    _, err, code = run(_P(proj) + ["deviate", "MISRA 21.3", "-j", "x" * 20,
                                   "--expires", "not-a-date"], capsys)
    assert code == 1 and "YYYY-MM-DD" in err


def test_recategorize_legal_and_illegal(proj, capsys):
    # advisory -> disapplied is legal
    out, _, code = run(_P(proj) + ["recategorize", "MISRA 15.5", "--to", "disapplied",
                                   "-r", "single-exit not enforced by acquirer agreement"], capsys)
    assert code == 0 and out["to_category"] == "disapplied"

    # a Mandatory/Required guideline may not drop to advisory — engine rejects it
    _, err, code = run(_P(proj) + ["recategorize", "MISRA 21.3", "--to", "advisory",
                                   "-r", "we would like this to be advisory"], capsys)
    assert code == 1 and "forbid" in err.lower()


def test_import_missing_file_fails_cleanly(proj, capsys):
    """`maishac import` on a missing file must exit 1 with a message, not spill
    an unhandled FileNotFoundError traceback (Finding #2, this cycle)."""
    _, err, code = run(_P(proj) + ["import", "does-not-exist.sarif"], capsys)
    assert code == 1
    assert "not found" in err.lower()
    assert "Traceback" not in err


def test_import_malformed_json_fails_cleanly(proj, capsys):
    bad = proj / "bad.sarif"
    bad.write_text("{ this is not valid json ")
    _, err, code = run(_P(proj) + ["import", str(bad)], capsys)
    assert code == 1
    assert "not valid sarif json" in err.lower()
    assert "Traceback" not in err


@pytest.mark.parametrize("fmt", ["markdown", "json", "sarif", "misra-compliance", "gep", "grp"])
def test_report_all_formats(proj, capsys, fmt):
    run(_P(proj) + ["scan", "src", "--analyzers", "native"], capsys)
    out, _, code = run(_P(proj) + ["report", "--format", fmt], capsys)
    assert code == 0


def test_report_to_file(proj, capsys):
    run(_P(proj) + ["scan", "src", "--analyzers", "native"], capsys)
    dest = proj / "compliance.sarif"
    out, _, code = run(_P(proj) + ["report", "--format", "sarif", "-o", str(dest)], capsys)
    assert code == 0 and dest.exists()
    doc = json.loads(dest.read_text("utf-8"))
    assert doc["version"] == "2.1.0"
