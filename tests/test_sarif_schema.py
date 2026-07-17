"""SARIF 2.1.0 schema-conformance tests.

The existing SARIF tests check semantics (rule mapping, round-trip fidelity,
relationships). These check *conformance*: that what Maisha emits actually
validates against the official OASIS SARIF 2.1.0 JSON schema, so a downstream
consumer (GitHub code scanning, an IDE problem pane, a CI gate) will accept it.
The schema is vendored at tests/data/sarif-2.1.0.json so the test is hermetic.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

from maishac.engine import LoopEngine  # noqa: E402
from maishac import report as report_mod  # noqa: E402

SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-2.1.0.json").read_text("utf-8"))
REPO = Path(__file__).resolve().parents[1]

BAD_C = """\
#include <string.h>
#include <stdlib.h>
void f(char *d, const char *s)
{
    char *p = malloc(10);
    strcpy(d, s);
    switch (d[0]) { case 1: break; }
}
"""


def _validate(doc: dict):
    jsonschema.validate(instance=doc, schema=SCHEMA)  # raises on non-conformance
    assert doc["version"] == "2.1.0"
    assert doc["$schema"]
    assert doc["runs"] and "tool" in doc["runs"][0]


def test_empty_export_is_conformant(tmp_path):
    eng = LoopEngine(tmp_path)
    _validate(report_mod.sarif(eng.mem))


def test_native_scan_export_is_conformant(tmp_path):
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "m.c").write_text(BAD_C)
    eng = LoopEngine(proj)
    eng.scan(["src"], analyzers=["native"])
    doc = report_mod.sarif(eng.mem)
    _validate(doc)
    # partialFingerprints (maishac/v1) carried per README
    results = doc["runs"][0]["results"]
    assert results
    assert any("partialFingerprints" in r for r in results)


def test_imported_sarif_with_codeflows_reexports_conformant(tmp_path):
    """Importing a qualified-engine SARIF (codeFlows, foreign rule ids) and
    re-exporting must still yield a schema-valid document — the round-trip that
    layers Maisha onto an existing engine can't emit malformed SARIF."""
    proj = tmp_path / "proj"
    proj.mkdir()
    eng = LoopEngine(proj)
    eng.import_sarif(REPO / "benchmark" / "synthetic_qualified_engine.sarif.json")
    _validate(report_mod.sarif(eng.mem))
