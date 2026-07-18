"""`maishac doctor` — diagnose the installation, toolchain and project state.

The question this answers is not "is Maisha installed" but **"what will this
machine actually detect, and what am I losing?"**

That matters more here than in most tools. Maisha's native analyzer is
zero-dependency and always runs, but it only covers the lexical subset; the
semantic rules are delegated to cppcheck and clang-tidy. So the same command on
two machines can produce very different coverage, silently. `doctor` makes that
difference explicit and quantified, per standard, before anyone draws a
compliance conclusion from a clean scan.

Checks run in four groups: environment, analyzer toolchain (with the resulting
rule coverage), knowledge-base integrity, and project memory. Any `error`
exits non-zero so CI can gate on it.
"""

from __future__ import annotations

import os
import platform
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from . import __version__
from .analyzers import ALL_ANALYZERS
from .coverage import analyzers_for, enforced_ids, reference_ids
from .rules import REGISTRY
from . import patterns

OK, WARN, ERROR = "ok", "warn", "error"
# ASCII only: doctor is the first thing run on an unfamiliar machine, and a
# Windows console in a legacy code page turns box-drawing/check glyphs into
# mojibake, which makes a diagnostic tool look broken at exactly the wrong
# moment.
_ICON = {OK: "[ ok ]", WARN: "[warn]", ERROR: "[FAIL]"}

# CERT identifiers numbered 00-29 are Recommendations, which are non-normative;
# 30+ are Rules. The knowledge base deliberately carries Rules only, so a
# cross-reference to a Recommendation is an intentional pointer outside the
# curated subset, not a broken link.
_CERT_RECOMMENDATION = re.compile(r"CERT [A-Z]{3}[0-2]\d-C")


def _check(name: str, status: str, detail: str, hint: str = "") -> dict:
    return {"name": name, "status": status, "detail": detail, "hint": hint}


# --------------------------------------------------------------- environment
def _environment() -> list[dict]:
    out = [
        _check("maishac version", OK, __version__),
        _check("python", OK, f"{platform.python_version()} ({sys.executable})"),
        _check("platform", OK, f"{platform.system()} {platform.release()}"),
    ]
    if sys.version_info < (3, 10):
        out.append(_check("python version", ERROR,
                          f"{platform.python_version()} is below the required 3.10",
                          "Install Python 3.10 or newer."))
    return out


# ----------------------------------------------------------------- analyzers
def _cppcheck_has_misra_addon() -> tuple[bool, str]:
    """Probe whether this cppcheck can actually run its MISRA addon.

    cppcheck installs frequently ship without addons/misra.py (several distro
    packages split it out). Without it cppcheck still runs, but every MISRA rule
    it would otherwise raise silently disappears — the single largest hidden
    coverage cliff in a Maisha install, which is exactly what doctor exists to
    surface.
    """
    with tempfile.TemporaryDirectory() as td:
        probe = Path(td) / "probe.c"
        probe.write_text("int main(void) { return 0; }\n", "utf-8")
        try:
            proc = subprocess.run(
                ["cppcheck", "--addon=misra", "--enable=all", "--xml", str(probe)],
                capture_output=True, text=True, timeout=60)
        except Exception as e:  # noqa: BLE001 — a probe must never break doctor
            return False, f"probe failed: {e}"
    err = (proc.stderr or "") + (proc.stdout or "")
    for marker in ("Did not find addon", "failed to load addon", "Failed to load addon",
                   "addon not found", "No such file or directory"):
        if marker.lower() in err.lower():
            return False, "cppcheck is installed but its MISRA addon is missing"
    return True, "MISRA addon responds"


def _analyzers() -> tuple[list[dict], set[str]]:
    """Returns (checks, names of analyzers actually usable on this machine)."""
    out, usable = [], set()
    for cls in ALL_ANALYZERS:
        an = cls()
        if not an.available():
            # `requires` is None for the compiler adapter, which resolves gcc,
            # clang or cc dynamically — so name the analyzer, not a null binary.
            need = an.requires or "gcc, clang or cc"
            out.append(_check(
                f"analyzer: {an.name}", WARN,
                f"not installed (needs {need} on PATH)",
                f"Install {need} to widen detection; "
                "see the coverage impact below."))
            continue
        usable.add(an.name)
        out.append(_check(f"analyzer: {an.name}", OK, an.version()))
        if an.name == "cppcheck":
            has_addon, why = _cppcheck_has_misra_addon()
            if has_addon:
                out.append(_check("cppcheck MISRA addon", OK, why))
            else:
                usable.discard("cppcheck")
                out.append(_check(
                    "cppcheck MISRA addon", ERROR, why,
                    "Without it cppcheck contributes no MISRA findings at all. "
                    "Install the addon (often a separate 'cppcheck-addons' "
                    "package) or use the container image, which bundles it."))
    return out, usable


def _coverage_impact(usable: set[str]) -> list[dict]:
    """How many KB rules this machine can actually reach, and what's missing.

    A rule counts as reachable if any *installed* analyzer maps a check onto it.
    'native (partial)' counts as reachable but is reported separately, because a
    partial check must never read as full coverage.
    """
    out = []
    reachable, unreachable_by_tool = set(), {}
    for rid in REGISTRY.all_ids():
        mapped = analyzers_for(rid)
        if not mapped:
            continue  # reference tier: nothing detects it anywhere
        hit = [m for m in mapped if m.split(" ")[0] in usable]
        if hit:
            reachable.add(rid)
        else:
            for m in mapped:
                unreachable_by_tool.setdefault(m.split(" ")[0], []).append(rid)

    enforced = enforced_ids()
    total = len(REGISTRY.all_ids())
    pct = (100 * len(reachable) / len(enforced)) if enforced else 0
    # Never an error: a native-only install is a documented, supported mode —
    # it is narrower, not broken. Errors are reserved for things that will
    # actually misbehave.
    status = OK if pct >= 99 else WARN
    out.append(_check(
        "reachable rules", status,
        f"{len(reachable)}/{len(enforced)} enforced rules detectable here "
        f"({pct:.0f}%); {len(reference_ids())} reference-only; {total} in the KB"))

    for std in ("MISRA-C:2012", "BARR-C:2018", "CERT-C"):
        ids = set(REGISTRY.all_ids(std))
        e = ids & enforced
        r = ids & reachable
        if not e:
            continue
        out.append(_check(f"  {std}", OK if len(r) == len(e) else WARN,
                          f"{len(r)}/{len(e)} enforced rules detectable"))

    for tool, lost in sorted(unreachable_by_tool.items()):
        out.append(_check(
            f"  lost without {tool}", WARN,
            f"{len(lost)} rule(s) unreachable, e.g. "
            + ", ".join(sorted(lost)[:3]) + ("..." if len(lost) > 3 else ""),
            f"Install {tool} to recover them."))

    partial = [rid for rid in reachable
               if any(m.endswith("(partial)") for m in analyzers_for(rid))]
    if partial:
        out.append(_check(
            "  partial coverage", WARN,
            f"{len(partial)} rule(s) are only partially checked: "
            + ", ".join(sorted(partial)),
            "The residual needs review or another tool - record it in the "
            "Guideline Enforcement Plan (maishac report --format gep)."))
    return out


# ------------------------------------------------------------ knowledge base
def _knowledge_base() -> list[dict]:
    out = []
    try:
        total = len(REGISTRY.all_ids())
    except Exception as e:  # noqa: BLE001
        return [_check("rule knowledge base", ERROR, f"failed to load: {e}",
                       "The package data may be corrupt; reinstall maishac.")]
    counts = ", ".join(f"{len(REGISTRY.all_ids(s))} {s}"
                       for s in ("MISRA-C:2012", "BARR-C:2018", "CERT-C"))
    out.append(_check("rule knowledge base", OK, f"{total} rules ({counts})"))

    mandatory = [r for r in REGISTRY.all_ids("MISRA-C:2012")
                 if REGISTRY.get(r).get("category") == "mandatory"]
    out.append(_check("  MISRA mandatory rules", OK if mandatory else WARN,
                      f"{len(mandatory)} loaded (deviations are refused against these)"))

    dead = [(rid, ref) for rid in REGISTRY.all_ids()
            for ref in REGISTRY.get(rid).get("cross", [])
            if not REGISTRY.resolve(ref)]
    external = [d for d in dead if _CERT_RECOMMENDATION.fullmatch(d[1])]
    broken = [d for d in dead if d not in external]
    out.append(_check("  cross-standard references",
                      OK if not broken else ERROR,
                      "all resolve" if not broken
                      else f"{len(broken)} broken link(s): {broken[:3]}",
                      "" if not broken
                      else "A broken cross-link silently drops guidance from findings."))
    if external:
        out.append(_check(
            "  references outside the subset", OK,
            f"{len(external)} point at CERT Recommendations (non-normative, "
            "deliberately not carried)"))

    patterns._BY_RULE = None
    covered = set(patterns._index())
    gaps = sorted(r for r in enforced_ids() if r not in covered)
    out.append(_check("  authoring patterns", OK if not gaps else ERROR,
                      f"{len(patterns.PATTERNS)} patterns cover every enforced rule"
                      if not gaps else f"{len(gaps)} enforced rule(s) have no pattern: {gaps[:3]}",
                      "" if not gaps else "Findings for these rules cannot teach a fix."))
    return out


# ----------------------------------------------------------- project memory
def _project(root: Path) -> list[dict]:
    out = [_check("project root", OK, str(root))]
    mdir = root / ".maishac"
    if not mdir.exists():
        out.append(_check("project memory", WARN, f"{mdir} does not exist yet",
                          "Created on first scan. Run: maishac scan src/"))
        return out
    if not os.access(mdir, os.W_OK):
        out.append(_check("project memory", ERROR, f"{mdir} is not writable",
                          "Maisha cannot record findings, attempts or deviations."))
        return out

    db_path = mdir / "memory.db"
    if not db_path.exists():
        out.append(_check("project memory", WARN, "no memory.db yet",
                          "Created on first scan."))
        return out
    size_kb = db_path.stat().st_size / 1024
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            out.append(_check("memory database", ERROR, f"integrity check: {integrity}",
                              "The audit trail may be corrupt. Restore from backup."))
        else:
            mode = con.execute("PRAGMA journal_mode").fetchone()[0]
            out.append(_check("memory database", OK,
                              f"{size_kb:.0f} KB, journal={mode}, integrity ok"))
            stats = []
            for table, label in (("findings", "findings"), ("deviations", "deviations"),
                                 ("suppressions", "suppressions"), ("sessions", "sessions"),
                                 ("notes", "notes")):
                try:
                    n = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    stats.append(f"{n} {label}")
                except sqlite3.Error:
                    pass
            if stats:
                out.append(_check("  contents", OK, ", ".join(stats)))
            try:
                open_n = con.execute(
                    "SELECT COUNT(*) FROM findings WHERE status IN "
                    "('open','regressed')").fetchone()[0]
                pend = con.execute(
                    "SELECT COUNT(*) FROM findings WHERE status="
                    "'pending_verification'").fetchone()[0]
                if pend:
                    out.append(_check("  awaiting sign-off", WARN,
                                      f"{pend} finding(s) in pending_verification",
                                      "Confirm with: maishac approve <fingerprint> --by you@example.com"))
                if open_n:
                    out.append(_check("  open findings", WARN, f"{open_n} open or regressed"))
            except sqlite3.Error:
                pass
        con.close()
    except sqlite3.Error as e:
        out.append(_check("memory database", ERROR, f"cannot open: {e}",
                          "The file may be corrupt or locked by another process."))

    gi = root / ".gitignore"
    ignored = gi.exists() and any(
        ln.strip().rstrip("/") in (".maishac", "**/.maishac")
        for ln in gi.read_text("utf-8", errors="replace").splitlines())
    out.append(_check("  .maishac gitignored", OK if ignored else WARN,
                      "yes" if ignored else "not listed in .gitignore",
                      "" if ignored else
                      "memory.db is local state, not source - add '.maishac/' to .gitignore."))
    return out


# ------------------------------------------------------------------ assembly
def diagnose(root: str | Path | None = None) -> dict:
    root = Path(root or os.getcwd()).resolve()
    analyzer_checks, usable = _analyzers()
    groups = [
        {"group": "Environment", "checks": _environment()},
        {"group": "Analyzers", "checks": analyzer_checks},
        {"group": "Rule coverage on this machine", "checks": _coverage_impact(usable)},
        {"group": "Knowledge base", "checks": _knowledge_base()},
        {"group": "Project", "checks": _project(root)},
    ]
    flat = [c for g in groups for c in g["checks"]]
    return {
        "project": str(root),
        "version": __version__,
        "groups": groups,
        "summary": {
            "ok": sum(1 for c in flat if c["status"] == OK),
            "warnings": sum(1 for c in flat if c["status"] == WARN),
            "errors": sum(1 for c in flat if c["status"] == ERROR),
        },
        "healthy": not any(c["status"] == ERROR for c in flat),
    }


def render(report: dict) -> str:
    L = [f"maishac {report['version']} at {report['project']}", ""]
    for g in report["groups"]:
        L.append(g["group"])
        for c in g["checks"]:
            L.append(f"  {_ICON[c['status']]} {c['name']}: {c['detail']}")
            if c["hint"] and c["status"] != OK:
                L.append(f"      -> {c['hint']}")
        L.append("")
    s = report["summary"]
    L.append(f"{s['ok']} ok, {s['warnings']} warning(s), {s['errors']} error(s)")
    if not report["healthy"]:
        L.append("Errors above will degrade or block compliance work.")
    elif s["warnings"]:
        L.append("Usable, but coverage is narrower than it could be - see warnings.")
    else:
        L.append("All checks passed.")
    return "\n".join(L)
