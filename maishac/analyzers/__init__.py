"""Analyzer orchestration: run every available evidence source and merge."""

from __future__ import annotations

from pathlib import Path

from .base import Analyzer, collect_c_files
from .native import NativeAnalyzer
from .cppcheck import CppcheckAnalyzer
from .clang_tidy import ClangTidyAnalyzer
from ..model import Finding

ALL_ANALYZERS: list[type[Analyzer]] = [NativeAnalyzer, CppcheckAnalyzer, ClangTidyAnalyzer]


def available_analyzers(only: list[str] | None = None) -> list[Analyzer]:
    out = []
    for cls in ALL_ANALYZERS:
        inst = cls()
        if only and inst.name not in only:
            continue
        if inst.available():
            out.append(inst)
    return out


def run_scan(paths: list[str], root: Path,
             analyzers: list[str] | None = None,
             include_paths: list[str] | None = None) -> tuple[list[Finding], list[str]]:
    """Run all (or the named) available analyzers over paths.

    include_paths are forwarded to analyzers that compile/parse (cppcheck,
    clang-tidy) as -I flags — without them, headers outside the scanned paths
    (e.g. a project's FreeRTOSConfig.h) are invisible and those analyzers
    misreport "undefined"/"file not found" false positives (see BENCHMARKS.md).

    Returns (deduped findings sorted by severity/file/line, analyzer names used).
    Dedup rule: fingerprint collision keeps the first occurrence but records the
    extra analyzer as reinforcing evidence in the message.
    """
    files = collect_c_files(paths, root)
    active = available_analyzers(analyzers)
    merged: dict[str, Finding] = {}
    used = []
    for an in active:
        used.append(an.name)
        for fnd in an.analyze(files, root, include_paths):
            key = fnd.fingerprint
            if key in merged:
                prior = merged[key]
                if an.name not in prior.analyzer:
                    prior.analyzer = f"{prior.analyzer}+{an.name}"
            else:
                merged[key] = fnd
    findings = sorted(
        merged.values(),
        key=lambda f: ({"blocker": 0, "critical": 1, "major": 2, "minor": 3, "info": 4}
                       .get(f.severity, 5), f.file, f.line),
    )
    return findings, used
