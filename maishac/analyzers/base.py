"""Analyzer plugin interface.

Every evidence source (native lexer, cppcheck, clang-tidy, compiler) subclasses
Analyzer and yields normalized Finding objects. The harness merges and
deduplicates them by fingerprint so overlapping tools reinforce rather than
duplicate each other.
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from ..model import Finding

C_EXTENSIONS = {".c", ".h"}


def collect_c_files(paths: list[str], root: Path) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        pth = (root / p) if not Path(p).is_absolute() else Path(p)
        if pth.is_dir():
            out.extend(sorted(f for f in pth.rglob("*") if f.suffix in C_EXTENSIONS))
        elif pth.suffix in C_EXTENSIONS and pth.exists():
            out.append(pth)
    # dedupe preserving order
    seen, uniq = set(), []
    for f in out:
        r = f.resolve()
        if r not in seen:
            seen.add(r)
            uniq.append(f)
    return uniq


class Analyzer(ABC):
    name: str = "base"
    requires: str | None = None  # executable dependency, if any

    def available(self) -> bool:
        return self.requires is None or shutil.which(self.requires) is not None

    @abstractmethod
    def analyze(self, files: list[Path], root: Path) -> list[Finding]:
        ...

    @staticmethod
    def _run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
