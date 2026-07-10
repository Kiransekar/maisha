"""Core shared data model for Maisha.

Every analyzer, the memory store, the loop engine and the MCP layer speak
one language: the Finding. A Finding carries a *stable fingerprint* so the
harness can recognize the same defect across edits (line numbers move,
content mostly doesn't) - this is what makes verification and memory work.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(str, Enum):
    # Unified severity across standards.
    # MISRA: mandatory/required/advisory. CERT: L1-L3. BARR-C: rule/guideline.
    BLOCKER = "blocker"      # MISRA mandatory, CERT L1
    CRITICAL = "critical"    # MISRA required,  CERT L2
    MAJOR = "major"          # CERT L3, BARR-C rules
    MINOR = "minor"          # MISRA advisory, BARR-C style guidance
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"blocker": 0, "critical": 1, "major": 2, "minor": 3, "info": 4}[self.value]


class Standard(str, Enum):
    MISRA = "MISRA-C:2012"
    BARR = "BARR-C:2018"
    CERT = "CERT-C"


_WS = re.compile(r"\s+")
_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def _normalize_line(line: str) -> str:
    """Whitespace-insensitive normalization so trivial reformatting does not
    change a finding's identity."""
    return _WS.sub(" ", line.strip())


def compute_fingerprint(rule_id: str, rel_path: str, line_content: str,
                        context_symbol: str = "") -> str:
    """Stable identity of a defect: rule + file + normalized offending line +
    enclosing symbol. Deliberately excludes the line *number*."""
    payload = "\x1f".join([rule_id, rel_path, _normalize_line(line_content), context_symbol])
    return hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class Finding:
    rule_id: str                 # e.g. "MISRA-C:2012 Rule 21.3", "CERT STR31-C", "BARR-C 1.3a"
    standard: str                # Standard enum value
    severity: str                # Severity enum value
    file: str                    # path relative to project root
    line: int
    column: int = 0
    message: str = ""
    analyzer: str = "native"     # which evidence source produced it
    line_content: str = ""       # the offending source line (for fingerprint + agent context)
    context_symbol: str = ""     # enclosing function, if known
    fingerprint: str = ""
    cross_refs: list[str] = field(default_factory=list)  # equivalent rules in other standards
    fix_hint: str = ""           # short remediation guidance for the agent
    code_flow: list = field(default_factory=list)  # data-flow steps [{file,line,message}] from a qualified engine's SARIF codeFlows

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(
                self.rule_id, self.file, self.line_content, self.context_symbol
            )

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        known = {f for f in Finding.__dataclass_fields__}  # type: ignore[attr-defined]
        return Finding(**{k: v for k, v in d.items() if k in known})


_CTRL_LEAD_RE = re.compile(r"^\s*(if|for|while|switch|else|do)\b")
_SIG_TAIL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*$")


def _reconstruct_header(lines: list[str], brace_line_idx: int) -> str:
    """A block's opening '{' identifies *that* brace's owner, but the header
    itself may live on earlier lines — either sharing the brace's line
    ("void f(void) {") or, for long parameter lists, spread across several
    lines with the brace alone on its own line (common Allman-style embedded
    C). Reconstruct the header text by pulling in lines until the parens
    balance, so it can be told apart from a control statement's header."""
    head = lines[brace_line_idx].split("{", 1)[0].strip()
    collected: list[str] = [head] if head else []
    j = brace_line_idx - 1
    if not head:
        while j >= 0 and not lines[j].strip():
            j -= 1
        if j < 0:
            return ""
        collected = [lines[j].strip()]
        j -= 1
    balance = collected[0].count(")") - collected[0].count("(")
    while balance > 0 and j >= 0:
        s = lines[j].strip()
        if not s:
            j -= 1
            continue
        if s.endswith((";", "{", "}")):
            break
        collected.insert(0, s)
        balance += s.count(")") - s.count("(")
        j -= 1
    return " ".join(collected).strip()


def enclosing_function(lines: list[str], idx: int) -> str:
    """Heuristic: walk upward tracking brace nesting to find the *innermost*
    block that actually encloses idx, skipping over control-flow blocks
    (if/for/while/switch/do) rather than matching the first line anywhere
    above that merely looks like a function header. Also reconstructs headers
    split across multiple lines. Good enough for fingerprint context."""
    balance = 0
    i = idx
    while i >= 0:
        balance += lines[i].count("}") - lines[i].count("{")
        if balance < 0:
            header = _reconstruct_header(lines, i)
            if header and not _CTRL_LEAD_RE.match(header):
                m = _SIG_TAIL_RE.search(header)
                if m:
                    return m.group(1)
            # not a function header (a control block, or unrecognized) —
            # treat this level as matched and keep looking for the next one up.
            balance = 0
        i -= 1
    return ""


def relpath(path: str | Path, root: str | Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(path)


def jdump(obj) -> str:
    return json.dumps(obj, indent=2, default=str)
