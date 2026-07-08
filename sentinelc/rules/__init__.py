"""Unified rule registry across MISRA C:2012, BARR-C:2018 and CERT C.

Responsibilities:
  * load + index all rule metadata shipped with the package
  * resolve fuzzy rule identifiers ("21.3", "misra 21.3", "STR31-C", "barr 1.3a")
  * expose the cross-standard equivalence graph so one fix can be credited
    against every standard it satisfies
"""

from __future__ import annotations

import json
import re
from importlib import resources
from typing import Optional

_FILES = {
    "MISRA-C:2012": "misra_c_2012.json",
    "BARR-C:2018": "barr_c_2018.json",
    "CERT-C": "cert_c.json",
}

_SEV_DEFAULT = {"mandatory": "blocker", "required": "critical", "advisory": "minor"}


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, dict] = {}   # canonical_id -> metadata
        self._by_standard: dict[str, list[str]] = {}
        for standard, fname in _FILES.items():
            data = json.loads(
                resources.files("sentinelc.rules").joinpath(fname).read_text("utf-8")
            )
            ids = []
            for rid, meta in data["rules"].items():
                canonical = self._canonical(standard, rid)
                meta = dict(meta)
                meta["id"] = canonical
                meta["standard"] = standard
                meta.setdefault("severity", "major")
                self._rules[canonical] = meta
                ids.append(canonical)
            self._by_standard[standard] = ids

    @staticmethod
    def _canonical(standard: str, rid: str) -> str:
        if standard == "MISRA-C:2012":
            return f"MISRA-C:2012 {rid}"
        if standard == "BARR-C:2018":
            return f"BARR-C {rid}"
        return f"CERT {rid}"

    # ------------------------------------------------------------------ lookup
    def resolve(self, query: str) -> Optional[dict]:
        """Resolve a possibly-informal rule reference to metadata."""
        q = query.strip()
        if q in self._rules:
            return self._rules[q]
        qn = q.lower().replace("misra-c:2012", "").replace("misra", "") \
              .replace("barr-c", "").replace("barr", "").replace("cert", "").strip(" :")
        if qn.startswith("rule "):
            qn = qn[5:].strip()
        elif qn.startswith("rule"):
            qn = qn[4:].strip()
        # CERT style: STR31-C
        m = re.fullmatch(r"([a-z]{3}\d{2}-c)", qn)
        if m:
            return self._rules.get(f"CERT {m.group(1).upper()}")
        # MISRA rule/dir numbers
        m = re.fullmatch(r"(dir\s*)?(\d+\.\d+)", qn)
        if m:
            num = m.group(2)
            for cand in (f"MISRA-C:2012 Rule {num}", f"MISRA-C:2012 Dir {num}"):
                if cand in self._rules:
                    return self._rules[cand]
        # BARR style: 1.3a
        m = re.fullmatch(r"(\d+\.\d+[a-z]?)", qn)
        if m and f"BARR-C {m.group(1)}" in self._rules:
            return self._rules[f"BARR-C {m.group(1)}"]
        # substring fallback over ids
        for rid in self._rules:
            if q.lower() in rid.lower():
                return self._rules[rid]
        return None

    def cross_refs(self, rule_id: str) -> list[str]:
        meta = self._rules.get(rule_id) or self.resolve(rule_id)
        if not meta:
            return []
        out = []
        for ref in meta.get("cross", []):
            r = self.resolve(ref)
            if r:
                out.append(r["id"])
        return out

    def search(self, text: str, limit: int = 10) -> list[dict]:
        t = text.lower()
        hits = [m for m in self._rules.values()
                if t in m["id"].lower() or t in m.get("summary", "").lower()
                or t in m.get("fix", "").lower()]
        return hits[:limit]

    def all_ids(self, standard: str | None = None) -> list[str]:
        if standard:
            return list(self._by_standard.get(standard, []))
        return list(self._rules)

    def get(self, rule_id: str) -> Optional[dict]:
        return self._rules.get(rule_id)


REGISTRY = RuleRegistry()
