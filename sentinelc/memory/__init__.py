"""Persistent project memory (SQLite, stored at <project>/.sentinelc/memory.db).

Memory is what turns a scanner into a harness. Five kinds of memory:

  findings      lifecycle of every defect fingerprint ever seen
                (open -> resolved -> regressed if it comes back)
  fix_attempts  what strategies were tried on each finding and how they went —
                the loop engine uses this to avoid repeating failed approaches
  deviations    formal, justified rule deviations (MISRA-style deviation
                records: scope, rationale, approver, expiry)
  suppressions  per-fingerprint false-positive markers with reasons
  notes         free-form learned knowledge: project conventions, allocator
                names, logging shims, architectural decisions
"""

from __future__ import annotations

import fnmatch
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Optional

from ..model import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  standard TEXT,
  severity TEXT,
  file TEXT,
  line INTEGER,
  message TEXT,
  analyzer TEXT,
  line_content TEXT,
  context_symbol TEXT,
  fix_hint TEXT,
  status TEXT NOT NULL DEFAULT 'open',        -- open|resolved|suppressed|deviated|regressed
  seen_count INTEGER NOT NULL DEFAULT 1,
  regress_count INTEGER NOT NULL DEFAULT 0,
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  resolved_at REAL
);
CREATE TABLE IF NOT EXISTS fix_attempts (
  id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  session_id TEXT,
  strategy TEXT,
  outcome TEXT,          -- pending|resolved|persisting|regressed|abandoned
  notes TEXT,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS deviations (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '*',   -- glob over file paths
  justification TEXT NOT NULL,
  approver TEXT,
  expires REAL,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS suppressions (
  fingerprint TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  topic TEXT,
  content TEXT NOT NULL,
  tags TEXT,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'active',   -- active|converged|budget_exhausted|aborted
  iteration INTEGER NOT NULL DEFAULT 0,
  config TEXT,
  history TEXT,          -- JSON list of iteration snapshots (open counts per iteration)
  started REAL NOT NULL,
  updated REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_attempts_fp ON fix_attempts(fingerprint);
"""


class MemoryStore:
    def __init__(self, project_root: str | Path):
        self.root = Path(project_root).resolve()
        self.dir = self.root / ".sentinelc"
        self.dir.mkdir(exist_ok=True)
        self.db = sqlite3.connect(self.dir / "memory.db")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)
        self.db.commit()

    # ------------------------------------------------------------ scan sync
    def sync_scan(self, findings: list[Finding], scanned_files: list[str]) -> dict:
        """Reconcile a fresh scan against memory.

        Returns a diff: {new, persisting, resolved, regressed, suppressed, deviated}
        (lists of fingerprints). A previously-resolved fingerprint reappearing is
        a *regression* — the loop engine treats those with top priority.
        """
        now = time.time()
        current = {f.fingerprint: f for f in findings}
        diff = {k: [] for k in ("new", "persisting", "resolved", "regressed",
                                 "suppressed", "deviated")}
        cur = self.db.execute("SELECT * FROM findings")
        known = {r["fingerprint"]: dict(r) for r in cur.fetchall()}
        scanned = set(scanned_files)

        for fp, f in current.items():
            if self.is_suppressed(fp):
                diff["suppressed"].append(fp)
                status = "suppressed"
            elif self.matching_deviation(f.rule_id, f.file):
                diff["deviated"].append(fp)
                status = "deviated"
            else:
                status = "open"

            if fp not in known:
                self.db.execute(
                    """INSERT INTO findings (fingerprint, rule_id, standard, severity, file,
                       line, message, analyzer, line_content, context_symbol, fix_hint,
                       status, first_seen, last_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (fp, f.rule_id, f.standard, f.severity, f.file, f.line, f.message,
                     f.analyzer, f.line_content, f.context_symbol, f.fix_hint,
                     status, now, now))
                if status == "open":
                    diff["new"].append(fp)
            else:
                prev = known[fp]
                regressed = prev["status"] == "resolved" and status == "open"
                new_status = "regressed" if regressed else status
                self.db.execute(
                    """UPDATE findings SET status=?, line=?, seen_count=seen_count+1,
                       last_seen=?, regress_count=regress_count+? WHERE fingerprint=?""",
                    (new_status, f.line, now, 1 if regressed else 0, fp))
                if regressed:
                    diff["regressed"].append(fp)
                elif status == "open":
                    diff["persisting"].append(fp)

        # anything known-open in a scanned file but absent now => resolved
        for fp, prev in known.items():
            if fp in current:
                continue
            if prev["status"] in ("open", "regressed") and prev["file"] in scanned:
                self.db.execute(
                    "UPDATE findings SET status='resolved', resolved_at=? WHERE fingerprint=?",
                    (now, fp))
                self.db.execute(
                    "UPDATE fix_attempts SET outcome='resolved' "
                    "WHERE fingerprint=? AND outcome='pending'", (fp,))
                diff["resolved"].append(fp)
        self.db.commit()
        return diff

    # ------------------------------------------------------------- lifecycle
    def open_findings(self, limit: int = 200, severities: list[str] | None = None) -> list[dict]:
        q = "SELECT * FROM findings WHERE status IN ('open','regressed')"
        args: list = []
        if severities:
            q += f" AND severity IN ({','.join('?' * len(severities))})"
            args += severities
        q += (" ORDER BY CASE status WHEN 'regressed' THEN 0 ELSE 1 END,"
              " CASE severity WHEN 'blocker' THEN 0 WHEN 'critical' THEN 1"
              " WHEN 'major' THEN 2 WHEN 'minor' THEN 3 ELSE 4 END, file, line LIMIT ?")
        args.append(limit)
        return [dict(r) for r in self.db.execute(q, args)]

    def get_finding(self, fingerprint: str) -> Optional[dict]:
        r = self.db.execute("SELECT * FROM findings WHERE fingerprint=?",
                            (fingerprint,)).fetchone()
        return dict(r) if r else None

    # ---------------------------------------------------------- fix attempts
    def record_fix_attempt(self, fingerprint: str, session_id: str,
                           strategy: str, notes: str = "") -> str:
        aid = uuid.uuid4().hex[:12]
        self.db.execute(
            "INSERT INTO fix_attempts (id, fingerprint, session_id, strategy, outcome, notes, ts)"
            " VALUES (?,?,?,?,?,?,?)",
            (aid, fingerprint, session_id, strategy, "pending", notes, time.time()))
        self.db.commit()
        return aid

    def close_pending_attempts(self, fingerprint: str, outcome: str) -> None:
        self.db.execute("UPDATE fix_attempts SET outcome=? WHERE fingerprint=? AND outcome='pending'",
                        (outcome, fingerprint))
        self.db.commit()

    def attempts_for(self, fingerprint: str) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM fix_attempts WHERE fingerprint=? ORDER BY ts", (fingerprint,))]

    def failed_strategies(self, fingerprint: str) -> list[str]:
        return [r["strategy"] for r in self.db.execute(
            "SELECT strategy FROM fix_attempts WHERE fingerprint=? "
            "AND outcome IN ('persisting','regressed','abandoned')", (fingerprint,))]

    # ------------------------------------------------------------ deviations
    def add_deviation(self, rule_id: str, scope: str, justification: str,
                      approver: str = "", expires_days: float | None = None) -> str:
        did = uuid.uuid4().hex[:12]
        expires = time.time() + expires_days * 86400 if expires_days else None
        self.db.execute(
            "INSERT INTO deviations (id, rule_id, scope, justification, approver, expires, ts)"
            " VALUES (?,?,?,?,?,?,?)",
            (did, rule_id, scope, justification, approver, expires, time.time()))
        self.db.commit()
        return did

    def matching_deviation(self, rule_id: str, file: str) -> Optional[dict]:
        now = time.time()
        for r in self.db.execute("SELECT * FROM deviations WHERE rule_id=?", (rule_id,)):
            if r["expires"] and r["expires"] < now:
                continue
            if fnmatch.fnmatch(file, r["scope"]):
                return dict(r)
        return None

    def deviations(self) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM deviations ORDER BY ts")]

    # ----------------------------------------------------------- suppressions
    def suppress(self, fingerprint: str, reason: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO suppressions VALUES (?,?,?)",
                        (fingerprint, reason, time.time()))
        self.db.execute("UPDATE findings SET status='suppressed' WHERE fingerprint=?",
                        (fingerprint,))
        self.db.commit()

    def is_suppressed(self, fingerprint: str) -> bool:
        return self.db.execute("SELECT 1 FROM suppressions WHERE fingerprint=?",
                               (fingerprint,)).fetchone() is not None

    # ----------------------------------------------------------------- notes
    def add_note(self, content: str, topic: str = "", tags: str = "") -> str:
        nid = uuid.uuid4().hex[:12]
        self.db.execute("INSERT INTO notes VALUES (?,?,?,?,?)",
                        (nid, topic, content, tags, time.time()))
        self.db.commit()
        return nid

    def search_notes(self, query: str, limit: int = 10) -> list[dict]:
        like = f"%{query}%"
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM notes WHERE content LIKE ? OR topic LIKE ? OR tags LIKE ?"
            " ORDER BY ts DESC LIMIT ?", (like, like, like, limit))]

    def all_notes(self, limit: int = 50) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM notes ORDER BY ts DESC LIMIT ?", (limit,))]

    # --------------------------------------------------------------- sessions
    def create_session(self, config: dict) -> str:
        sid = uuid.uuid4().hex[:12]
        now = time.time()
        self.db.execute("INSERT INTO sessions (id, config, history, started, updated)"
                        " VALUES (?,?,?,?,?)",
                        (sid, json.dumps(config), "[]", now, now))
        self.db.commit()
        return sid

    def get_session(self, sid: str) -> Optional[dict]:
        r = self.db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["config"] = json.loads(d["config"] or "{}")
        d["history"] = json.loads(d["history"] or "[]")
        return d

    def update_session(self, sid: str, *, status: str | None = None,
                       iteration: int | None = None,
                       history: list | None = None) -> None:
        sets, args = ["updated=?"], [time.time()]
        if status is not None:
            sets.append("status=?"); args.append(status)
        if iteration is not None:
            sets.append("iteration=?"); args.append(iteration)
        if history is not None:
            sets.append("history=?"); args.append(json.dumps(history))
        args.append(sid)
        self.db.execute(f"UPDATE sessions SET {', '.join(sets)} WHERE id=?", args)
        self.db.commit()

    def latest_active_session(self) -> Optional[dict]:
        r = self.db.execute(
            "SELECT id FROM sessions WHERE status='active' ORDER BY started DESC LIMIT 1"
        ).fetchone()
        return self.get_session(r["id"]) if r else None

    # ------------------------------------------------------------------ stats
    def stats(self) -> dict:
        by_status = {r["status"]: r["n"] for r in self.db.execute(
            "SELECT status, COUNT(*) n FROM findings GROUP BY status")}
        by_std = {r["standard"]: r["n"] for r in self.db.execute(
            "SELECT standard, COUNT(*) n FROM findings"
            " WHERE status IN ('open','regressed') GROUP BY standard")}
        return {
            "findings_by_status": by_status,
            "open_by_standard": by_std,
            "deviations": self.db.execute("SELECT COUNT(*) n FROM deviations").fetchone()["n"],
            "suppressions": self.db.execute("SELECT COUNT(*) n FROM suppressions").fetchone()["n"],
            "notes": self.db.execute("SELECT COUNT(*) n FROM notes").fetchone()["n"],
            "fix_attempts": self.db.execute("SELECT COUNT(*) n FROM fix_attempts").fetchone()["n"],
        }
