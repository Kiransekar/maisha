"""Concurrency stress for the shared per-project SQLite memory.

README "Teams & concurrency" promises the DB runs in WAL mode with a busy
timeout so a CI scan and a local session can read/write the same
.maishac/memory.db without hard-blocking, and that `session begin` refuses a
second concurrent session. BENCHMARK-SUITE-REPORT.md §9 flags "no
multi-user/concurrent-session stress test beyond the existing single-assertion
unit test" as a gap. These tests exercise real parallel writers/readers against
one database and assert no lock errors and no lost writes.
"""

from __future__ import annotations

import threading

from maishac.engine import LoopEngine
from maishac.memory import MemoryStore


def test_parallel_writers_no_lock_errors_no_lost_writes(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    writers, per_writer = 8, 40
    errors: list[Exception] = []
    barrier = threading.Barrier(writers)

    def work(wid: int):
        try:
            # Each thread opens its OWN MemoryStore (own sqlite connection), the
            # way separate processes would — this is what WAL + busy_timeout must
            # survive without "database is locked".
            mem = MemoryStore(proj)
            barrier.wait()  # maximize contention: everyone writes at once
            for i in range(per_writer):
                mem.add_note(f"note {wid}-{i}", topic=f"t{wid}", tags="conc")
        except Exception as e:  # noqa: BLE001 — capture, assert outside the thread
            errors.append(e)

    threads = [threading.Thread(target=work, args=(w,)) for w in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent writers raised: {errors!r}"
    # every single write landed — no silent loss under contention
    total = MemoryStore(proj).stats()["notes"]
    assert total == writers * per_writer


def test_reader_and_writer_coexist(tmp_path):
    """A long read loop (a CI scan reporting) must not be starved out by, nor
    hard-block, a concurrent writer (a local session recording attempts)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    seed = MemoryStore(proj)
    for i in range(20):
        seed.add_note(f"seed {i}", tags="seed")

    errors: list[Exception] = []
    stop = threading.Event()

    def reader():
        try:
            mem = MemoryStore(proj)
            while not stop.is_set():
                _ = mem.search_notes("seed", limit=50)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def writer():
        try:
            mem = MemoryStore(proj)
            for i in range(200):
                mem.add_note(f"live {i}", tags="live")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    r = threading.Thread(target=reader)
    w = threading.Thread(target=writer)
    r.start(); w.start()
    w.join(); stop.set(); r.join()

    assert not errors, f"reader/writer coexistence raised: {errors!r}"
    assert MemoryStore(proj).stats()["notes"] == 220


def test_second_session_is_refused_across_engine_instances(tmp_path):
    """Two LoopEngine instances (as two processes would be) must not both hold an
    active session on the same project — the second begin is refused and points
    back at the live session id."""
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "m.c").write_text("int main(void){return 0;}\n")

    a = LoopEngine(proj).begin_session(["src"], {"analyzers": ["native"]})
    assert "session_id" in a

    b = LoopEngine(proj).begin_session(["src"], {"analyzers": ["native"]})
    assert "error" in b
    assert b["active_session_id"] == a["session_id"]

    # ...but --force overrides for the deliberate case
    c = LoopEngine(proj).begin_session(["src"], {"analyzers": ["native"]}, force=True)
    assert "session_id" in c
