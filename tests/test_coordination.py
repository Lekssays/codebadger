"""Tests for Phase-3c coordination: per-CPG query lock (in-process + Redis).

The Redis tests need a real server — set CODEBADGER_TEST_REDIS_URL
(e.g. redis://localhost:56379/0) to run them; skipped otherwise.
"""

import os
import threading
import time

import pytest

from src.services.coordination import (
    InProcessCoordinator,
    QueryLockTimeout,
    make_coordinator,
)

REDIS_URL = os.getenv("CODEBADGER_TEST_REDIS_URL")
redis_only = pytest.mark.skipif(not REDIS_URL, reason="set CODEBADGER_TEST_REDIS_URL to run Redis tests")


def _mutual_exclusion_probe(coord, codebase_hash="h1"):
    """Two threads contend for the same lock; record max concurrent holders."""
    state = {"current": 0, "max": 0}
    mutex = threading.Lock()

    def worker():
        with coord.codebase_query_lock(codebase_hash):
            with mutex:
                state["current"] += 1
                state["max"] = max(state["max"], state["current"])
            time.sleep(0.1)
            with mutex:
                state["current"] -= 1

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return state["max"]


def test_inprocess_serializes_same_codebase():
    coord = InProcessCoordinator()
    assert _mutual_exclusion_probe(coord) == 1  # never two holders at once


def test_inprocess_different_codebases_dont_block():
    coord = InProcessCoordinator()
    order = []

    def worker(h):
        with coord.codebase_query_lock(h):
            order.append(h)
            time.sleep(0.05)

    a = threading.Thread(target=worker, args=("a",))
    b = threading.Thread(target=worker, args=("b",))
    start = time.time()
    a.start(); b.start(); a.join(); b.join()
    # Both ran concurrently -> total < 2x the hold time.
    assert time.time() - start < 0.09
    assert set(order) == {"a", "b"}


def test_make_coordinator_defaults_in_process():
    assert make_coordinator("").backend == "in-process"
    assert make_coordinator(None).backend == "in-process"


def test_make_coordinator_bad_redis_falls_back():
    # Unreachable Redis -> graceful in-process fallback, not a crash.
    assert make_coordinator("redis://127.0.0.1:1/0").backend == "in-process"


@redis_only
def test_redis_serializes_across_clients():
    # Two independent coordinator instances == two processes sharing Redis.
    c1 = make_coordinator(REDIS_URL)
    c2 = make_coordinator(REDIS_URL)
    assert c1.backend == "redis"
    held = []

    def worker(coord, tag):
        with coord.codebase_query_lock("shared-hash"):
            held.append(("enter", tag))
            time.sleep(0.2)
            held.append(("exit", tag))

    t1 = threading.Thread(target=worker, args=(c1, "c1"))
    t2 = threading.Thread(target=worker, args=(c2, "c2"))
    t1.start(); time.sleep(0.02); t2.start(); t1.join(); t2.join()
    # Strict enter/exit interleaving proves mutual exclusion across clients.
    assert held[0][0] == "enter" and held[1][0] == "exit"
    assert held[2][0] == "enter" and held[3][0] == "exit"


@redis_only
def test_redis_lock_times_out_when_held():
    c = make_coordinator(REDIS_URL, lock_timeout=60)
    # Force a short blocking timeout to assert SERVER_BUSY-style failure.
    from src.services.coordination import RedisCoordinator
    busy = RedisCoordinator(REDIS_URL, lock_timeout=60, blocking_timeout=1)
    with c.codebase_query_lock("contended"):
        with pytest.raises(QueryLockTimeout):
            with busy.codebase_query_lock("contended"):
                pass
