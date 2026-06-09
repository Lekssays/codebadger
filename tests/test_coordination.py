"""Tests for cross-process coordination: per-CPG query lock (Redis).

Redis is mandatory, so the only coordinator is RedisCoordinator. The Redis tests
need a real server — set CODEBADGER_TEST_REDIS_URL (e.g. redis://localhost:56379/0)
to run them; skipped otherwise.
"""

import os
import threading
import time

import pytest

from src.services.coordination import QueryLockTimeout, make_coordinator

REDIS_URL = os.getenv("CODEBADGER_TEST_REDIS_URL")
redis_only = pytest.mark.skipif(not REDIS_URL, reason="set CODEBADGER_TEST_REDIS_URL to run Redis tests")


def test_make_coordinator_requires_redis_url():
    # Redis is mandatory: an empty URL fails fast instead of degrading silently.
    with pytest.raises(RuntimeError, match="REDIS_URL is required"):
        make_coordinator("")
    with pytest.raises(RuntimeError, match="REDIS_URL is required"):
        make_coordinator(None)


def test_make_coordinator_unreachable_redis_raises():
    # Unreachable Redis -> raise (fail-fast boot), no in-process fallback.
    with pytest.raises(Exception):
        make_coordinator("redis://127.0.0.1:1/0")


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
