"""Phase-3c multi-process pool: two JoernServerManager instances sharing Redis.

Docker is mocked (no real Joern containers); these validate the cross-process
coordination — shared reservation ledger, warm-worker discovery, single-spawn,
and global LRU eviction. The Redis tests need a server: set
CODEBADGER_TEST_REDIS_URL to run them.
"""

import os
from unittest.mock import MagicMock

import pytest

import src.services.joern_server_manager as jsm
from src.config import load_config

REDIS_URL = os.getenv("CODEBADGER_TEST_REDIS_URL")
redis_only = pytest.mark.skipif(not REDIS_URL, reason="set CODEBADGER_TEST_REDIS_URL to run Redis tests")


def _make_manager(monkeypatch, budget_mb, redis_url):
    monkeypatch.setenv("JOERN_WORKER_MODE", "pool")
    monkeypatch.setenv("JOERN_MEMORY_BUDGET_MB", str(budget_mb))
    fake = MagicMock()
    fake.containers.get.side_effect = jsm.NotFound("absent")
    fake.containers.list.return_value = []
    monkeypatch.setattr(jsm.docker, "from_env", lambda: fake)
    m = jsm.JoernServerManager(config=load_config(), redis_url=redis_url)
    # Stub the Docker-/network-touching bits so we exercise only coordination.
    m._wait_for_server = lambda port, timeout=120: True
    m._port_healthy = lambda port: True
    m._plan_server = lambda h: (2, 3072)  # tier-S: 3072 MB reservation each
    return m, fake


def test_pool_without_redis_is_in_process(monkeypatch):
    m, _ = _make_manager(monkeypatch, 6144, redis_url="")
    assert m._redis_pool is None  # no REDIS_URL -> single-process pool state


@redis_only
def test_cross_process_discovery_admission_and_eviction(monkeypatch):
    m1, _f1 = _make_manager(monkeypatch, 6144, REDIS_URL)  # budget fits two 3072 MB servers
    m2, f2 = _make_manager(monkeypatch, 6144, REDIS_URL)
    assert m1._redis_pool is not None and m2._redis_pool is not None
    for k in m1._redis_pool.r.keys("cb:pool:*"):
        m1._redis_pool.r.delete(k)

    # m1 spawns h1; m2 discovers it via the shared registry and adopts it
    # (no second container).
    p1 = m1.spawn_server("h1")
    assert p1 and m2.get_server_port("h1") == p1
    assert m2.spawn_server("h1") == p1
    f2.containers.run.assert_not_called()

    # Shared reservation ledger is visible to both.
    assert m1._redis_pool.total_reserved_mb() == 3072
    assert m2._redis_pool.total_reserved_mb() == 3072

    # m2 spawns h2 -> ledger at budget (6144).
    p2 = m2.spawn_server("h2")
    assert p2 != p1
    assert m2._redis_pool.total_reserved_mb() == 6144

    # h3 needs room -> global LRU eviction removes the oldest (h1), even though
    # m1 (not m3-the-spawner) originally started it.
    p3 = m1.spawn_server("h3")
    assert m1._redis_pool.get_port("h1") is None        # h1 evicted globally
    assert m1._redis_pool.total_reserved_mb() == 6144    # h2 + h3
    assert set(m1.get_running_servers()) == {"h2", "h3"}


@redis_only
def test_make_room_purges_stale_ledger_entry(monkeypatch):
    """A stale entry (reserved + LRU, no registry port) — e.g. a crash between
    reserve and set_port — must be purged by make-room, not spun on forever."""
    m, _ = _make_manager(monkeypatch, 4096, REDIS_URL)
    rp = m._redis_pool
    for k in rp.r.keys("cb:pool:*"):
        rp.r.delete(k)

    # Simulate the half-claimed state the old non-atomic spawn could leave.
    rp.reserve("stale", 8192)
    rp.touch("stale")
    assert rp.get_port("stale") is None          # never registered
    assert rp.total_reserved_mb() == 8192

    with rp.admit_lock():
        m._make_room(1024)                        # over budget -> must evict

    assert rp.total_reserved_mb() == 0            # purged, no infinite loop
    assert rp.oldest() is None


@redis_only
def test_claim_and_release_are_atomic(monkeypatch):
    """claim() registers reservation+port+LRU together; release() clears all."""
    m, _ = _make_manager(monkeypatch, 4096, REDIS_URL)
    rp = m._redis_pool
    for k in rp.r.keys("cb:pool:*"):
        rp.r.delete(k)

    rp.claim("h", 14000, 3072)
    assert rp.get_port("h") == 14000
    assert rp.total_reserved_mb() == 3072
    assert rp.oldest() == "h"

    rp.release("h")
    assert rp.get_port("h") is None
    assert rp.total_reserved_mb() == 0
    assert rp.oldest() is None
