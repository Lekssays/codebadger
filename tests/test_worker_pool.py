"""Unit tests for Phase-2 pool mode: each CPG runs in its own Docker container.

Docker is mocked, so these verify the orchestration (container run/remove args,
state bookkeeping, error handling) without a daemon.
"""

from unittest.mock import MagicMock

import pytest

import src.services.joern_server_manager as jsm
from src.config import load_config
from src.services.port_manager import PortManager


def test_port_allocation_rotates_instead_of_reusing_lowest():
    """A just-released port must not be the very next port handed out.

    Always returning min(available) republishes the same host port on the next
    spawn, racing Docker's port-mapping teardown / TIME_WAIT and concentrating
    all failures on the first port (14000). Allocation must sweep the range.
    """
    pm = PortManager(port_min=14000, port_max=14002)
    a = pm.allocate_port("a")
    b = pm.allocate_port("b")
    assert (a, b) == (14000, 14001)  # cursor advances, not stuck on min

    # Free the lowest, allocate again: must NOT immediately reuse 14000.
    pm.release_port("a")
    c = pm.allocate_port("c")
    assert c == 14002  # rotated past the freed port
    assert c != a

    # Range still fully reclaimable (wraps around to the freed 14000).
    d = pm.allocate_port("d")
    assert d == 14000
    assert sorted([b, c, d]) == [14000, 14001, 14002]


@pytest.fixture
def pool(monkeypatch):
    monkeypatch.setenv("JOERN_WORKER_MODE", "pool")
    monkeypatch.setenv("JOERN_MEMORY_BUDGET_MB", "0")  # legacy admission keeps the test simple
    fake = MagicMock()
    fake.containers.get.side_effect = jsm.NotFound("absent")  # no stale containers
    fake.containers.list.return_value = []
    monkeypatch.setattr(jsm.docker, "from_env", lambda: fake)
    m = jsm.JoernServerManager(config=load_config())
    m._wait_for_server = lambda port, timeout=120: True  # skip real readiness poll
    return m, fake


def test_pool_construction_uses_worker_port_range_and_cleans_orphans(pool):
    m, fake = pool
    assert m.worker_mode == "pool"
    assert (m.port_manager.port_min, m.port_manager.port_max) == (14000, 14999)
    fake.containers.list.assert_called_once()  # orphan sweep at startup


def test_pool_spawn_runs_capped_container(pool, monkeypatch):
    m, fake = pool
    monkeypatch.setattr(m, "_plan_server", lambda h: (6, 8192))  # M tier
    port = m.spawn_server("abc")
    assert 14000 <= port <= 14999
    assert m._worker_containers["abc"] == "codebadger-joern-abc"
    assert m._ports["abc"] == port
    _, kwargs = fake.containers.run.call_args
    assert kwargs["name"] == "codebadger-joern-abc"
    assert kwargs["mem_limit"] == "8192m"
    assert kwargs["ports"] == {"8080/tcp": ("127.0.0.1", port)}
    assert kwargs["labels"]["codebadger.role"] == "joern-worker"
    assert kwargs["command"][:2] == ["/opt/joern/joern-cli/joern", "--server"]
    assert "JAVA_OPTS" in kwargs["environment"] and "-Xmx6G" in kwargs["environment"]["JAVA_OPTS"]


def test_pool_terminate_removes_container_and_clears_state(pool):
    m, fake = pool
    m._exec_ids["abc"] = "exec-abc"
    m._ports["abc"] = 14000
    m._reservations["abc"] = 8192
    m._worker_containers["abc"] = "codebadger-joern-abc"
    m._lru["abc"] = None
    assert m.terminate_server("abc") is True
    assert "abc" not in m._worker_containers
    assert "abc" not in m._ports
    assert "abc" not in m._reservations


def test_pool_missing_image_raises_and_cleans_up(pool, monkeypatch):
    m, fake = pool
    monkeypatch.setattr(m, "_plan_server", lambda h: (2, 3072))
    fake.containers.run.side_effect = jsm.ImageNotFound("no image")
    with pytest.raises(RuntimeError, match="Worker image"):
        m.spawn_server("zzz")
    assert "zzz" not in m._ports
    assert "zzz" not in m._worker_containers
    assert m.port_manager.available_count() == (14999 - 14000 + 1)  # port released


def test_spawn_guard_blocks_concurrent_same_hash(pool, monkeypatch):
    m, fake = pool
    monkeypatch.setattr(m, "_plan_server", lambda h: (4, 5120))
    m._spawning.add("busy")  # simulate another in-flight spawn for this hash
    with pytest.raises(RuntimeError, match="Spawn already in progress"):
        m.spawn_server("busy")
    # The other spawn's marker is left intact (we didn't own it).
    assert "busy" in m._spawning
    fake.containers.run.assert_not_called()


class _FakePoolStore:
    """In-memory stand-in for RedisPoolStore (resv/registry/worker/lru)."""

    def __init__(self):
        self.resv = {}
        self.reg = {}
        self.worker = {}
        self.lru = []

    def total_reserved_mb(self):
        return sum(self.resv.values())

    def oldest(self, exclude=()):
        excl = set(exclude)
        for h in self.lru:
            if h not in excl:
                return h
        return None

    def get_port(self, h):
        return self.reg.get(h)

    def get_worker(self, h):
        return self.worker.get(h)

    def allocate_port(self, pmin, pmax):
        taken = set(self.reg.values())
        for p in range(pmin, pmax + 1):
            if p not in taken:
                return p
        return None

    def release(self, h):
        self.resv.pop(h, None)
        self.reg.pop(h, None)
        self.worker.pop(h, None)
        if h in self.lru:
            self.lru.remove(h)

    def idle(self, ttl_seconds):  # tests inject the idle set directly
        return list(getattr(self, "_idle", []))


def test_make_room_purges_stale_pool_entry_without_spinning(pool, monkeypatch):
    """A stale Redis ledger entry (reserved + LRU, no registry port) must be
    purged by _make_room, not re-picked forever ('No server found' spin)."""
    m, fake = pool
    store = _FakePoolStore()
    # Stale: reserved + in LRU, but never registered (no port) -> terminate_server
    # returns False, so only the defensive release in _evict can clear it.
    store.resv["stale"] = 8192
    store.lru.append("stale")
    m._redis_pool = store
    m._memory_budget_mb = 4096  # over budget -> the memory loop must evict

    m._make_room(needed_mb=1024)

    assert store.total_reserved_mb() == 0
    assert store.oldest() is None
    assert "stale" not in store.resv


def test_evict_releases_port_back_to_pool(pool, monkeypatch):
    """Evicting a CPG must return its host port to the pool (no port leak)."""
    m, fake = pool
    monkeypatch.setattr(m, "_plan_server", lambda h: (2, 3072))
    total = m.port_manager.available_count()
    port = m.spawn_server("abc")
    assert m.port_manager.available_count() == total - 1
    assert m.port_manager.get_port("abc") == port

    m._evict("abc")

    assert m.port_manager.get_port("abc") is None
    assert m.port_manager.available_count() == total  # port returned


def test_evict_releases_port_even_when_terminate_noops(pool):
    """Defensive: a port allocated but out of sync with _exec_ids is still freed."""
    m, fake = pool
    total = m.port_manager.available_count()
    port = m.port_manager.allocate_port("orphan")  # allocated, but never registered in _exec_ids
    assert m.port_manager.available_count() == total - 1

    m._evict("orphan")  # terminate_server no-ops (not in _exec_ids)

    assert m.port_manager.get_port("orphan") is None
    assert m.port_manager.available_count() == total


def test_idle_candidates_local_mode_picks_stale_only(pool, monkeypatch):
    """Local mode: only workers untouched beyond the TTL are reap candidates."""
    m, fake = pool
    m._idle_ttl_seconds = 600
    now = 1_000_000.0
    monkeypatch.setattr(jsm.time, "time", lambda: now)
    m._ports = {"old": 14000, "fresh": 14001}
    m._last_touch = {"old": now - 700, "fresh": now - 60}
    assert m._idle_candidates() == ["old"]


def test_idle_candidates_redis_mode_delegates(pool):
    """Redis (pool) mode reads idle candidates from the shared LRU ledger."""
    m, fake = pool
    store = _FakePoolStore()
    store._idle = ["h1", "h2"]
    m._redis_pool = store
    assert m._idle_candidates() == ["h1", "h2"]


def test_reaper_disabled_when_ttl_zero(pool):
    m, fake = pool
    m._idle_ttl_seconds = 0
    m.start_reaper()
    assert m._reaper_task is None


def test_shared_mode_does_not_touch_worker_containers(monkeypatch):
    monkeypatch.setenv("JOERN_WORKER_MODE", "shared")
    fake = MagicMock()
    fake.containers.list.return_value = []
    monkeypatch.setattr(jsm.docker, "from_env", lambda: fake)
    m = jsm.JoernServerManager(config=load_config())
    assert m.worker_mode == "shared"
    assert (m.port_manager.port_min, m.port_manager.port_max) == (13371, 13870)
    fake.containers.list.assert_not_called()  # no orphan sweep in shared mode
