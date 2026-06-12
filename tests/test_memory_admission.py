"""Unit tests for the memory-aware Joern admission ledger and tiered heaps.

These exercise the Phase-1 logic in JoernServerManager without Docker: heap
parsing/rewriting, CPG-size -> tier planning, and the eviction decisions in
_make_room (memory budget, port-pool pressure, and the legacy count cap).
"""

import types

import pytest

from src.config import load_config
from src.models import SessionStatus
from src.services.joern_server_manager import JoernServerManager
from src.utils.recommend import tier_for_cpg_size_gb


@pytest.fixture
def manager(monkeypatch):
    monkeypatch.setenv("JOERN_MEMORY_BUDGET_MB", "20480")  # 20 GB
    return JoernServerManager(config=load_config())


def _stub_evict(manager):
    """Replace _evict with a tracker that mutates the in-memory ledger only."""
    evicted = []

    def _evict(codebase_hash):
        evicted.append(codebase_hash)
        manager._lru.pop(codebase_hash, None)
        manager._reservations.pop(codebase_hash, None)
        manager._ports.pop(codebase_hash, None)

    manager._evict = _evict
    return evicted


def test_default_heap_parsing(manager):
    assert manager._default_heap_gb() == 4  # from default -Xmx4G


def test_java_opts_rewrites_xmx_and_clamps_xms(manager):
    small = manager._java_opts_for(2)
    assert "-Xmx2G" in small and "-Xms2G" in small
    big = manager._java_opts_for(28)
    assert "-Xmx28G" in big and "-Xms2G" in big  # -Xms clamped to <= 2G


@pytest.mark.parametrize("size_gb,exp_heap", [(0.5, 2), (2.0, 6), (8.0, 16), (20.0, 28)])
def test_plan_server_maps_size_to_tier(manager, monkeypatch, size_gb, exp_heap):
    monkeypatch.setattr(manager, "_cpg_size_gb", lambda h: size_gb)
    heap, reserve_mb = manager._plan_server("h1")
    assert heap == exp_heap
    assert reserve_mb == tier_for_cpg_size_gb(size_gb).container_cap_gb * 1024


def test_plan_server_unknown_size_uses_default_heap(manager, monkeypatch):
    monkeypatch.setattr(manager, "_cpg_size_gb", lambda h: None)
    heap, reserve_mb = manager._plan_server("h1")
    assert heap == 4 and reserve_mb == (4 + 1) * 1024


def test_cpg_size_gb_reads_file(manager, tmp_path):
    f = tmp_path / "cpg.bin"
    f.write_bytes(b"x" * 1024)
    manager.codebase_tracker = types.SimpleNamespace(
        get_codebase=lambda h: types.SimpleNamespace(cpg_path=str(f))
    )
    assert manager._cpg_size_gb("h1") == pytest.approx(1024 / (1024 ** 3))


def test_make_room_evicts_until_budget_fits(manager):
    manager._memory_budget_mb = 20480  # 20 GB
    for h in ["a", "b", "c"]:  # 3 x 8 GB reserved = 24 GB
        manager._reservations[h] = 8192
        manager._lru[h] = None
    evicted = _stub_evict(manager)
    manager._make_room(8192)  # need another 8 GB
    # 24+8=32 > 20 -> evict a (->16+8=24>20) -> evict b (->8+8=16<=20) -> stop
    assert evicted == ["a", "b"]
    assert manager._current_reserved_mb() == 8192


def test_make_room_evicts_on_port_pressure(manager, monkeypatch):
    manager._memory_budget_mb = 10 ** 9  # memory effectively unlimited
    for h in ["a", "b"]:
        manager._reservations[h] = 1024
        manager._lru[h] = None
    counts = iter([0, 1])  # pool exhausted, then one free after eviction
    monkeypatch.setattr(manager.port_manager, "available_count", lambda: next(counts))
    evicted = _stub_evict(manager)
    manager._make_room(1024)
    assert evicted == ["a"]


def test_legacy_count_cap_when_budget_disabled():
    m = JoernServerManager(config=load_config(), max_active_servers=2)
    m._memory_budget_mb = 0
    for i, h in enumerate(["a", "b"]):
        m._ports[h] = 13371 + i
        m._lru[h] = None
    evicted = _stub_evict(m)
    m._make_room(0)  # at the count cap (2 >= 2) -> evict exactly one
    assert len(evicted) == 1


# --- Redis pool: container teardown is deferred off the admit lock (HIGH-1) ---


class _FakeRedisPool:
    """In-memory stand-in for RedisPoolStore exercising the make-room ledger."""

    def __init__(self):
        self.resv = {}        # hash -> reserved MB
        self.reg = {}         # hash -> host port
        self.workers = {}     # hash -> container name
        self.lru = []         # hashes, oldest first

    def seed(self, h, mb, port):
        self.resv[h] = mb
        self.reg[h] = port
        self.workers[h] = f"codebadger-joern-{h}"
        self.lru.append(h)

    def total_reserved_mb(self):
        return sum(self.resv.values())

    def oldest(self, exclude=()):
        excl = set(exclude)
        for h in self.lru:
            if h not in excl and h in self.resv:
                return h
        return None

    def allocate_port(self, pmin, pmax):
        taken = set(self.reg.values())
        for p in range(pmin, pmax + 1):
            if p not in taken:
                return p
        return None

    def get_worker(self, h):
        return self.workers.get(h)

    def release(self, h):
        self.resv.pop(h, None)
        self.reg.pop(h, None)
        self.workers.pop(h, None)
        if h in self.lru:
            self.lru.remove(h)


def test_redis_make_room_frees_ledger_but_defers_container_teardown(manager, monkeypatch):
    """The Redis make-room loop must release the ledger (so the loop sees
    reclaimed capacity) WITHOUT removing containers under the admit lock."""
    rp = _FakeRedisPool()
    manager._redis_pool = rp
    manager._memory_budget_mb = 20480  # 20 GB
    pmin = manager.port_manager.port_min
    for i, h in enumerate(["a", "b", "c"]):  # 3 x 8 GB = 24 GB reserved
        rp.seed(h, 8192, pmin + i)

    removed = []
    monkeypatch.setattr(manager, "_remove_worker_container", lambda name: removed.append(name))

    victims = manager._make_room(8192)  # need another 8 GB

    # Evicted a then b (24+8>20 -> 16+8>20 -> 8+8<=20), returning them to reap.
    assert [h for h, _ in victims] == ["a", "b"]
    assert [n for _, n in victims] == ["codebadger-joern-a", "codebadger-joern-b"]
    # Ledger reclaimed: only c (8 GB) remains, so the new 8 GB fits the budget.
    assert rp.total_reserved_mb() == 8192
    assert "a" not in rp.resv and "b" not in rp.resv
    # ...but NO container was torn down under the lock — that is deferred.
    assert removed == []


def test_reap_evicted_removes_containers_and_marks_sleeping(manager, monkeypatch):
    removed = []
    monkeypatch.setattr(manager, "_remove_worker_container", lambda name: removed.append(name))
    updates = []
    manager.codebase_tracker = types.SimpleNamespace(
        update_codebase=lambda h, **kw: updates.append((h, kw))
    )

    manager._reap_evicted([("a", "codebadger-joern-a"), ("b", "codebadger-joern-b")])

    assert removed == ["codebadger-joern-a", "codebadger-joern-b"]
    assert [h for h, _ in updates] == ["a", "b"]
    assert all(kw["metadata"]["status"] == SessionStatus.SLEEPING for _, kw in updates)


def test_get_running_servers_does_not_probe_in_shared_mode(manager, monkeypatch):
    """Shared mode returns the believed-live registry without a TCP probe per
    server (the probe loop blocked /health for tens of seconds at scale)."""
    manager._redis_pool = None
    manager._ports = {"a": 13371, "b": 13372}

    probed = []
    monkeypatch.setattr(manager, "is_server_running", lambda h: probed.append(h) or True)
    monkeypatch.setattr(
        manager, "_port_healthy", lambda p: probed.append(p) or True
    )

    servers = manager.get_running_servers()

    assert servers == {"a": 13371, "b": 13372}
    assert probed == []  # no per-server liveness probe was issued


def test_get_running_servers_uses_redis_registry_when_pooled(manager):
    rp = _FakeRedisPool()
    rp.reg = {"x": 14001, "y": 14002}
    rp.running_servers = lambda: dict(rp.reg)
    manager._redis_pool = rp
    assert manager.get_running_servers() == {"x": 14001, "y": 14002}


def test_reap_evicted_continues_when_one_removal_fails(manager, monkeypatch):
    def _remove(name):
        if name == "codebadger-joern-a":
            raise RuntimeError("docker boom")

    monkeypatch.setattr(manager, "_remove_worker_container", _remove)
    manager.codebase_tracker = None
    # Must not raise even though the first removal failed.
    manager._reap_evicted([("a", "codebadger-joern-a"), ("b", "codebadger-joern-b")])
