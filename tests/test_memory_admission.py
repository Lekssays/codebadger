"""Unit tests for the memory-aware Joern admission ledger and tiered heaps.

These exercise the Phase-1 logic in JoernServerManager without Docker: heap
parsing/rewriting, CPG-size -> tier planning, and the eviction decisions in
_make_room (memory budget, port-pool pressure, and the legacy count cap).
"""

import types

import pytest

from src.config import load_config
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
