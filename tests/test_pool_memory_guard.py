"""Tests for pool-mode memory coordination: recommender split + over-commit guard.

Ensures the build (joern-server) container cap and the worker reservation ledger
cannot jointly over-commit host RAM in pool mode.
"""

import types

import pytest

import main
from src.utils.recommend import HostSpec, compute

HOST = HostSpec(total_mem_gb=125, cores=64, source="manual")


def test_parse_mem_to_mb():
    assert main._parse_mem_to_mb("100g") == 102400
    assert main._parse_mem_to_mb("512m") == 512
    assert main._parse_mem_to_mb("28g") == 28672
    assert main._parse_mem_to_mb("2048") == 2048   # bare = MB
    assert main._parse_mem_to_mb("4G") == 4096      # case-insensitive
    assert main._parse_mem_to_mb(None) is None
    assert main._parse_mem_to_mb("garbage") is None


def test_recommender_pool_split_invariant():
    shared = compute(HOST, worker_mode="shared")
    pool = compute(HOST, worker_mode="pool")
    # shared: one container holds everything -> cap is the whole budget.
    assert shared.docker_mem_limit_gb == shared.joern_budget_gb
    # pool: build container only builds -> cap is the build reserve.
    assert pool.docker_mem_limit_gb == pool.build_reserve_gb
    # The invariant that prevents host over-commit.
    assert pool.build_container_cap_gb + pool.query_budget_gb == pool.joern_budget_gb


def _pool_cfg(memory_budget_mb):
    return types.SimpleNamespace(
        joern=types.SimpleNamespace(memory_budget_mb=memory_budget_mb, worker_mode="pool")
    )


def test_guard_clamps_when_build_cap_too_large(monkeypatch):
    rec = compute(HOST, worker_mode="pool")
    monkeypatch.setenv("JOERN_MEM_LIMIT", "100g")  # oversized build cap (shared-mode default)
    cfg = _pool_cfg(rec.query_budget_gb * 1024)
    main._guard_pool_memory(cfg, rec)
    expected = rec.joern_budget_gb * 1024 - 100 * 1024
    assert cfg.joern.memory_budget_mb == expected
    # No over-commit: build_cap + worker_budget <= joern_budget.
    assert 100 * 1024 + cfg.joern.memory_budget_mb <= rec.joern_budget_gb * 1024


def test_guard_no_clamp_when_build_cap_sized_correctly(monkeypatch):
    rec = compute(HOST, worker_mode="pool")
    monkeypatch.setenv("JOERN_MEM_LIMIT", f"{rec.build_container_cap_gb}g")
    cfg = _pool_cfg(rec.query_budget_gb * 1024)
    main._guard_pool_memory(cfg, rec)
    assert cfg.joern.memory_budget_mb == rec.query_budget_gb * 1024  # untouched


def test_guard_floors_when_build_cap_exceeds_budget(monkeypatch):
    rec = compute(HOST, worker_mode="pool")
    monkeypatch.setenv("JOERN_MEM_LIMIT", "200g")  # bigger than the whole budget
    cfg = _pool_cfg(rec.query_budget_gb * 1024)
    main._guard_pool_memory(cfg, rec)
    min_worker = min(t.container_cap_gb for t in rec.tiers) * 1024
    assert cfg.joern.memory_budget_mb == min_worker
