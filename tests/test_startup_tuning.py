"""Unit tests for src/startup_tuning.py (extracted from main.py)."""

import types

import pytest

from src.startup_tuning import parse_mem_to_mb, guard_pool_memory


@pytest.mark.parametrize("value,expected", [
    ("100g", 100 * 1024),
    ("512m", 512),
    ("2048", 2048),     # bare value treated as MB
    ("100gb", 100 * 1024),
    ("4G", 4 * 1024),
    (None, None),
    ("", None),
    ("garbage", None),
])
def test_parse_mem_to_mb(value, expected):
    assert parse_mem_to_mb(value) == expected


def test_guard_pool_memory_clamps_overcommit(monkeypatch):
    monkeypatch.setenv("JOERN_MEM_LIMIT", "90g")  # build cap 90 GB
    config = types.SimpleNamespace(joern=types.SimpleNamespace(memory_budget_mb=50 * 1024))
    rec = types.SimpleNamespace(
        joern_budget_gb=100, build_container_cap_gb=10, query_budget_gb=10,
        tiers=[types.SimpleNamespace(container_cap_gb=3)],
    )
    # build 90 GB + worker 50 GB > 100 GB budget -> worker clamped to 100-90=10 GB
    guard_pool_memory(config, rec)
    assert config.joern.memory_budget_mb == 10 * 1024


# ── guard_build_concurrency (A3) ──────────────────────────────────────────────

def _cfg(build_workers, build_heap_gb=6):
    return types.SimpleNamespace(
        cpg=types.SimpleNamespace(build_workers=build_workers, build_heap_gb=build_heap_gb)
    )


def test_guard_build_concurrency_clamps_overcommit():
    from src.startup_tuning import guard_build_concurrency
    cfg = _cfg(build_workers=4, build_heap_gb=6)  # 4 × (6+1) = 28 GB
    guard_build_concurrency(cfg, build_limit_mb=24 * 1024)  # fits 24//7 = 3
    assert cfg.cpg.build_workers == 3


def test_guard_build_concurrency_leaves_safe_config_alone():
    from src.startup_tuning import guard_build_concurrency
    cfg = _cfg(build_workers=2, build_heap_gb=6)  # 2 × 7 = 14 GB <= 24
    guard_build_concurrency(cfg, build_limit_mb=24 * 1024)
    assert cfg.cpg.build_workers == 2


def test_guard_build_concurrency_floors_at_one():
    from src.startup_tuning import guard_build_concurrency
    cfg = _cfg(build_workers=4, build_heap_gb=6)
    guard_build_concurrency(cfg, build_limit_mb=4 * 1024)  # one build doesn't even fit
    assert cfg.cpg.build_workers == 1


def test_guard_build_concurrency_noop_when_cap_unknown():
    from src.startup_tuning import guard_build_concurrency
    cfg = _cfg(build_workers=8, build_heap_gb=6)
    guard_build_concurrency(cfg, build_limit_mb=None)
    guard_build_concurrency(cfg, build_limit_mb=0)
    assert cfg.cpg.build_workers == 8  # unchanged
