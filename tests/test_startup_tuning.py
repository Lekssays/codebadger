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
