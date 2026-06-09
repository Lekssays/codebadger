"""Tests for the dependency-aware /health status model.

Covers the up/partial/down aggregation truth table and the liveness probes that
feed it (PostgresDBManager.ping / coordinator.ping). The full /health response
shape is exercised in tests/test_main.py.
"""

import os

import pytest

import main


def _deps(joern="up", postgres="up", redis="up", docker="up", cpg_queue="up"):
    return {"joern": joern, "postgres": postgres, "redis": redis,
            "docker": docker, "cpg_queue": cpg_queue}


class TestAggregateStatus:
    def test_all_up(self):
        assert main._aggregate_status(_deps()) == "up"

    @pytest.mark.parametrize("dep", ["postgres", "redis", "docker", "joern"])
    def test_critical_down_is_down(self, dep):
        assert main._aggregate_status(_deps(**{dep: "down"})) == "down"

    def test_joern_partial_is_partial(self):
        assert main._aggregate_status(_deps(joern="partial")) == "partial"

    def test_queue_full_is_partial(self):
        assert main._aggregate_status(_deps(cpg_queue="partial")) == "partial"

    def test_noncritical_down_is_partial_not_down(self):
        # cpg_queue is not critical: its loss degrades, but isn't a full outage.
        assert main._aggregate_status(_deps(cpg_queue="down")) == "partial"

    def test_critical_down_outranks_partial(self):
        assert main._aggregate_status(_deps(postgres="down", joern="partial")) == "down"


class TestProbes:
    def test_postgres_ping_error_path_does_not_raise(self):
        from src.utils.postgres_db_manager import PostgresDBManager
        # Unreachable DSN -> ping returns ok=False with an error, never raises.
        m = PostgresDBManager("postgresql://nobody@127.0.0.1:1/none")
        result = m.ping()
        assert result["ok"] is False and "error" in result

    @pytest.mark.skipif(not os.getenv("CODEBADGER_TEST_PG_DSN"),
                        reason="set CODEBADGER_TEST_PG_DSN for the Postgres happy path")
    def test_postgres_ping_ok(self):
        from src.utils.postgres_db_manager import PostgresDBManager
        m = PostgresDBManager(os.getenv("CODEBADGER_TEST_PG_DSN"))
        result = m.ping()
        assert result["ok"] is True and "latency_ms" in result

    @pytest.mark.skipif(not os.getenv("CODEBADGER_TEST_REDIS_URL"),
                        reason="set CODEBADGER_TEST_REDIS_URL for the Redis happy path")
    def test_redis_coordinator_ping_ok(self):
        from src.services.coordination import RedisCoordinator
        c = RedisCoordinator(os.getenv("CODEBADGER_TEST_REDIS_URL"))
        result = c.ping()
        assert result["ok"] is True and result["backend"] == "redis"


@pytest.mark.asyncio
async def test_run_probe_timeout_returns_error():
    """A probe that exceeds its timeout resolves to ok=False, not a hang."""
    import time
    result = await main._run_probe(lambda: time.sleep(5), timeout=0.1)
    assert result["ok"] is False and "error" in result
