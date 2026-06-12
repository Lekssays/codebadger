"""Tests for QueryExecutor resource limits / output safety (DoS hardening)."""

import json
from unittest.mock import MagicMock

from src.services.query_executor import QueryExecutor
from src.defaults import MAX_RESULT_ROWS


def _make_executor():
    # _normalize_query / _execute_via_client only need a constructed instance;
    # the coordinator is required by __init__ but unused by these methods.
    return QueryExecutor(joern_server_manager=MagicMock(), config={}, coordinator=MagicMock())


def test_normalize_query_caps_unbounded_query():
    """A raw query with no limit gets a default .take() ceiling."""
    qe = _make_executor()
    out = qe._normalize_query("cpg.method.l", None)
    assert f".take({MAX_RESULT_ROWS})" in out


def test_normalize_query_clamps_huge_explicit_limit():
    """An absurd caller limit is clamped to the hard ceiling."""
    qe = _make_executor()
    out = qe._normalize_query("cpg.method", 1_000_000_000)
    assert f".take({MAX_RESULT_ROWS})" in out


def test_normalize_query_leaves_size_queries_alone():
    qe = _make_executor()
    out = qe._normalize_query("cpg.method.size", None)
    assert ".take(" not in out
    assert out.endswith(".toString")


def test_execute_via_client_truncates_rows():
    qe = _make_executor()
    client = MagicMock()
    big = [{"i": i} for i in range(MAX_RESULT_ROWS + 50)]
    client.execute_query.return_value = {"success": True, "stdout": json.dumps(big)}

    res = qe._execute_via_client(client, "q", 30)

    assert res.success is True
    assert res.truncated is True
    assert res.row_count == MAX_RESULT_ROWS


def test_execute_via_client_sanitizes_host_paths_in_error():
    qe = _make_executor()
    client = MagicMock()
    client.execute_query.return_value = {
        "success": False,
        "stderr": "boom at /mnt/nvme0/workspace/codebadger/playground/cpgs/abc/cpg.bin",
    }

    res = qe._execute_via_client(client, "q", 30)

    assert res.success is False
    assert "/mnt/nvme0/workspace" not in res.error
    assert "cpg.bin" in res.error

from types import SimpleNamespace
from src.models import SessionStatus


def _executor_with(manager, tracker):
    coord = MagicMock()
    coord.codebase_query_lock.return_value.__enter__ = lambda *_: None
    coord.codebase_query_lock.return_value.__exit__ = lambda *a: False
    return QueryExecutor(joern_server_manager=manager, config={}, codebase_tracker=tracker, coordinator=coord)


def test_execute_query_does_not_dispatch_while_loading():
    """A query for a LOADING codebase returns a retry response, never hitting the JVM."""
    mgr = MagicMock()
    mgr.get_server_port.return_value = None
    tracker = MagicMock()
    tracker.get_codebase.return_value = SimpleNamespace(
        metadata={"status": SessionStatus.LOADING}, cpg_path="/p/cpg.bin"
    )
    qe = _executor_with(mgr, tracker)

    res = qe.execute_query("abc123", "/p/cpg.bin", "cpg.method.l", timeout=30)

    assert res.success is False
    assert res.error_code == "SERVER_UNAVAILABLE"
    assert "loading" in res.error.lower()
    mgr.reactivate.assert_not_called()          # must not reactivate mid-build
    mgr.get_or_create_client.assert_not_called()  # must not dispatch


def test_execute_query_reactivates_ready_zombie():
    """A READY codebase whose worker is gone is reactivated, not failed."""
    mgr = MagicMock()
    mgr.get_server_port.return_value = None
    mgr.reactivate.return_value = 14000
    client = MagicMock()
    client.check_health.return_value = True
    client.execute_query.return_value = {"success": True, "stdout": "[]"}
    mgr.get_or_create_client.return_value = client
    tracker = MagicMock()
    tracker.get_codebase.return_value = SimpleNamespace(
        metadata={"status": SessionStatus.READY}, cpg_path="/p/cpg.bin"
    )
    qe = _executor_with(mgr, tracker)

    res = qe.execute_query("abc123", "/p/cpg.bin", "cpg.method.l", timeout=30)

    mgr.reactivate.assert_called_once_with("abc123", "/p/cpg.bin")
    assert res.success is True
