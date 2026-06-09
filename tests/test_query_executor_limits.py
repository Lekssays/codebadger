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
