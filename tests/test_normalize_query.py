"""Tests for QueryExecutor._normalize_query — the run_cpgql_query char-explosion fix.

The bug: a trailing `.toJsonPretty` appended to a `++` chain bound only to the LAST operand,
so its String concatenated into the list as List[String | Char] and printed as raw characters.
The fix parenthesises the base query so the serializer applies to the whole expression, while
keeping the JSON output path (the <codebadger_result> marker is reserved for self-emitting
template blocks)."""

from unittest.mock import MagicMock

from src.services.query_executor import QueryExecutor
from src.defaults import MAX_RESULT_ROWS


def _qe():
    return QueryExecutor(joern_server_manager=MagicMock(), config={}, coordinator=MagicMock())


def test_plus_chain_is_parenthesised_as_a_whole():
    """The regression: the entire `++` chain must be wrapped before .take/.toJsonPretty,
    so the serializer can't bind to just the last operand."""
    qe = _qe()
    out = qe._normalize_query("cpg.x.l ++ cpg.y.name.l", None)
    # trailing .l stripped, whole expression parenthesised, then capped + serialized
    assert out.startswith("(cpg.x.l ++ cpg.y.name)"), out
    assert ".take(" in out
    assert out.endswith(".toJsonPretty")
    # the bug signature must NOT appear: a bare `name.toJsonPretty` tail on the chain
    assert not out.replace(" ", "").endswith("name.toJsonPretty")


def test_simple_query_parenthesised_and_serialized():
    qe = _qe()
    out = qe._normalize_query("cpg.method.name(\"f\").code.l", None)
    assert out.startswith("(cpg.method.name(\"f\").code)")
    assert out.endswith(".toJsonPretty")


def test_size_query_uses_toString_no_take():
    qe = _qe()
    out = qe._normalize_query("cpg.method.size", None)
    assert ".take(" not in out
    assert out.endswith(".toString")
    assert out.startswith("(cpg.method.size)")


def test_unbounded_query_capped():
    qe = _qe()
    out = qe._normalize_query("cpg.method.l", None)
    assert f".take({MAX_RESULT_ROWS})" in out


def test_huge_explicit_limit_clamped():
    qe = _qe()
    out = qe._normalize_query("cpg.method", 1_000_000_000)
    assert f".take({MAX_RESULT_ROWS})" in out


def test_marker_block_passthrough_unchanged():
    """Self-emitting analysis templates (own <codebadger_result> envelope) are left as-is."""
    qe = _qe()
    block = '{ val x = cpg.method.l; "<codebadger_result>\\n" + x.mkString + "\\n</codebadger_result>" }'
    assert qe._normalize_query(block, None) == block


def test_block_with_tojson_tail_passthrough():
    qe = _qe()
    block = "{ cpg.method.l.toJsonPretty }"
    assert qe._normalize_query(block, None) == block


def test_trailing_tojsonpretty_is_stripped_then_reapplied_once():
    qe = _qe()
    out = qe._normalize_query("cpg.method.name(\"f\").toJsonPretty", None)
    # exactly one .toJsonPretty, applied to the parenthesised base
    assert out.count(".toJsonPretty") == 1
    assert out.startswith("(cpg.method.name(\"f\"))")
