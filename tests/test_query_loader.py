"""Unit tests for QueryLoader placeholder substitution / coercion.

Focus on the bare-numeric and bare-boolean placeholders that are interpolated
into the Scala query OUTSIDE a string literal (line numbers, node ids, the
program-slice booleans). These must be coerced to int/bool — string-escaping
them would let a non-numeric value land as a raw Scala token (a syntax break or
an injection), so a bad value must fail fast.
"""

import pytest

from src.tools.queries import QueryLoader
from src.defaults import MAX_RESULT_ROWS


def test_int_placeholder_coerced_to_bare_integer():
    q = QueryLoader.load("taint_flows", source_line=42, sink_line=7,
                         source_node_id=12345, sink_node_id=-1,
                         source_file="a.c", sink_file="b.c", max_results=10)
    assert "val sourceLine = 42" in q
    assert "val sinkLine = 7" in q
    assert "val sourceNodeId = 12345L" in q
    assert "val sinkNodeId = -1L" in q
    # String placeholders are still escaped inside their quotes.
    assert 'val sourceFile = "a.c"' in q


@pytest.mark.parametrize("bad", ["1; cpg.method.l", "0)})//", "abc", "", "1.5", None])
def test_int_placeholder_rejects_non_integer(bad):
    with pytest.raises(ValueError, match="must be an integer"):
        QueryLoader.load("taint_flows", source_line=bad, sink_line=1,
                         source_node_id=-1, sink_node_id=-1,
                         source_file="a.c", sink_file="b.c", max_results=10)


def test_string_valued_integer_is_accepted():
    # A digit string is fine — it coerces cleanly.
    q = QueryLoader.load("taint_flows", source_line="42", sink_line="7",
                         source_node_id="5", sink_node_id="-1",
                         source_file="a.c", sink_file="b.c", max_results=10)
    assert "val sourceLine = 42" in q


def test_bool_placeholders_render_lowercase_scala():
    q = QueryLoader.load("program_slice", line_num=10, max_depth=5,
                         include_backward=True, include_forward=False,
                         include_control_flow=True)
    assert "val includeBackward = true" in q
    assert "val includeForward = false" in q
    assert "val includeControlFlow = true" in q
    # A Python bool must NOT render as "True"/"False" (invalid Scala).
    assert "True" not in q.split("includeBackward")[1].split("\n")[0]


def test_bool_placeholder_accepts_lowercased_strings():
    q = QueryLoader.load("program_slice", line_num=1, max_depth=1,
                         include_backward="true", include_forward="false",
                         include_control_flow="true")
    assert "val includeBackward = true" in q
    assert "val includeForward = false" in q


def test_bool_placeholder_rejects_garbage():
    with pytest.raises(ValueError, match="must be a boolean"):
        QueryLoader.load("program_slice", line_num=1, max_depth=1,
                         include_backward="maybe", include_forward=False,
                         include_control_flow=True)


def test_numeric_ceiling_still_clamps():
    q = QueryLoader.load("use_after_free", filename="", limit=10 ** 9)
    assert f"val maxResults = {MAX_RESULT_ROWS}" in q


def test_string_placeholder_still_escaped():
    # A filename with a quote must be escaped, not break out of the literal.
    q = QueryLoader.load("use_after_free", filename='a".c', limit=5)
    assert r'\"' in q  # the embedded quote is escaped
