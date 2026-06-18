"""Tests for _sanitize_build_opt_list — validation of c2cpg include paths / defines."""

import pytest

from src.exceptions import ValidationError
from src.tools.core_tools import _sanitize_build_opt_list


def test_none_and_empty_yield_empty_list():
    assert _sanitize_build_opt_list(None, "include path") == []
    assert _sanitize_build_opt_list([], "define") == []


def test_blanks_are_dropped_and_trimmed():
    assert _sanitize_build_opt_list(["  include  ", "", "   "], "include path") == ["include"]


def test_relative_include_with_dotdot_rejected():
    with pytest.raises(ValidationError, match=r"\.\."):
        _sanitize_build_opt_list(["../../etc"], "include path")
    with pytest.raises(ValidationError):
        _sanitize_build_opt_list(["build/../../x"], "include path")


def test_absolute_include_allowed():
    assert _sanitize_build_opt_list(["/opt/include"], "include path") == ["/opt/include"]


def test_normal_relative_include_kept():
    assert _sanitize_build_opt_list(["include", "_build_asan"], "include path") == ["include", "_build_asan"]


def test_control_characters_rejected():
    with pytest.raises(ValidationError, match="control characters"):
        _sanitize_build_opt_list(["inc\x00lude"], "include path")
    with pytest.raises(ValidationError, match="control characters"):
        _sanitize_build_opt_list(["FOO\x07"], "define")


def test_defines_pass_through():
    assert _sanitize_build_opt_list(["LIBXML_CATALOG_ENABLED", "FOO=1"], "define") == [
        "LIBXML_CATALOG_ENABLED",
        "FOO=1",
    ]


def test_dotdot_only_checked_for_include_paths_not_defines():
    # a define isn't a path, so '..' is not a traversal concern there
    assert _sanitize_build_opt_list(["A..B"], "define") == ["A..B"]
