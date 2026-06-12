"""Unit tests for the shared tool helpers (src/tools/_common.py)."""

import types

import pytest

from src.exceptions import ValidationError
from src.tools._common import require_cpg, unwrap_result


def _services(info):
    return {"codebase_tracker": types.SimpleNamespace(get_codebase=lambda h: info)}


def test_require_cpg_returns_info_when_ready():
    info = types.SimpleNamespace(cpg_path="/p/cpg.bin")
    assert require_cpg(_services(info), "a" * 16) is info


def test_require_cpg_raises_when_missing():
    with pytest.raises(ValidationError, match="CPG not found"):
        require_cpg(_services(None), "a" * 16)


def test_require_cpg_raises_when_no_cpg_path():
    info = types.SimpleNamespace(cpg_path=None)
    with pytest.raises(ValidationError, match="CPG not found"):
        require_cpg(_services(info), "a" * 16)


def test_require_cpg_rejects_bad_hash():
    with pytest.raises(ValidationError):
        require_cpg(_services(None), "not-a-valid-hash!!")


class _Result:
    def __init__(self, success, data=None, error=None):
        self.success, self.data, self.error = success, data, error


def test_unwrap_result_failure_returns_error_string():
    assert unwrap_result(_Result(False, error="boom")) == "Error: boom"


def test_unwrap_result_string_data_stripped():
    assert unwrap_result(_Result(True, data="  hi  ")) == "hi"


def test_unwrap_result_list_first_element():
    assert unwrap_result(_Result(True, data=["  x  ", "y"])) == "x"


def test_unwrap_result_unexpected_format():
    out = unwrap_result(_Result(True, data={"k": 1}))
    assert "unexpected format" in out
