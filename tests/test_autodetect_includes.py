"""Tests for _autodetect_c_includes — the C/C++ include-dir discovery that lets
generated, feature-macro-gated headers (e.g. libxml2's <libxml/xmlversion.h>, which
defines LIBXML_CATALOG_ENABLED) resolve so #ifdef-gated modules are parsed."""

import os

from src.tools.core_tools import _autodetect_c_includes


def _touch(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").close()


def test_source_root_always_present(tmp_path):
    assert _autodetect_c_includes(str(tmp_path)) == ["."]


def test_finds_include_dir(tmp_path):
    os.makedirs(tmp_path / "include" / "libxml")
    out = _autodetect_c_includes(str(tmp_path))
    assert "." in out
    assert "include" in out


def test_finds_dir_with_config_h(tmp_path):
    _touch(str(tmp_path / "_build" / "config.h"))
    out = _autodetect_c_includes(str(tmp_path))
    assert "_build" in out


def test_finds_dir_with_generated_version_header(tmp_path):
    # mimics _build_asan/libxml/xmlversion.h
    _touch(str(tmp_path / "_build_asan" / "libxml" / "xmlversion.h"))
    out = _autodetect_c_includes(str(tmp_path))
    assert os.path.join("_build_asan", "libxml") in out


def test_git_dir_excluded(tmp_path):
    _touch(str(tmp_path / ".git" / "config.h"))
    out = _autodetect_c_includes(str(tmp_path))
    assert not any(p.startswith(".git") for p in out)


def test_depth_bounded(tmp_path):
    # config.h buried deeper than the depth cap (5) must not be picked up.
    deep = tmp_path / "a" / "b" / "c" / "d" / "e" / "f" / "g"
    _touch(str(deep / "config.h"))
    out = _autodetect_c_includes(str(tmp_path))
    assert os.path.join("a", "b", "c", "d", "e", "f", "g") not in out


def test_result_capped(tmp_path):
    for i in range(40):
        _touch(str(tmp_path / f"inc{i}" / "config.h"))
    out = _autodetect_c_includes(str(tmp_path), max_dirs=10)
    assert len(out) <= 10


def test_no_duplicates(tmp_path):
    _touch(str(tmp_path / "include" / "config.h"))  # both an include dir AND has config.h
    out = _autodetect_c_includes(str(tmp_path))
    assert len(out) == len(set(out))


def test_missing_dir_never_raises(tmp_path):
    # best-effort: a non-existent path returns the root sentinel, no exception
    out = _autodetect_c_includes(str(tmp_path / "does_not_exist"))
    assert out == ["."]
