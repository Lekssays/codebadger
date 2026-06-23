"""Unit tests for include_globs → exclude-regex scoping construction."""

import re

import pytest

from src.utils.build_scoping import (
    glob_to_path_regex,
    scope_exclude_regex,
    combine_exclude_regexes,
)


def _excluded(regex, path):
    """Frontend semantics: a path is excluded iff the regex full-matches it."""
    return re.match(regex + r"\Z", path) is not None


C_EXTS = ["c", "cc", "cpp", "cxx", "c++", "i"]


class TestGlobToPathRegex:
    def test_dir_prefix_bare_name(self):
        rx = glob_to_path_regex("libavcodec")
        assert re.match(rx + r"\Z", "libavcodec/h264.c")
        assert not re.match(rx + r"\Z", "libavutil/mem.c")

    def test_dir_prefix_trailing_slash(self):
        rx = glob_to_path_regex("src/")
        assert re.match(rx + r"\Z", "src/a/b.c")
        assert not re.match(rx + r"\Z", "test/a.c")

    def test_double_star_suffix(self):
        rx = glob_to_path_regex("libavcodec/**")
        assert re.match(rx + r"\Z", "libavcodec/x/y.c")

    def test_double_star_slash_matches_root(self):
        rx = glob_to_path_regex("**/*.c")
        assert re.match(rx + r"\Z", "main.c")          # zero leading dirs
        assert re.match(rx + r"\Z", "a/b/main.c")      # nested

    def test_single_star_is_segment_bounded(self):
        rx = glob_to_path_regex("src/*.c")
        assert re.match(rx + r"\Z", "src/a.c")
        assert not re.match(rx + r"\Z", "src/sub/a.c")  # * doesn't cross /

    def test_regex_specials_are_escaped(self):
        rx = glob_to_path_regex("a.b+c/**")
        assert re.match(rx + r"\Z", "a.b+c/x.c")
        assert not re.match(rx + r"\Z", "aXbYc/x.c")


class TestScopeExcludeRegex:
    def test_keeps_in_scope_sources_excludes_others(self):
        rx = scope_exclude_regex(["libavcodec/**", "libavutil/**"], C_EXTS)
        assert rx is not None
        # in scope → not excluded
        assert not _excluded(rx, "libavcodec/h264.c")
        assert not _excluded(rx, "libavutil/mem.c")
        # out of scope source → excluded
        assert _excluded(rx, "libavformat/mov.c")
        assert _excluded(rx, "tests/foo.c")

    def test_headers_never_excluded(self):
        rx = scope_exclude_regex(["libavcodec/**"], C_EXTS)
        # An out-of-scope HEADER must stay includable (not excluded).
        assert not _excluded(rx, "libavutil/common.h")
        assert not _excluded(rx, "include/global.hpp")

    def test_non_source_assets_not_excluded(self):
        rx = scope_exclude_regex(["src/**"], C_EXTS)
        assert not _excluded(rx, "docs/readme.md")
        assert not _excluded(rx, "Makefile")

    def test_python_scope(self):
        rx = scope_exclude_regex(["pkg/**"], ["py", "pyi"])
        assert not _excluded(rx, "pkg/mod.py")
        assert _excluded(rx, "other/mod.py")
        assert not _excluded(rx, "pkg/data.json")  # not a source ext

    def test_empty_globs_returns_none(self):
        assert scope_exclude_regex([], C_EXTS) is None
        assert scope_exclude_regex(["", "  "], C_EXTS) is None

    def test_no_exts_returns_none(self):
        assert scope_exclude_regex(["src/**"], []) is None

    def test_result_is_valid_regex(self):
        rx = scope_exclude_regex(["a/**", "b/*.c", "**/*.cpp"], C_EXTS)
        re.compile(rx)  # must not raise


class TestCombineExcludeRegexes:
    def test_combine_junk_and_scope(self):
        junk = r".*/test.*"
        scope = scope_exclude_regex(["src/**"], C_EXTS)
        combined = combine_exclude_regexes([junk, scope])
        re.compile(combined)
        # default-junk excluded even if in scope
        assert _excluded(combined, "src/test_helpers.c") or _excluded(combined, "a/test/x.c")
        # out-of-scope source excluded via the scope alternative
        assert _excluded(combined, "other/a.c")
        # in-scope non-test source kept
        assert not _excluded(combined, "src/main.c")

    def test_none_when_all_empty(self):
        assert combine_exclude_regexes([None, None]) is None

    def test_single_passthrough(self):
        assert combine_exclude_regexes([None, "x.*"]) == "x.*"
