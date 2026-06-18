"""Tests for _hash_tree_in_process — the content fingerprint behind local CPG cache keying.

Properties that matter for the cache key: deterministic, content-sensitive, path-prefix
independent (so identical trees dedupe), file-order independent, and .git is excluded."""

import os

from src.tools.core_tools import _hash_tree_in_process


def _write(path, data=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(data)


def test_deterministic(tmp_path):
    _write(str(tmp_path / "a.c"), "int a;")
    _write(str(tmp_path / "sub" / "b.c"), "int b;")
    assert _hash_tree_in_process(str(tmp_path)) == _hash_tree_in_process(str(tmp_path))


def test_content_change_changes_hash(tmp_path):
    f = tmp_path / "a.c"
    _write(str(f), "int a;")
    before = _hash_tree_in_process(str(tmp_path))
    _write(str(f), "int a; int extra;")
    assert _hash_tree_in_process(str(tmp_path)) != before


def test_identical_trees_at_different_roots_match(tmp_path):
    """Path-prefix independent => identical content dedupes regardless of location."""
    r1, r2 = tmp_path / "one", tmp_path / "two"
    for r in (r1, r2):
        _write(str(r / "a.c"), "int a;")
        _write(str(r / "inc" / "h.h"), "#define X 1")
    assert _hash_tree_in_process(str(r1)) == _hash_tree_in_process(str(r2))


def test_git_dir_excluded(tmp_path):
    _write(str(tmp_path / "a.c"), "int a;")
    before = _hash_tree_in_process(str(tmp_path))
    _write(str(tmp_path / ".git" / "HEAD"), "ref: refs/heads/main")
    _write(str(tmp_path / ".git" / "objects" / "pack" / "x.pack"), "binary-ish")
    assert _hash_tree_in_process(str(tmp_path)) == before


def test_new_file_changes_hash(tmp_path):
    _write(str(tmp_path / "a.c"), "int a;")
    before = _hash_tree_in_process(str(tmp_path))
    _write(str(tmp_path / "b.c"), "int b;")
    assert _hash_tree_in_process(str(tmp_path)) != before


def test_returns_hex_digest(tmp_path):
    _write(str(tmp_path / "a.c"), "x")
    h = _hash_tree_in_process(str(tmp_path))
    assert isinstance(h, str) and len(h) == 64
    int(h, 16)
