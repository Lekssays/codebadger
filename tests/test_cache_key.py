"""Tests for get_cpg_cache_key — branch, build-options (extra), and content keying.

Covers the cache-key changes:
  - github/gitlab `branch` is part of the key (two branches must not collide)
  - caller build options (`extra`: include paths / defines) are part of the key
  - local sources key on a content fingerprint (dedupe across paths; rebuild on change)
"""

from src.tools.core_tools import get_cpg_cache_key

GH = "https://github.com/owner/repo"
GL = "https://gitlab.com/group/sub/repo"


def test_github_branch_changes_key():
    """Two branches of the same repo must produce distinct CPG hashes."""
    default = get_cpg_cache_key("github", GH, "c")
    main = get_cpg_cache_key("github", GH, "c", branch="main")
    dev = get_cpg_cache_key("github", GH, "c", branch="dev")
    assert default != main, "explicit branch must differ from default"
    assert main != dev, "different branches must not collide on one CPG"


def test_github_default_branch_is_stable():
    """No branch given -> stable key (back-compat with existing default-branch CPGs)."""
    assert get_cpg_cache_key("github", GH, "c") == get_cpg_cache_key("github", GH, "c")


def test_gitlab_branch_changes_key():
    """Branch keying also applies to gitlab URLs (same source_type='github')."""
    a = get_cpg_cache_key("github", GL, "c", branch="v2")
    b = get_cpg_cache_key("github", GL, "c", branch="v3")
    assert a != b


def test_local_ignores_branch():
    """branch is a remote-revision selector; it must not affect local source keys."""
    base = get_cpg_cache_key("local", "/src", "c", content="abc")
    with_branch = get_cpg_cache_key("local", "/src", "c", content="abc", branch="dev")
    assert base == with_branch


def test_extra_build_options_change_key():
    """include paths / defines (extra) produce a distinct CPG."""
    plain = get_cpg_cache_key("local", "/src", "c", content="abc")
    with_inc = get_cpg_cache_key("local", "/src", "c", content="abc", extra="inc=include,_build")
    with_def = get_cpg_cache_key("local", "/src", "c", content="abc", extra="def=LIBXML_CATALOG_ENABLED")
    assert plain != with_inc
    assert with_inc != with_def


def test_local_content_dedupes_across_paths():
    """Identical content at different paths => same key (dedupe)."""
    a = get_cpg_cache_key("local", "/path/one", "c", content="IDENTICAL")
    b = get_cpg_cache_key("local", "/path/two", "c", content="IDENTICAL")
    assert a == b


def test_local_content_change_rebuilds():
    """Changed content => new key (no stale-CPG reuse)."""
    a = get_cpg_cache_key("local", "/src", "c", content="v1")
    b = get_cpg_cache_key("local", "/src", "c", content="v2")
    assert a != b


def test_local_without_content_is_path_based():
    """Fallback when fingerprinting unavailable: distinct paths => distinct keys."""
    a = get_cpg_cache_key("local", "/path/one", "c")
    b = get_cpg_cache_key("local", "/path/two", "c")
    assert a != b


def test_commit_hash_changes_key():
    a = get_cpg_cache_key("github", GH, "c")
    b = get_cpg_cache_key("github", GH, "c", commit_hash="deadbeef")
    assert a != b


def test_snippet_keys_on_content_not_label():
    """Snippets dedupe on code content regardless of the label/source_path."""
    a = get_cpg_cache_key("snippet", "label-a", "c", content="int main(){}")
    b = get_cpg_cache_key("snippet", "label-b", "c", content="int main(){}")
    c = get_cpg_cache_key("snippet", "label-a", "c", content="int other(){}")
    assert a == b
    assert a != c


def test_key_is_16_hex_chars():
    k = get_cpg_cache_key("github", GH, "c", branch="x")
    assert len(k) == 16
    int(k, 16)  # raises if not hex
