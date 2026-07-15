"""
Tests for input validation utilities
"""

from unittest.mock import patch

import pytest

from src.exceptions import ValidationError
from src.utils.validators import (
    hash_query,
    sanitize_path,
    snippet_filename,
    validate_code_snippet,
    validate_cpgql_query,
    validate_git_branch,
    validate_github_token,
    validate_github_url,
    validate_language,
    validate_local_path,
    validate_snippet_label,
    validate_source_type,
    validate_timeout,
    resolve_host_path,
)


class TestValidateSourceType:
    """Test source type validation"""

    def test_valid_source_types(self):
        """Test valid source types"""
        valid_types = ["local", "github", "snippet"]

        for source_type in valid_types:
            # Should not raise
            validate_source_type(source_type)

    def test_invalid_source_type(self):
        """Test invalid source type"""
        with pytest.raises(ValidationError) as exc_info:
            validate_source_type("invalid")

        assert "Invalid source_type 'invalid'" in str(exc_info.value)
        assert "snippet" in str(exc_info.value)


class TestValidateCodeSnippet:
    """Test pasted code snippet validation"""

    def test_valid_snippet(self):
        validate_code_snippet("int main() { return 0; }")

    @pytest.mark.parametrize("bad", [None, "", "   ", "\n\t"])
    def test_empty_snippet_rejected(self, bad):
        with pytest.raises(ValidationError):
            validate_code_snippet(bad)

    def test_oversize_snippet_rejected(self):
        from src.defaults import MAX_SNIPPET_BYTES

        with pytest.raises(ValidationError):
            validate_code_snippet("a" * (MAX_SNIPPET_BYTES + 1))

    def test_null_byte_rejected(self):
        with pytest.raises(ValidationError):
            validate_code_snippet("int main(){}\x00")


class TestValidateGitBranch:
    """Test git branch/ref validation"""

    @pytest.mark.parametrize(
        "ok", [None, "main", "develop", "release/1.2.x", "feature_x-1.0", "v2.0.0"]
    )
    def test_valid_branches(self, ok):
        validate_git_branch(ok)

    @pytest.mark.parametrize(
        "bad",
        [
            "--upload-pack=touch /tmp/pwned",  # classic git arg-injection RCE
            "-x",
            "a b",
            "a..b",
            "a@{0}",
            "/leading",
            "trailing/",
            "feature.lock",
            "a;rm -rf /",
            "a//b",
            "",
            "   ",
        ],
    )
    def test_malicious_branches_rejected(self, bad):
        with pytest.raises(ValidationError):
            validate_git_branch(bad)


class TestValidateGithubToken:
    """Test GitHub token shape validation"""

    @pytest.mark.parametrize("ok", [None, "ghp_abcDEF123", "github_pat_11ABC_def-ghi"])
    def test_valid_tokens(self, ok):
        validate_github_token(ok)

    @pytest.mark.parametrize(
        "bad",
        [
            "tok with space",
            "evil@host",        # would break out of https://<token>@host
            "a/b",
            "user:pass",
            "frag#ment",
            "q?uery",
            "x" * 513,
        ],
    )
    def test_invalid_tokens_rejected(self, bad):
        with pytest.raises(ValidationError):
            validate_github_token(bad)


class TestValidateSnippetLabel:
    """Test snippet label sanitization"""

    def test_empty_returns_empty(self):
        assert validate_snippet_label(None) == ""
        assert validate_snippet_label("") == ""

    def test_strips_control_characters(self):
        assert validate_snippet_label("he\x07llo\nworld") == "helloworld"

    def test_bounds_length(self):
        assert len(validate_snippet_label("a" * 500)) == 256


class TestSnippetFilename:
    """Test snippet filename resolution"""

    def test_default_from_language(self):
        assert snippet_filename("python") == "snippet.py"
        assert snippet_filename("c") == "snippet.c"

    def test_unknown_language_falls_back_to_txt(self):
        assert snippet_filename("ghidra") == "snippet.txt"

    def test_honors_explicit_filename(self):
        assert snippet_filename("c", "parser.c") == "parser.c"

    def test_strips_path_traversal(self):
        assert snippet_filename("c", "../../etc/passwd") == "passwd"
        assert snippet_filename("c", "/abs/path/foo.c") == "foo.c"

    def test_dotdot_only_falls_back(self):
        assert snippet_filename("python", "..") == "snippet.py"

    def test_unsafe_charset_falls_back(self):
        # Names with shell metachars / spaces are not trusted; fall back to default.
        assert snippet_filename("c", "a;rm -rf b.c") == "snippet.c"
        assert snippet_filename("c", "weird name.c") == "snippet.c"


class TestValidateLanguage:
    """Test language validation"""

    def test_valid_languages(self):
        """Test valid programming languages"""
        valid_languages = [
            "java",
            "c",
            "cpp",
            "javascript",
            "python",
            "go",
            "kotlin",
            "csharp",
            "ghidra",
            "jimple",
            "php",
            "ruby",
            "swift",
        ]

        for language in valid_languages:
            # Should not raise
            validate_language(language)

    def test_invalid_language(self):
        """Test invalid programming language"""
        with pytest.raises(ValidationError) as exc_info:
            validate_language("cobol")

        msg = str(exc_info.value)
        assert "Unsupported language 'cobol'" in msg
        # The message must list the accepted ids so the caller can self-correct.
        assert "java" in msg and "swift" in msg


class TestValidateGithubUrl:
    """Test GitHub URL validation"""

    def test_valid_repo_urls(self):
        """Valid github.com / gitlab.com https URLs are accepted."""
        valid_urls = [
            "https://github.com/user/repo",
            "https://github.com/user/repo.git",
            "https://www.github.com/user/repo",
            "https://github.com/user-name/repo_name",
            "https://github.com/user/repo/issues",
            "https://gitlab.com/user/repo",
            "https://gitlab.com/user/repo.git",
            "https://www.gitlab.com/user/repo",
            "https://gitlab.com/group/subgroup/project",  # nested gitlab group
        ]

        for url in valid_urls:
            # Should not raise
            validate_github_url(url)

    def test_invalid_repo_urls(self):
        """Malformed or off-allowlist URLs are rejected."""
        invalid_urls = [
            "https://bitbucket.org/user/repo",  # Wrong domain
            "https://github.com/user",  # Missing repo
            "https://github.com/",  # Incomplete
            "not-a-url",
            "",
            None,
        ]

        for url in invalid_urls:
            with pytest.raises(ValidationError):
                validate_github_url(url)

    def test_ssrf_and_scheme_hardening(self):
        """SSRF / undefined-behavior vectors must all be rejected."""
        malicious = [
            "http://github.com/user/repo",            # non-https scheme
            "git://github.com/user/repo",             # git protocol
            "ssh://git@github.com/user/repo",         # ssh
            "file:///etc/passwd",                     # local file
            "https://github.com@evil.com/user/repo",  # userinfo host smuggling
            "https://user:tok@github.com/user/repo",  # embedded credentials
            "https://github.com:22/user/repo",        # non-default port
            "https://localhost/user/repo",            # internal host
            "https://169.254.169.254/latest/meta",    # cloud metadata endpoint
            "https://github.com.evil.com/user/repo",  # suffix look-alike
            "https://github.com/user/repo\n.git",     # control char injection
        ]

        for url in malicious:
            with pytest.raises(ValidationError):
                validate_github_url(url)

    def test_literal_prefix_gate(self):
        """The string must literally begin with an allowed https://host/ prefix."""
        from src.utils.validators import ALLOWED_REPO_URL_PREFIXES

        # The canonical lowercase prefixes are exactly the four allowed hosts.
        assert ALLOWED_REPO_URL_PREFIXES == (
            "https://github.com/",
            "https://gitlab.com/",
            "https://www.github.com/",
            "https://www.gitlab.com/",
        )

        # Case-variant scheme/host pass urlparse's hostname check but must be
        # rejected by the literal (case-sensitive) prefix gate.
        for url in [
            "HTTPS://github.com/user/repo",
            "https://GitHub.com/user/repo",
            " https://github.com/user/repo",  # leading space (also caught earlier)
        ]:
            with pytest.raises(ValidationError):
                validate_github_url(url)


class TestParseSnippetBlocks:
    """<code language="..."> snippet extraction."""

    def _parse(self, text):
        from src.utils.validators import parse_snippet_blocks
        return parse_snippet_blocks(text)

    def test_single_block(self):
        lang, code = self._parse('<code language="c">int main(){}</code>')
        assert lang == "c"
        assert code == "int main(){}"

    def test_strips_surrounding_newlines(self):
        lang, code = self._parse('<code language="python">\nprint(1)\n</code>')
        assert lang == "python"
        assert code == "print(1)"

    def test_lang_alias_and_single_quotes_and_extra_attrs(self):
        lang, code = self._parse("<code id='x' lang='go' >package main</code>")
        assert lang == "go"
        assert code == "package main"

    def test_case_insensitive_tag_and_attr(self):
        lang, code = self._parse('<CODE LANGUAGE="Java">class A{}</CODE>')
        assert lang == "java"  # lowercased
        assert code == "class A{}"

    def test_multiple_same_language_concatenated(self):
        lang, code = self._parse(
            '<code language="c">int a;</code>\nnoise\n<code language="c">int b;</code>'
        )
        assert lang == "c"
        assert code == "int a;\n\nint b;"

    def test_multiple_languages_rejected(self):
        with pytest.raises(ValidationError):
            self._parse('<code language="c">x</code><code language="go">y</code>')

    def test_empty_body_rejected(self):
        with pytest.raises(ValidationError):
            self._parse('<code language="c">   </code>')

    @pytest.mark.parametrize("text", [None, "", "int main(){}", "<code>no lang</code>"])
    def test_no_tag_returns_none(self, text):
        # No well-formed tag -> caller falls back to raw code + language arg.
        assert self._parse(text) is None


class TestSnippetLanguageInferAndValidate:
    """validate_and_infer_snippet_language + infer_snippet_language."""

    def _vi(self, code, declared=None):
        from src.utils.validators import validate_and_infer_snippet_language
        return validate_and_infer_snippet_language(code, declared)

    def _infer(self, code):
        from src.utils.validators import infer_snippet_language
        return infer_snippet_language(code)

    C_CODE = '#include <stdio.h>\nint main(void){ char b[8]; malloc(8); return 0; }'
    PY_CODE = 'def foo():\n    import os\n    print(os)\n'
    CPP_CODE = '#include <iostream>\nint main(){ std::cout << "x"; }'

    def test_declared_matches_is_returned(self):
        assert self._vi(self.C_CODE, "c") == "c"

    def test_declared_mismatch_refused_with_helpful_message(self):
        from src.exceptions import ValidationError
        with pytest.raises(ValidationError) as e:
            self._vi(self.C_CODE, "python")
        msg = str(e.value)
        assert "does not match" in msg and "language=" in msg  # actionable

    def test_overlapping_family_not_refused(self):
        # cpp code declared as c: c still has signals, so we don't refuse.
        assert self._vi(self.CPP_CODE, "c") == "c"

    def test_infers_when_no_declaration(self):
        assert self._vi(self.PY_CODE) == "python"

    def test_ambiguous_without_declaration_refused(self):
        from src.exceptions import ValidationError
        with pytest.raises(ValidationError) as e:
            self._vi("x = 1")
        assert "Supported languages" in str(e.value)  # lists ids to self-correct

    def test_uninferable_language_accepted_as_declared(self):
        # ghidra/jimple look like other languages but must be trusted as declared.
        assert self._vi(self.C_CODE, "ghidra") == "ghidra"

    def test_empty_code_refused(self):
        from src.exceptions import ValidationError
        with pytest.raises(ValidationError):
            self._vi("   ", "c")

    def test_unsupported_declared_refused(self):
        from src.exceptions import ValidationError
        with pytest.raises(ValidationError):
            self._vi(self.C_CODE, "rust")

    def test_infer_returns_none_when_unsure(self):
        assert self._infer("x = 1") is None
        assert self._infer("") is None


class TestValidateLocalPath:
    """Test local path validation"""

    def test_valid_local_path(self):
        """Test valid local path"""
        # Should not raise - now only checks absolute path
        validate_local_path("/valid/path")

    def test_invalid_local_path_not_absolute(self):
        """Test relative path"""
        with pytest.raises(ValidationError) as exc_info:
            validate_local_path("relative/path")

        assert "Local path must be absolute" in str(exc_info.value)


class TestValidateCpgqlQuery:
    """Test CPGQL query validation"""

    def test_valid_queries(self):
        """Test valid CPGQL queries"""
        valid_queries = [
            "cpg.method.name.l",
            "cpg.call.name('printf').l",
            "cpg.literal.code('SELECT *').l",
            "cpg.file.name.toJson",
            "cpg.method.where(_.name('main')).l",
        ]

        for query in valid_queries:
            # Should not raise
            validate_cpgql_query(query)

    def test_empty_query(self):
        """Test empty query"""
        with pytest.raises(ValidationError) as exc_info:
            validate_cpgql_query("")

        assert "Query must be a non-empty string" in str(exc_info.value)

    def test_none_query(self):
        """Test None query"""
        with pytest.raises(ValidationError) as exc_info:
            validate_cpgql_query(None)

        assert "Query must be a non-empty string" in str(exc_info.value)

    def test_query_too_long(self):
        """Test query that exceeds length limit"""
        long_query = "cpg.method.name.l" * 1000  # Very long query

        with pytest.raises(ValidationError) as exc_info:
            validate_cpgql_query(long_query)

        assert "Query too long" in str(exc_info.value)

    def test_dangerous_queries(self):
        """Test queries with dangerous operations"""
        dangerous_queries = [
            "System.exit(0)",
            "Runtime.getRuntime.exec('rm -rf /')",
            "ProcessBuilder",
            "java.io.File.delete",
        ]

        for query in dangerous_queries:
            with pytest.raises(ValidationError) as exc_info:
                validate_cpgql_query(query)

            assert "potentially dangerous operation" in str(exc_info.value)

    def test_expanded_blocklist_covers_reads_dynload_reflection_network(self):
        """Patterns added after the audit: file reads, $ivy, sys.exit, reflection bypass, aliased process, URI."""
        dangerous = [
            'scala.io.Source.fromFile("/etc/passwd").mkString',  # file read
            'new java.io.FileInputStream("/etc/passwd")',         # file read
            "java.nio.file.Files.readAllBytes(p)",                # file read
            "os.read(p)",                                         # ammonite read
            'import $ivy.`org.x:y:1.0`',                          # dynamic dep load
            "sys.exit(1)",                                        # scala exit
            'import scala.sys.{process => p}; p.stringToProcess("id").!',  # aliased process
            'cls.getMethod("exec")',                              # reflection (getMethod, not getDeclaredMethod)
            'classOf[String].getClassLoader.loadClass("java.lang.Runtime")',  # loadClass
            'java.net.URI("http://x").toURL.openConnection',      # network via URI
        ]
        for q in dangerous:
            with pytest.raises(ValidationError):
                validate_cpgql_query(q)

    def test_legitimate_queries_not_falsely_blocked(self):
        """Common analysis queries must still pass the expanded blocklist."""
        ok = [
            'cpg.method.name("main").l',
            'cpg.call.name("memcpy").l',
            "cpg.method.fullName.l",
            'cpg.literal.code(".*SELECT.*").l',
            "cpg.method.where(_.name(\"parse.*\")).parameter.l",
        ]
        for q in ok:
            validate_cpgql_query(q)


class TestValidateSearchPattern:
    """Test regex/name-filter ReDoS + length guard"""

    def test_empty_is_noop(self):
        from src.utils.validators import validate_search_pattern
        validate_search_pattern(None)
        validate_search_pattern("")

    def test_benign_patterns_pass(self):
        from src.utils.validators import validate_search_pattern
        for ok in [".*parse.*", "foo|bar", "(abc)", "a+", "(a|b)c", "memcpy"]:
            validate_search_pattern(ok)

    @pytest.mark.parametrize("bad", ["(a+)+$", "(a*)*", "(ab|ab)+", "(.*,)+", "(a|a)*"])
    def test_redos_shapes_rejected(self, bad):
        from src.utils.validators import validate_search_pattern
        with pytest.raises(ValidationError):
            validate_search_pattern(bad)

    def test_overlong_pattern_rejected(self):
        from src.utils.validators import validate_search_pattern
        from src.defaults import MAX_SEARCH_PATTERN_LEN
        with pytest.raises(ValidationError):
            validate_search_pattern("a" * (MAX_SEARCH_PATTERN_LEN + 1))


class TestClampInt:
    """Test the numeric clamp helper used for limit / take(n) / depth params"""

    def test_clamps_to_ceiling(self):
        from src.utils.validators import clamp_int
        assert clamp_int(10**9, 10000) == 10000

    def test_clamps_to_floor(self):
        from src.utils.validators import clamp_int
        assert clamp_int(-5, 100) == 1
        assert clamp_int(0, 100, minimum=1) == 1

    def test_non_numeric_uses_default(self):
        from src.utils.validators import clamp_int
        assert clamp_int("nope", 100, default=7) == 7
        assert clamp_int(None, 100) == 1  # falls back to minimum

    def test_in_range_unchanged(self):
        from src.utils.validators import clamp_int
        assert clamp_int(50, 100) == 50


class TestQueryLoaderClamps:
    """QueryLoader clamps caller-supplied numeric placeholders before substitution"""

    def test_limit_clamped_in_take(self):
        from src.tools.queries import QueryLoader
        from src.defaults import MAX_RESULT_ROWS
        q = QueryLoader.load("type_definition", type_name="Foo", limit=10**9)
        assert f".take({MAX_RESULT_ROWS})" in q

    def test_depth_clamped(self):
        from src.tools.queries import QueryLoader
        from src.defaults import MAX_TRAVERSAL_DEPTH
        q = QueryLoader.load("call_graph", method_name="main", depth=99999, direction="outgoing")
        assert f"val maxDepth = {MAX_TRAVERSAL_DEPTH}" in q

    def test_small_values_preserved(self):
        from src.tools.queries import QueryLoader
        q = QueryLoader.load("type_definition", type_name="Foo", limit=10)
        assert ".take(10)" in q


class TestSanitizeErrorText:
    """Test host-path redaction in client-facing error text"""

    def test_redacts_absolute_paths(self):
        from src.utils.validators import sanitize_error_text
        out = sanitize_error_text(
            "boom at /mnt/nvme0/workspace/codebadger/playground/cpgs/abcd/cpg.bin"
        )
        assert "/mnt/nvme0/workspace" not in out
        assert "cpg.bin" in out

    def test_empty(self):
        from src.utils.validators import sanitize_error_text
        assert sanitize_error_text(None) == ""

    def test_bounds_length(self):
        from src.utils.validators import sanitize_error_text
        assert len(sanitize_error_text("x" * 5000, max_len=100)) <= 120


class TestHashQuery:
    """Test query hashing"""

    def test_hash_query_consistent(self):
        """Test that same query produces same hash"""
        query = "cpg.method.name.l"
        hash1 = hash_query(query)
        hash2 = hash_query(query)

        assert hash1 == hash2
        assert isinstance(hash1, str)
        assert len(hash1) == 64  # SHA256 hex length

    def test_hash_query_different(self):
        """Test that different queries produce different hashes"""
        query1 = "cpg.method.name.l"
        query2 = "cpg.call.name.l"

        hash1 = hash_query(query1)
        hash2 = hash_query(query2)

        assert hash1 != hash2


class TestSanitizePath:
    """Test path sanitization"""

    def test_sanitize_path_safe(self):
        """Test sanitizing safe paths without root constraint"""
        safe_paths = ["/safe/path", "/another/safe/path", "safe/path"]

        for path in safe_paths:
            result = sanitize_path(path)
            assert result == path

    def test_sanitize_path_traversal_no_root(self):
        """Test sanitizing paths with traversal attempts (no root constraint)"""
        dangerous_paths = [
            "../../../etc/passwd",
            "../../../../root",
            "..\\..\\..\\windows\\system32",
        ]

        for path in dangerous_paths:
            result = sanitize_path(path)
            assert ".." not in result

    def test_sanitize_path_with_root_safe(self):
        """Test sanitizing safe paths with root constraint"""
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a subdirectory
            subdir = os.path.join(tmpdir, "subdir")
            os.makedirs(subdir, exist_ok=True)

            # Test that paths within root are accepted
            safe_path = os.path.join(subdir, "file.txt")
            result = sanitize_path(safe_path, allowed_root=tmpdir)
            assert result == os.path.realpath(safe_path)

            # Test relative path within root
            result = sanitize_path("subdir/file.txt", allowed_root=tmpdir)
            assert result == os.path.realpath(safe_path)

    def test_sanitize_path_with_root_traversal(self):
        """Test that path traversal is blocked with root constraint"""
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            # Try to escape the root directory
            with pytest.raises(ValidationError, match="Path traversal attempt detected"):
                sanitize_path("../../../etc/passwd", allowed_root=tmpdir)

            # Try using absolute path outside root
            with pytest.raises(ValidationError, match="Path traversal attempt detected"):
                sanitize_path("/etc/passwd", allowed_root=tmpdir)

    def test_sanitize_path_with_root_traversal_redacts_paths(self):
        """Traversal errors should not leak host filesystem paths."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            attempted = "../secret"
            with pytest.raises(ValidationError) as exc_info:
                sanitize_path(attempted, allowed_root=tmpdir)

            message = str(exc_info.value)
            assert "Path traversal attempt detected" in message
            assert attempted not in message
            assert tmpdir not in message

    def test_sanitize_path_canonicalization(self):
        """Test that paths are properly canonicalized"""
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested directories
            nested = os.path.join(tmpdir, "a", "b", "c")
            os.makedirs(nested, exist_ok=True)

            # Path with .. that stays within root
            result = sanitize_path(
                os.path.join(tmpdir, "a", "b", "c", "..", "file.txt"),
                allowed_root=tmpdir
            )
            expected = os.path.realpath(os.path.join(tmpdir, "a", "b", "file.txt"))
            assert result == expected


class TestValidateTimeout:
    """Test timeout validation"""

    def test_valid_timeout(self):
        """Test valid timeout values"""
        valid_timeouts = [1, 30, 300, 100]

        for timeout in valid_timeouts:
            # Should not raise
            validate_timeout(timeout)

    def test_invalid_timeout_zero(self):
        """Test zero timeout"""
        with pytest.raises(ValidationError) as exc_info:
            validate_timeout(0)

        assert "Timeout must be at least 1 second" in str(exc_info.value)

    def test_invalid_timeout_negative(self):
        """Test negative timeout"""
        with pytest.raises(ValidationError) as exc_info:
            validate_timeout(-1)

        assert "Timeout must be at least 1 second" in str(exc_info.value)

    def test_invalid_timeout_too_large(self):
        """Test timeout exceeding maximum"""
        with pytest.raises(ValidationError) as exc_info:
            validate_timeout(400)

        assert "Timeout cannot exceed 300 seconds" in str(exc_info.value)


class TestResolveHostPath:
    """Test host path resolution"""

    def test_valid_host_path(self, tmp_path):
        """Test resolving valid host path"""
        result = resolve_host_path(str(tmp_path))
        assert result == str(tmp_path)

    def test_invalid_host_path_not_absolute(self):
        """Test relative path"""
        with pytest.raises(ValidationError) as exc_info:
            resolve_host_path("relative/path")

        assert str(exc_info.value) == "Host path must be absolute"

    def test_invalid_host_path_with_traversal(self):
        """Test path with traversal patterns"""
        with pytest.raises(ValidationError) as exc_info:
            resolve_host_path("/home/user/../../../etc/passwd")

        assert str(exc_info.value) == "Invalid host path"

    def test_invalid_host_path_system_etc(self):
        """Test system path /etc"""
        with pytest.raises(ValidationError) as exc_info:
            resolve_host_path("/etc/passwd")

        assert str(exc_info.value) == "Invalid host path"

    def test_invalid_host_path_not_found_redacts_path(self):
        """Missing path errors should not echo the requested host path."""
        with pytest.raises(ValidationError) as exc_info:
            resolve_host_path("/tmp/definitely-not-a-real-codebadger-path")

        assert str(exc_info.value) == "Path does not exist"

    def test_invalid_host_path_system_sys(self):
        """Test system path /sys"""
        with pytest.raises(ValidationError) as exc_info:
            resolve_host_path("/sys/kernel")

        assert "Invalid host path" in str(exc_info.value)

    def test_invalid_host_path_not_exists(self):
        """Test non-existent path"""
        with pytest.raises(ValidationError) as exc_info:
            resolve_host_path("/nonexistent/path/that/does/not/exist")

        assert "Path does not exist" in str(exc_info.value)

    def test_invalid_host_path_not_directory(self, tmp_path):
        """Test path that exists but is not a directory"""
        file_path = tmp_path / "test.txt"
        file_path.write_text("test")
        
        with pytest.raises(ValidationError) as exc_info:
            resolve_host_path(str(file_path))

        assert "Path is not a directory" in str(exc_info.value)

    def test_control_char_rejected(self):
        with pytest.raises(ValidationError) as e:
            resolve_host_path("/tmp/evil\x00/etc/passwd")
        assert "control characters" in str(e.value)

    def test_empty_rejected(self):
        with pytest.raises(ValidationError):
            resolve_host_path("")

    def test_allowlist_contains_allowed_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALLOWED_SOURCE_ROOTS", str(tmp_path))
        sub = tmp_path / "proj"
        sub.mkdir()
        assert resolve_host_path(str(sub)) == str(sub)

    def test_allowlist_rejects_outside_path(self, tmp_path, monkeypatch):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        monkeypatch.setenv("ALLOWED_SOURCE_ROOTS", str(allowed))
        with pytest.raises(ValidationError) as e:
            resolve_host_path(str(outside))
        assert "outside the allowed source roots" in str(e.value)
