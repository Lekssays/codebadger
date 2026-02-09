"""
Tests for input validation utilities
"""

from unittest.mock import patch

import pytest

from src.exceptions import ValidationError
from src.utils.validators import (
    hash_query,
    sanitize_path,
    validate_cpgql_query,
    validate_github_url,
    validate_language,
    validate_local_path,
    validate_session_id,
    validate_source_type,
    validate_timeout,
    resolve_host_path,
)


class TestValidateSourceType:
    """Test source type validation"""

    def test_valid_source_types(self):
        """Test valid source types"""
        valid_types = ["local", "github"]

        for source_type in valid_types:
            # Should not raise
            validate_source_type(source_type)

    def test_invalid_source_type(self):
        """Test invalid source type"""
        with pytest.raises(ValidationError) as exc_info:
            validate_source_type("invalid")

        assert "Invalid source_type 'invalid'" in str(exc_info.value)
        assert "Must be one of: local, github" in str(exc_info.value)


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
            validate_language("rust")

        assert "Unsupported language 'rust'" in str(exc_info.value)
        assert "Supported:" in str(exc_info.value)


class TestValidateSessionId:
    """Test session ID validation"""

    def test_valid_session_id(self):
        """Test valid 16-character hex session ID"""
        valid_hex = "1234567890abcdef"
        # Should not raise
        validate_session_id(valid_hex)

    def test_invalid_session_id_empty(self):
        """Test empty session ID"""
        with pytest.raises(ValidationError) as exc_info:
            validate_session_id("")

        assert "session_id must be a non-empty string" in str(exc_info.value)

    def test_invalid_session_id_none(self):
        """Test None session ID"""
        with pytest.raises(ValidationError) as exc_info:
            validate_session_id(None)

        assert "session_id must be a non-empty string" in str(exc_info.value)

    def test_invalid_session_id_wrong_format(self):
        """Test invalid hex format"""
        invalid_ids = [
            "not-hex-at-all",  # Non-hex characters, 15 chars
            "gggggggggggggggg",  # Invalid hex characters, 16 chars
            "1234567890ABCDEF",  # Uppercase (should be lowercase), 16 chars
            "ggggggggggggggggg",  # Invalid hex, 17 chars (too long)
        ]

        for invalid_id in invalid_ids:
            with pytest.raises(ValidationError) as exc_info:
                validate_session_id(invalid_id)

            assert "session_id must be a valid 16-character hex string" in str(exc_info.value)


class TestValidateGithubUrl:
    """Test GitHub URL validation"""

    def test_valid_github_urls(self):
        """Test valid GitHub URLs"""
        valid_urls = [
            "https://github.com/user/repo",
            "https://github.com/user/repo.git",
            "https://www.github.com/user/repo",
            "https://github.com/user-name/repo_name",
            "https://github.com/user/repo/issues",
        ]

        for url in valid_urls:
            # Should not raise
            validate_github_url(url)

    def test_invalid_github_urls(self):
        """Test invalid GitHub URLs"""
        invalid_urls = [
            "https://gitlab.com/user/repo",  # Wrong domain
            "https://github.com/user",  # Missing repo
            "https://github.com/",  # Incomplete
            "not-a-url",
        ]

        for url in invalid_urls:
            with pytest.raises(ValidationError):
                validate_github_url(url)


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

        assert "Host path must be absolute" in str(exc_info.value)

    def test_invalid_host_path_with_traversal(self):
        """Test path with traversal patterns"""
        with pytest.raises(ValidationError) as exc_info:
            resolve_host_path("/home/user/../../../etc/passwd")

        assert "Invalid host path" in str(exc_info.value)

    def test_invalid_host_path_system_etc(self):
        """Test system path /etc"""
        with pytest.raises(ValidationError) as exc_info:
            resolve_host_path("/etc/passwd")

        assert "Invalid host path" in str(exc_info.value)

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
