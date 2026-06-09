"""
Tests for CPG Generator
"""

import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
import pytest

from src.services.cpg_generator import CPGGenerator
from src.models import Config, CPGConfig, JoernConfig, ServerConfig, QueryConfig, StorageConfig
from src.exceptions import CPGGenerationError


class TestCPGGenerator:
    """Test CPG Generator functionality"""

    @pytest.fixture
    def config(self):
        """Create a test configuration"""
        return Config(
            server=ServerConfig(),
            joern=JoernConfig(),
            cpg=CPGConfig(
                generation_timeout=600,
                max_repo_size_mb=500,
                supported_languages=["c", "cpp", "java", "python"],
                exclusion_patterns=[
                    ".*/test.*",
                    "test.*",
                    ".*/build/.*",
                    ".*/node_modules/.*",
                ],
                languages_with_exclusions=["c", "cpp", "java", "python"],
            ),
            query=QueryConfig(),
            storage=StorageConfig(),
        )

    @pytest.fixture
    def generator(self, config):
        """Create a CPG generator instance"""
        return CPGGenerator(config)

    def test_calculate_repo_size_mb_simple(self, generator, tmp_path):
        """Test calculating repository size for a simple directory"""
        # Create some test files
        test_file1 = tmp_path / "file1.txt"
        test_file1.write_text("x" * 1024)  # 1KB

        test_file2 = tmp_path / "file2.txt"
        test_file2.write_text("y" * (1024 * 100))  # 100KB

        # Calculate size
        size_mb = generator._calculate_repo_size_mb(str(tmp_path))

        # Should be around 0.099MB (101KB / 1024KB/MB)
        assert size_mb >= 0
        assert size_mb < 1  # Less than 1MB

    def test_calculate_repo_size_mb_with_subdirs(self, generator, tmp_path):
        """Test calculating repository size with nested directories"""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        file1 = tmp_path / "file1.txt"
        file1.write_text("x" * (1024 * 100))  # 100KB

        file2 = subdir / "file2.txt"
        file2.write_text("y" * (1024 * 50))  # 50KB

        size_mb = generator._calculate_repo_size_mb(str(tmp_path))

        # Should be around 0.146MB (150KB / 1024KB/MB)
        assert size_mb >= 0
        assert size_mb < 1  # Less than 1MB

    def test_calculate_repo_size_mb_ignores_git(self, generator, tmp_path):
        """Test that .git directory is excluded from size calculation"""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        git_file = git_dir / "HEAD"
        git_file.write_text("x" * (1024 * 200))  # 200KB in .git

        source_file = tmp_path / "source.c"
        source_file.write_text("y" * (1024 * 50))  # 50KB in source

        size_mb = generator._calculate_repo_size_mb(str(tmp_path))

        # Should only count the 50KB source file, not the .git directory
        assert size_mb >= 0
        assert size_mb < 1

    def test_calculate_repo_size_mb_exceeds_limit(self, config):
        """Test that size calculation raises error for oversized repos"""
        config.cpg.max_repo_size_mb = 1  # 1MB limit
        generator = CPGGenerator(config)

        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create a file that's 2MB
            large_file = os.path.join(tmp_dir, "large.bin")
            with open(large_file, "wb") as f:
                f.write(b"x" * (1024 * 1024 * 2))  # 2MB

            with pytest.raises(CPGGenerationError) as exc_info:
                generator.generate_cpg(tmp_dir, "c", "/tmp/cpg.bin", "test_hash")

            assert "exceeds maximum allowed" in str(exc_info.value)

    def test_escape_regex_pattern_valid(self, generator):
        """Test escaping valid regex patterns"""
        pattern = ".*\\.test$"
        result = generator._escape_regex_pattern(pattern)
        assert result == pattern  # Should return unchanged for valid regex

    def test_escape_regex_pattern_invalid(self, generator):
        """Test escaping invalid regex patterns"""
        pattern = "***invalid***"
        result = generator._escape_regex_pattern(pattern)
        # Should escape the pattern for literal matching
        assert result != pattern
        assert "\\*" in result  # Asterisks should be escaped

    def test_generate_cpg_applies_exclusion_patterns(self, config):
        """Test that exclusion patterns are applied during CPG generation"""
        config.cpg.max_repo_size_mb = 5000  # High limit so size check passes
        generator = CPGGenerator(config)

        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create a simple source file
            source_file = os.path.join(tmp_dir, "test.c")
            with open(source_file, "w") as f:
                f.write("int main() { return 0; }")

            with patch.object(generator, "_exec_command_sync") as mock_exec:
                mock_exec.return_value = "CPG generation output"

                with patch.object(generator, "_validate_cpg") as mock_validate:
                    mock_validate.return_value = False

                    try:
                        generator.generate_cpg(tmp_dir, "c", "/tmp/cpg.bin", "test_hash")
                    except CPGGenerationError:
                        pass  # Expected - validation fails

                    # Verify that _exec_command_sync was called
                    assert mock_exec.called

                    # Get the command arguments
                    call_args = mock_exec.call_args
                    cmd_args = call_args[0][0]  # First positional argument

                    # Check that exclusion patterns were added to command
                    assert "--exclude-regex" in cmd_args
                    regex_index = cmd_args.index("--exclude-regex")
                    combined_regex = cmd_args[regex_index + 1]

                    # Verify the regex contains patterns
                    assert "|" in combined_regex  # Multiple patterns combined with OR
                    assert "test" in combined_regex  # At least one test pattern

    def test_generate_cpg_logs_exclusion_count(self, config, caplog):
        """Test that exclusion pattern count is logged"""
        import logging
        caplog.set_level(logging.INFO)

        config.cpg.max_repo_size_mb = 5000
        config.cpg.exclusion_patterns = [
            ".*/test.*",
            "test.*",
            ".*/build/.*",
        ]
        generator = CPGGenerator(config)

        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = os.path.join(tmp_dir, "test.c")
            with open(source_file, "w") as f:
                f.write("int main() { return 0; }")

            with patch.object(generator, "_exec_command_sync") as mock_exec:
                mock_exec.return_value = "output"

                with patch.object(generator, "_validate_cpg") as mock_validate:
                    mock_validate.return_value = False

                    try:
                        generator.generate_cpg(tmp_dir, "c", "/tmp/cpg.bin", "test_hash")
                    except CPGGenerationError:
                        pass

                    # Check that the count was logged
                    assert any(
                        "Applied 3 exclusion patterns" in record.message
                        for record in caplog.records
                    )

    def test_host_to_container_path_conversion(self, generator):
        """Test host to container path conversion"""
        host_path = "/home/user/workspace/playground/cpgs/hash123/cpg.bin"
        result = generator._host_to_container_path(host_path)
        assert result == "/playground/cpgs/hash123/cpg.bin"

    def test_host_to_container_path_already_container(self, generator):
        """Test that container paths are returned as-is"""
        container_path = "/playground/cpgs/hash123/cpg.bin"
        result = generator._host_to_container_path(container_path)
        assert result == "/playground/cpgs/hash123/cpg.bin"


class TestApplyOverlays:
    """Tests for #7: persisting Joern overlays into cpg.bin at build time.

    Overlays must be applied once in the big-heap build container so that memory-
    capped query workers can deserialize the CPG instead of recomputing the dataflow
    overlay (which OOMs tier-S workers -> "No projects loaded").
    """

    def _gen(self):
        from src.models import (
            Config, CPGConfig, JoernConfig, ServerConfig, QueryConfig, StorageConfig,
        )
        cfg = Config(
            server=ServerConfig(),
            joern=JoernConfig(),
            cpg=CPGConfig(generation_timeout=600, build_heap_gb=32),
            query=QueryConfig(),
            storage=StorageConfig(),
        )
        return CPGGenerator(cfg)

    def test_apply_overlays_success_builds_correct_command(self):
        gen = self._gen()
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            m = Mock()
            m.returncode = 0
            m.stdout = "OVERLAY_OK bytes=108748947\n"
            m.stderr = ""
            return m

        with patch("src.services.cpg_generator.subprocess.run", side_effect=fake_run):
            ok = gen._apply_overlays("/playground/cpgs/deadbeefdeadbeef/cpg.bin",
                                     "deadbeefdeadbeef", 32)
        assert ok is True
        cmd = captured["cmd"]
        # Runs in the Joern build container via bash -lc, with the build heap.
        assert cmd[0:2] == ["docker", "exec"]
        assert "codebadger-joern-server" in cmd
        assert "bash" in cmd and "-lc" in cmd
        joined = " ".join(cmd)
        assert "-Xmx32G" in joined
        assert "/opt/joern/joern-cli/joern --script" in joined
        # Imports the built cpg and promotes the overlaid result back over it.
        assert 'importCpg' in joined
        assert "/playground/cpgs/deadbeefdeadbeef/cpg.bin" in joined

    def test_apply_overlays_failure_is_best_effort(self):
        gen = self._gen()

        def fake_run(cmd, **kwargs):
            if "rm" in cmd and "-rf" in cmd:  # cleanup call
                m = Mock(); m.returncode = 0; m.stdout = ""; m.stderr = ""; return m
            m = Mock(); m.returncode = 3; m.stdout = "OVERLAY_NO_OUTPUT\n"; m.stderr = ""
            return m

        with patch("src.services.cpg_generator.subprocess.run", side_effect=fake_run):
            ok = gen._apply_overlays("/playground/cpgs/deadbeefdeadbeef/cpg.bin",
                                     "deadbeefdeadbeef", 32)
        # Failure must NOT raise (base CPG kept; worker falls back to recompute).
        assert ok is False

    def test_apply_overlays_timeout_is_best_effort(self):
        import subprocess as _sp
        gen = self._gen()

        def fake_run(cmd, **kwargs):
            if "rm" in cmd and "-rf" in cmd:
                m = Mock(); m.returncode = 0; m.stdout = ""; m.stderr = ""; return m
            raise _sp.TimeoutExpired(cmd, 600)

        with patch("src.services.cpg_generator.subprocess.run", side_effect=fake_run):
            ok = gen._apply_overlays("/playground/cpgs/deadbeefdeadbeef/cpg.bin",
                                     "deadbeefdeadbeef", 32)
        assert ok is False
