"""
Tests for data models
"""

from datetime import datetime

import pytest

from src.models import (
    Config,
    CPGConfig,
    JoernConfig,
    QueryConfig,
    QueryResult,
    ServerConfig,
    SessionStatus,
    SourceType,
    StorageConfig,
)


class TestQueryResult:
    """Test QueryResult model"""

    def test_query_result_creation(self):
        """Test basic query result creation"""
        result = QueryResult(success=True, data=[{"name": "test"}], execution_time=1.5)

        assert result.success is True
        assert result.data == [{"name": "test"}]
        assert result.error is None
        assert result.execution_time == 1.5
        assert result.row_count == 0

    def test_query_result_with_error(self):
        """Test query result with error"""
        result = QueryResult(success=False, error="Query failed", execution_time=0.5)

        assert result.success is False
        assert result.data is None
        assert result.error == "Query failed"
        assert result.execution_time == 0.5

    def test_query_result_to_dict(self):
        """Test query result serialization"""
        result = QueryResult(
            success=True, data=[{"name": "test"}], execution_time=1.5, row_count=1
        )

        data = result.to_dict()

        assert data["success"] is True
        assert data["data"] == [{"name": "test"}]
        assert data["error"] is None
        assert data["execution_time"] == 1.5
        assert data["row_count"] == 1


class TestEnums:
    """Test enumeration classes"""

    def test_session_status_values(self):
        """Test SessionStatus enum values"""
        assert SessionStatus.INITIALIZING.value == "initializing"
        assert SessionStatus.GENERATING.value == "generating"
        assert SessionStatus.READY.value == "ready"
        assert SessionStatus.ERROR.value == "error"

    def test_source_type_values(self):
        """Test SourceType enum values"""
        assert SourceType.LOCAL.value == "local"
        assert SourceType.GITHUB.value == "github"
        assert SourceType.SNIPPET.value == "snippet"


class TestConfigModels:
    """Test configuration models"""

    def test_server_config(self):
        """Test ServerConfig creation"""
        config = ServerConfig(host="127.0.0.1", port=8080, log_level="DEBUG")

        assert config.host == "127.0.0.1"
        assert config.port == 8080
        assert config.log_level == "DEBUG"

    def test_cpg_config(self):
        """Test CPGConfig creation"""
        config = CPGConfig(
            generation_timeout=1200,
            max_repo_size_mb=1000,
            supported_languages=["java", "python", "c", "cpp"]
        )

        assert config.generation_timeout == 1200
        assert config.max_repo_size_mb == 1000
        assert "java" in config.supported_languages
        assert "python" in config.supported_languages

    def test_query_config(self):
        """Test QueryConfig creation"""
        config = QueryConfig(timeout=60, cache_enabled=False, cache_ttl=600)

        assert config.timeout == 60
        assert config.cache_enabled is False
        assert config.cache_ttl == 600

    def test_storage_config(self):
        """Test StorageConfig creation"""
        config = StorageConfig(workspace_root="/tmp/test", cleanup_on_shutdown=False)

        assert config.workspace_root == "/tmp/test"
        assert config.cleanup_on_shutdown is False

    def test_joern_config(self):
        """Test JoernConfig creation"""
        config = JoernConfig(binary_path="/usr/local/bin/joern", java_opts="-Xmx8G")

        assert config.binary_path == "/usr/local/bin/joern"
        assert config.java_opts == "-Xmx8G"

    def test_config_composition(self):
        """Test Config composition"""
        config = Config(
            server=ServerConfig(host="0.0.0.0", port=4242),
            joern=JoernConfig(binary_path="joern"),
            cpg=CPGConfig(generation_timeout=600),
            query=QueryConfig(timeout=30),
            storage=StorageConfig(workspace_root="/tmp/joern"),
        )

        assert config.server.host == "0.0.0.0"
        assert config.joern.binary_path == "joern"
        assert config.cpg.generation_timeout == 600
        assert config.query.timeout == 30
        assert config.storage.workspace_root == "/tmp/joern"
