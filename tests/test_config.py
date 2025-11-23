"""
Tests for configuration management
"""

import os
import tempfile
from unittest.mock import patch

import yaml

from src.config import _dict_to_config, _substitute_env_vars, load_config
from src.models import Config


class TestLoadConfig:
    """Test configuration loading"""

    def test_load_config_from_file(self):
        """Test loading config from YAML file"""
        config_data = {
            "server": {"host": "127.0.0.1", "port": 8080, "log_level": "DEBUG"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            config = load_config(config_path)

            assert config.server.host == "127.0.0.1"
            assert config.server.port == 8080
            assert config.server.log_level == "DEBUG"
        finally:
            os.unlink(config_path)

    def test_load_config_from_env_vars(self):
        """Test loading config from environment variables"""
        env_vars = {
            "MCP_HOST": "0.0.0.0",
            "MCP_PORT": "4242",
            "MCP_LOG_LEVEL": "INFO",
            "JOERN_BINARY_PATH": "/usr/bin/joern",
            "JOERN_MEMORY_LIMIT": "4g",
            "CPG_GENERATION_TIMEOUT": "1200",
            "MAX_REPO_SIZE_MB": "1000",
            "QUERY_TIMEOUT": "60",
            "QUERY_CACHE_ENABLED": "false",
            "QUERY_CACHE_TTL": "600",
            "WORKSPACE_ROOT": "/tmp/custom",
            "CLEANUP_ON_SHUTDOWN": "false",
        }

        with patch.dict(os.environ, env_vars):
            config = load_config()

            assert config.server.host == "0.0.0.0"
            assert config.server.port == 4242
            assert config.server.log_level == "INFO"
            assert config.joern.binary_path == "/usr/bin/joern"
            assert config.joern.memory_limit == "4g"
            assert config.cpg.generation_timeout == 1200
            assert config.cpg.max_repo_size_mb == 1000
            assert config.query.timeout == 60
            assert config.query.cache_enabled is False
            assert config.query.cache_ttl == 600
            assert config.storage.workspace_root == "/tmp/custom"
            assert config.storage.cleanup_on_shutdown is False

    def test_load_config_defaults(self):
        """Test loading config with defaults"""
        # Clear environment
        with patch.dict(os.environ, {}, clear=True):
            config = load_config()

            assert config.server.host == "0.0.0.0"
            assert config.server.port == 4242
            assert config.server.log_level == "INFO"
            assert config.joern.binary_path == "joern"
            assert config.joern.memory_limit == "4g"
            assert config.cpg.generation_timeout == 600
            assert config.cpg.max_repo_size_mb == 500
            assert config.query.timeout == 30
            assert config.query.cache_enabled is True
            assert config.query.cache_ttl == 300
            assert config.storage.workspace_root == "/tmp/codebadger"
            assert config.storage.cleanup_on_shutdown is True

    def test_load_config_file_not_found(self):
        """Test loading config when file doesn't exist"""
        config = load_config("/nonexistent/config.yaml")

        # Should fall back to environment/defaults
        assert isinstance(config, Config)

    def test_substitute_env_vars(self):
        """Test environment variable substitution"""
        data = {
            "host": "${TEST_HOST}",
            "port": 8080,
            "nested": {"path": "${TEST_PATH}", "value": "static"},
            "list": ["${TEST_ITEM1}", "static", "${TEST_ITEM2}"],
        }

        env_vars = {
            "TEST_HOST": "localhost",
            "TEST_PATH": "/tmp/test",
            "TEST_ITEM1": "item1",
            "TEST_ITEM2": "item2",
        }

        with patch.dict(os.environ, env_vars):
            result = _substitute_env_vars(data)

            assert result["host"] == "localhost"
            assert result["port"] == 8080
            assert result["nested"]["path"] == "/tmp/test"
            assert result["nested"]["value"] == "static"
            assert result["list"] == ["item1", "static", "item2"]

    def test_substitute_env_vars_with_defaults(self):
        """Test environment variable substitution with defaults"""
        data = {
            "host": "${TEST_HOST:default_host}",
            "missing": "${MISSING_VAR:default_value}",
        }

        env_vars = {"TEST_HOST": "actual_host"}

        with patch.dict(os.environ, env_vars):
            result = _substitute_env_vars(data)

            assert result["host"] == "actual_host"
            assert result["missing"] == "default_value"

    def test_substitute_env_vars_no_substitution(self):
        """Test that non-template strings are unchanged"""
        data = {"host": "localhost", "port": 8080, "path": "/tmp/test"}

        result = _substitute_env_vars(data)
        assert result == data


class TestDictToConfig:
    """Test dictionary to config conversion"""

    def test_dict_to_config_full(self):
        """Test converting full config dictionary"""
        data = {
            "server": {"host": "127.0.0.1", "port": 8080, "log_level": "DEBUG"},
            "joern": {"binary_path": "/usr/bin/joern", "memory_limit": "8g"},
            "cpg": {"generation_timeout": 1200, "max_repo_size_mb": 1000},
            "query": {"timeout": 60, "cache_enabled": False, "cache_ttl": 600},
            "storage": {"workspace_root": "/tmp/custom", "cleanup_on_shutdown": False},
        }

        config = _dict_to_config(data)

        assert config.server.host == "127.0.0.1"
        assert config.server.port == 8080
        assert config.server.log_level == "DEBUG"
        assert config.joern.binary_path == "/usr/bin/joern"
        assert config.joern.memory_limit == "8g"
        assert config.cpg.generation_timeout == 1200
        assert config.cpg.max_repo_size_mb == 1000
        assert config.query.timeout == 60
        assert config.query.cache_enabled is False
        assert config.query.cache_ttl == 600
        assert config.storage.workspace_root == "/tmp/custom"
        assert config.storage.cleanup_on_shutdown is False

    def test_dict_to_config_partial(self):
        """Test converting partial config dictionary"""
        data = {"server": {"port": 9000}}

        config = _dict_to_config(data)

        # Specified values
        assert config.server.port == 9000

        # Default values
        assert config.server.host == "0.0.0.0"
        assert config.server.log_level == "INFO"

    def test_dict_to_config_empty(self):
        """Test converting empty config dictionary"""
        config = _dict_to_config({})

        # All default values
        assert config.server.host == "0.0.0.0"
        assert config.server.port == 4242

    def test_dict_to_config_type_conversions(self):
        """Test type conversions in config"""
        data = {
            "server": {"port": "9000", "log_level": "INFO"},  # String to int
            "query": {
                "cache_enabled": "true",  # String to bool
                "timeout": "45",  # String to int
            },
            "storage": {"cleanup_on_shutdown": "false"},  # String to bool
        }

        config = _dict_to_config(data)

        assert config.server.port == 9000
        assert config.query.cache_enabled is True
        assert config.query.timeout == 45
        assert config.storage.cleanup_on_shutdown is False
