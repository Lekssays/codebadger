"""Configuration management for the CodeBadger Server."""

import os
from typing import Any, Optional

import yaml

from . import defaults
from .models import (
    Config,
    CPGConfig,
    JoernConfig,
    QueryConfig,
    ServerConfig,
    StorageConfig,
    TelemetryConfig,
)


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from file or environment variables
    
    Priority order:
    1. Environment variables (highest priority)
    2. Config file (YAML)
    3. Centralized defaults in defaults.py (lowest priority)
    """
    if config_path and os.path.exists(config_path):
        with open(config_path, "r") as f:
            config_data = yaml.safe_load(f)
            # Process environment variable substitutions
            config_data = _substitute_env_vars(config_data)
        return _dict_to_config(config_data)
    else:
        # Load from environment variables with centralized defaults
        return Config(
            server=ServerConfig(
                host=os.getenv("MCP_HOST", defaults.SERVER_HOST),
                port=int(os.getenv("MCP_PORT", str(defaults.SERVER_PORT))),
                log_level=os.getenv("MCP_LOG_LEVEL", defaults.SERVER_LOG_LEVEL),
            ),
            joern=JoernConfig(
                binary_path=os.getenv("JOERN_BINARY_PATH", defaults.JOERN_BINARY_PATH),
                memory_limit=os.getenv("JOERN_MEMORY_LIMIT", defaults.JOERN_MEMORY_LIMIT),
                java_opts=os.getenv("JOERN_JAVA_OPTS", defaults.JOERN_JAVA_OPTS),
                server_host=os.getenv("JOERN_SERVER_HOST", defaults.JOERN_SERVER_HOST),
                server_port=int(os.getenv("JOERN_SERVER_PORT", str(defaults.JOERN_SERVER_PORT))),
                server_auth_username=os.getenv("JOERN_SERVER_AUTH_USERNAME"),
                server_auth_password=os.getenv("JOERN_SERVER_AUTH_PASSWORD"),
                port_min=int(os.getenv("JOERN_PORT_MIN", str(defaults.JOERN_PORT_MIN))),
                port_max=int(os.getenv("JOERN_PORT_MAX", str(defaults.JOERN_PORT_MAX))),
                server_init_sleep_time=float(os.getenv("JOERN_SERVER_INIT_SLEEP_TIME", str(defaults.JOERN_SERVER_INIT_SLEEP_TIME))),
                server_startup_timeout=int(os.getenv("JOERN_SERVER_STARTUP_TIMEOUT", str(defaults.JOERN_SERVER_STARTUP_TIMEOUT))),
            ),
            cpg=CPGConfig(
                generation_timeout=int(os.getenv("CPG_GENERATION_TIMEOUT", str(defaults.CPG_GENERATION_TIMEOUT))),
                max_repo_size_mb=int(os.getenv("MAX_REPO_SIZE_MB", str(defaults.MAX_REPO_SIZE_MB))),
                supported_languages=defaults.SUPPORTED_LANGUAGES,
                exclusion_patterns=defaults.EXCLUSION_PATTERNS,
                languages_with_exclusions=defaults.LANGUAGES_WITH_EXCLUSIONS,
                taint_sources={},
                taint_sinks={},
                min_cpg_file_size=int(os.getenv("MIN_CPG_FILE_SIZE", str(defaults.MIN_CPG_FILE_SIZE))),
                output_truncation_length=int(os.getenv("OUTPUT_TRUNCATION_LENGTH", str(defaults.OUTPUT_TRUNCATION_LENGTH))),
            ),
            query=QueryConfig(
                timeout=int(os.getenv("QUERY_TIMEOUT", str(defaults.QUERY_TIMEOUT))),
                cache_enabled=os.getenv("QUERY_CACHE_ENABLED", str(defaults.QUERY_CACHE_ENABLED)).lower()
                == "true",
                cache_ttl=int(os.getenv("QUERY_CACHE_TTL", str(defaults.QUERY_CACHE_TTL))),
            ),
            storage=StorageConfig(
                workspace_root=os.getenv("WORKSPACE_ROOT", defaults.WORKSPACE_ROOT),
                cleanup_on_shutdown=os.getenv("CLEANUP_ON_SHUTDOWN", str(defaults.CLEANUP_ON_SHUTDOWN)).lower()
                == "true",
            ),
            telemetry=TelemetryConfig(
                enabled=os.getenv("OTEL_ENABLED", "false").lower() == "true",
                service_name=os.getenv("OTEL_SERVICE_NAME", "codebadger"),
                otlp_endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"),
                otlp_protocol=os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
            ),
        )


def _substitute_env_vars(data: Any) -> Any:
    """Recursively substitute environment variables in config"""
    if isinstance(data, dict):
        return {k: _substitute_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_substitute_env_vars(item) for item in data]
    elif isinstance(data, str) and data.startswith("${") and data.endswith("}"):
        env_var = data[2:-1]
        default = None
        if ":" in env_var:
            env_var, default = env_var.split(":", 1)
        return os.getenv(env_var, default)
    return data


def _dict_to_config(data: dict) -> Config:
    """Convert dictionary to Config object with proper type conversions
    
    Uses centralized defaults.py as fallback for missing values in the YAML config.
    Priority: YAML values > Environment variables > Centralized defaults
    """

    # Helper function to convert values based on dataclass field types
    def convert_config_section(config_class, values):
        if not values:
            return config_class()
        converted = {}
        for field_name, field_type in config_class.__annotations__.items():
            if field_name in values:
                value = values[field_name]
                # Handle type conversions
                if field_type == int or (
                    hasattr(field_type, "__origin__") and field_type.__origin__ == int
                ):
                    converted[field_name] = int(value) if value is not None else None
                elif field_type == float or (
                    hasattr(field_type, "__origin__") and field_type.__origin__ == float
                ):
                    converted[field_name] = float(value) if value is not None else None
                elif field_type == bool or (
                    hasattr(field_type, "__origin__") and field_type.__origin__ == bool
                ):
                    if isinstance(value, str):
                        converted[field_name] = value.lower() in ("true", "1", "yes")
                    else:
                        converted[field_name] = bool(value)
                elif hasattr(field_type, "__origin__") and field_type.__origin__ == list:
                    # Handle List types
                    if isinstance(value, list):
                        converted[field_name] = value
                    else:
                        converted[field_name] = [value] if value is not None else None
                elif hasattr(field_type, "__origin__") and field_type.__origin__ == dict:
                    # Handle Dict types
                    if isinstance(value, dict):
                        converted[field_name] = value
                    else:
                        converted[field_name] = None
                else:
                    converted[field_name] = value
        return config_class(**converted)

    # Get config sections with environment variable substitution
    cpg_data = data.get("cpg", {})
    
    # Apply centralized defaults for missing CPG values
    if "max_repo_size_mb" not in cpg_data:
        cpg_data = {**cpg_data, "max_repo_size_mb": defaults.MAX_REPO_SIZE_MB}
    if "generation_timeout" not in cpg_data:
        cpg_data = {**cpg_data, "generation_timeout": defaults.CPG_GENERATION_TIMEOUT}
    if "supported_languages" not in cpg_data:
        cpg_data = {**cpg_data, "supported_languages": defaults.SUPPORTED_LANGUAGES}
    if "exclusion_patterns" not in cpg_data:
        cpg_data = {**cpg_data, "exclusion_patterns": defaults.EXCLUSION_PATTERNS}
    if "languages_with_exclusions" not in cpg_data:
        cpg_data = {**cpg_data, "languages_with_exclusions": defaults.LANGUAGES_WITH_EXCLUSIONS}

    return Config(
        server=convert_config_section(ServerConfig, data.get("server", {})),
        joern=convert_config_section(JoernConfig, data.get("joern", {})),
        cpg=convert_config_section(CPGConfig, cpg_data),
        query=convert_config_section(QueryConfig, data.get("query", {})),
        storage=convert_config_section(StorageConfig, data.get("storage", {})),
        telemetry=convert_config_section(TelemetryConfig, data.get("telemetry", {})),
    )
