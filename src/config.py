"""Configuration management for the CodeBadger Server."""

import os
from typing import Optional

import yaml

from .models import (
    Config,
    CPGConfig,
    JoernConfig,
    QueryConfig,
    ServerConfig,
    StorageConfig,
)


def _get_default_cpg_config() -> CPGConfig:
    """Get default CPG configuration values"""
    return CPGConfig(
        generation_timeout=600,
        max_repo_size_mb=500,
        supported_languages=[
            "java", "c", "cpp", "javascript", "python", "go",
            "kotlin", "csharp", "ghidra", "jimple", "php", "ruby", "swift"
        ],
        exclusion_patterns=[
            ".*/\\..*", "\\..*", ".*/test.*", "test.*", ".*/fuzz.*", "fuzz.*",
            ".*/Testing.*", "Testing.*", ".*/spec.*", "spec.*", ".*/__tests__/.*",
            "__tests__/.*", ".*/e2e.*", "e2e.*", ".*/integration.*", "integration.*",
            ".*/unit.*", "unit.*", ".*/benchmark.*", "benchmark.*", ".*/perf.*", "perf.*",
            ".*/docs?/.*", "docs?/.*", ".*/documentation.*", "documentation.*",
            ".*/example.*", "example.*", ".*/sample.*", "sample.*", ".*/demo.*", "demo.*",
            ".*/tutorial.*", "tutorial.*", ".*/guide.*", "guide.*", ".*/build.*/.*",
            ".*_build/.*", ".*/target/.*", ".*/out/.*", ".*/dist/.*", ".*/bin/.*",
            ".*/obj/.*", ".*/Debug/.*", ".*/Release/.*", ".*/cmake/.*", ".*/m4/.*",
            ".*/autom4te.*/.*", ".*/autotools/.*", ".*/\\.git/.*", ".*/\\.svn/.*",
            ".*/\\.hg/.*", ".*/\\.deps/.*", ".*/node_modules/.*", ".*/vendor/.*",
            ".*/third_party/.*", ".*/extern/.*", ".*/external/.*", ".*/packages/.*",
            ".*/benchmark.*/.*", ".*/perf.*/.*", ".*/profile.*/.*", ".*/bench/.*",
            ".*/tool.*/.*", ".*/script.*/.*", ".*/utils/.*", ".*/util/.*",
            ".*/helper.*/.*", ".*/misc/.*", ".*/python/.*", ".*/java/.*",
            ".*/ruby/.*", ".*/perl/.*", ".*/php/.*", ".*/csharp/.*", ".*/dotnet/.*",
            ".*/go/.*", ".*/generated/.*", ".*/gen/.*", ".*/temp/.*", ".*/tmp/.*",
            ".*/cache/.*", ".*/\\.cache/.*", ".*/log.*/.*", ".*/logs/.*",
            ".*/result.*/.*", ".*/results/.*", ".*/output/.*", ".*\\.md$",
            ".*\\.txt$", ".*\\.xml$", ".*\\.json$", ".*\\.yaml$", ".*\\.yml$",
            ".*\\.toml$", ".*\\.ini$", ".*\\.cfg$", ".*\\.conf$", ".*\\.properties$",
            ".*\\.cmake$", ".*Makefile.*", ".*makefile.*", ".*configure.*",
            ".*\\.am$", ".*\\.in$", ".*\\.ac$", ".*\\.log$", ".*\\.cache$",
            ".*\\.lock$", ".*\\.tmp$", ".*\\.bak$", ".*\\.orig$", ".*\\.swp$",
            ".*~$", ".*/\\.vscode/.*", ".*/\\.idea/.*", ".*/\\.eclipse/.*",
            ".*\\.DS_Store$", ".*Thumbs\\.db$"
        ],
        languages_with_exclusions=[
            "c", "cpp", "java", "javascript", "python", "go",
            "kotlin", "csharp", "php", "ruby"
        ],
        taint_sources={},
        taint_sinks={}
    )


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from file or environment variables"""
    if config_path and os.path.exists(config_path):
        with open(config_path, "r") as f:
            config_data = yaml.safe_load(f)
            # Process environment variable substitutions
            config_data = _substitute_env_vars(config_data)
        return _dict_to_config(config_data)
    else:
        # Load from environment variables
        return Config(
            server=ServerConfig(
                host=os.getenv("MCP_HOST", "0.0.0.0"),
                port=int(os.getenv("MCP_PORT", "4242")),
                log_level=os.getenv("MCP_LOG_LEVEL", "INFO"),
            ),
            joern=JoernConfig(
                binary_path=os.getenv("JOERN_BINARY_PATH", "joern"),
                memory_limit=os.getenv("JOERN_MEMORY_LIMIT", "4g"),
                java_opts=os.getenv("JOERN_JAVA_OPTS", "-Xmx4G -Xms2G -XX:+UseG1GC -Dfile.encoding=UTF-8"),
                server_host=os.getenv("JOERN_SERVER_HOST", "localhost"),
                server_port=int(os.getenv("JOERN_SERVER_PORT", "8080")),
                server_auth_username=os.getenv("JOERN_SERVER_AUTH_USERNAME"),
                server_auth_password=os.getenv("JOERN_SERVER_AUTH_PASSWORD"),
            ),
            cpg=CPGConfig(
                generation_timeout=int(os.getenv("CPG_GENERATION_TIMEOUT", "600")),
                max_repo_size_mb=int(os.getenv("MAX_REPO_SIZE_MB", "500")),
                supported_languages=[
                    "java", "c", "cpp", "javascript", "python", "go",
                    "kotlin", "csharp", "ghidra", "jimple", "php", "ruby", "swift"
                ],
                exclusion_patterns=[
                    ".*/\\..*", "\\..*", ".*/test.*", "test.*", ".*/fuzz.*", "fuzz.*",
                    ".*/Testing.*", "Testing.*", ".*/spec.*", "spec.*", ".*/__tests__/.*",
                    "__tests__/.*", ".*/e2e.*", "e2e.*", ".*/integration.*", "integration.*",
                    ".*/unit.*", "unit.*", ".*/benchmark.*", "benchmark.*", ".*/perf.*", "perf.*",
                    ".*/docs?/.*", "docs?/.*", ".*/documentation.*", "documentation.*",
                    ".*/example.*", "example.*", ".*/sample.*", "sample.*", ".*/demo.*", "demo.*",
                    ".*/tutorial.*", "tutorial.*", ".*/guide.*", "guide.*", ".*/build.*/.*",
                    ".*_build/.*", ".*/target/.*", ".*/out/.*", ".*/dist/.*", ".*/bin/.*",
                    ".*/obj/.*", ".*/Debug/.*", ".*/Release/.*", ".*/cmake/.*", ".*/m4/.*",
                    ".*/autom4te.*/.*", ".*/autotools/.*", ".*/\\.git/.*", ".*/\\.svn/.*",
                    ".*/\\.hg/.*", ".*/\\.deps/.*", ".*/node_modules/.*", ".*/vendor/.*",
                    ".*/third_party/.*", ".*/extern/.*", ".*/external/.*", ".*/packages/.*",
                    ".*/benchmark.*/.*", ".*/perf.*/.*", ".*/profile.*/.*", ".*/bench/.*",
                    ".*/tool.*/.*", ".*/script.*/.*", ".*/utils/.*", ".*/util/.*",
                    ".*/helper.*/.*", ".*/misc/.*", ".*/python/.*", ".*/java/.*",
                    ".*/ruby/.*", ".*/perl/.*", ".*/php/.*", ".*/csharp/.*", ".*/dotnet/.*",
                    ".*/go/.*", ".*/generated/.*", ".*/gen/.*", ".*/temp/.*", ".*/tmp/.*",
                    ".*/cache/.*", ".*/\\.cache/.*", ".*/log.*/.*", ".*/logs/.*",
                    ".*/result.*/.*", ".*/results/.*", ".*/output/.*", ".*\\.md$",
                    ".*\\.txt$", ".*\\.xml$", ".*\\.json$", ".*\\.yaml$", ".*\\.yml$",
                    ".*\\.toml$", ".*\\.ini$", ".*\\.cfg$", ".*\\.conf$", ".*\\.properties$",
                    ".*\\.cmake$", ".*Makefile.*", ".*makefile.*", ".*configure.*",
                    ".*\\.am$", ".*\\.in$", ".*\\.ac$", ".*\\.log$", ".*\\.cache$",
                    ".*\\.lock$", ".*\\.tmp$", ".*\\.bak$", ".*\\.orig$", ".*\\.swp$",
                    ".*~$", ".*/\\.vscode/.*", ".*/\\.idea/.*", ".*/\\.eclipse/.*",
                    ".*\\.DS_Store$", ".*Thumbs\\.db$"
                ],
                languages_with_exclusions=[
                    "c", "cpp", "java", "javascript", "python", "go",
                    "kotlin", "csharp", "php", "ruby"
                ],
                taint_sources={},
                taint_sinks={}
            ),
            query=QueryConfig(
                timeout=int(os.getenv("QUERY_TIMEOUT", "30")),
                cache_enabled=os.getenv("QUERY_CACHE_ENABLED", "true").lower()
                == "true",
                cache_ttl=int(os.getenv("QUERY_CACHE_TTL", "300")),
            ),
            storage=StorageConfig(
                workspace_root=os.getenv("WORKSPACE_ROOT", "/tmp/codebadger"),
                cleanup_on_shutdown=os.getenv("CLEANUP_ON_SHUTDOWN", "true").lower()
                == "true",
            ),
        )


def _substitute_env_vars(data):
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
    """Convert dictionary to Config object with proper type conversions"""

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

    return Config(
        server=convert_config_section(ServerConfig, data.get("server", {})),
        joern=convert_config_section(JoernConfig, data.get("joern", {})),
        cpg=convert_config_section(CPGConfig, data.get("cpg", {})),
        query=convert_config_section(QueryConfig, data.get("query", {})),
        storage=convert_config_section(StorageConfig, data.get("storage", {})),
    )
