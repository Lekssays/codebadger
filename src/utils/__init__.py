"""
Utilities package
"""

from .logging import get_logger, setup_logging
from .validators import (
    hash_query,
    sanitize_error_text,
    sanitize_path,
    validate_codebase_hash,
    validate_cpgql_query,
    validate_github_url,
    validate_language,
    validate_local_path,
    validate_search_pattern,
    validate_source_type,
    validate_timeout,
)
from .cpgql_validator import CPGQLValidator, QueryTransformer
from .query_rendering import escape_scala_string
from .recommend import (
    compute as compute_recommendation,
    current_from_config,
    detect_host,
    render as render_recommendation,
)

__all__ = [
    "get_logger",
    "setup_logging",
    "compute_recommendation",
    "current_from_config",
    "detect_host",
    "render_recommendation",
    "validate_codebase_hash",
    "validate_source_type",
    "validate_local_path",
    "validate_github_url",
    "validate_language",
    "sanitize_path",
    "sanitize_error_text",
    "validate_cpgql_query",
    "validate_search_pattern",
    "validate_timeout",
    "hash_query",
    "escape_scala_string",
    "CPGQLValidator",
    "QueryTransformer",
]
