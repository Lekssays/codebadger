"""
Utilities package
"""

from .logging import get_logger, setup_logging
from .db_manager import DBManager
from .validators import (
    hash_query,
    sanitize_path,
    validate_codebase_hash,
    validate_cpgql_query,
    validate_github_url,
    validate_language,
    validate_local_path,
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
    "DBManager",
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
    "validate_cpgql_query",
    "validate_timeout",
    "hash_query",
    "escape_scala_string",
    "CPGQLValidator",
    "QueryTransformer",
]
