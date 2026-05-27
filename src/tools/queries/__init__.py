"""
Query Loader Utility for CodeBadger

Provides utilities to load Scala query templates from files and substitute variables.
"""

import os
from typing import Dict

from ...utils.query_rendering import escape_scala_string


class QueryLoader:
    """Utility to load Scala query templates from files."""

    _cache: Dict[str, str] = {}
    _queries_dir = os.path.dirname(__file__)
    # Sentinel used to escape {{ in user values to prevent template injection
    _ESCAPE_SENTINEL = "\x00__ESCAPED_OPEN_BRACE__\x00"

    @classmethod
    def _sanitize_value(cls, value: str) -> str:
        """Sanitize a value to prevent template injection.

        Replaces {{ sequences in user-supplied values with a sentinel
        that will be restored to literal {{ after template substitution, and
        escapes the value for safe embedding inside Scala string literals.

        Args:
            value: The user-supplied value to sanitize

        Returns:
            Sanitized value with {{ escaped
        """
        escaped = escape_scala_string(value)
        return escaped.replace("{{", cls._ESCAPE_SENTINEL)

    @classmethod
    def load(cls, query_name: str, **kwargs) -> str:
        """Load a query template and substitute variables.

        Args:
            query_name: Name of the query file (without .scala extension)
            **kwargs: Variables to substitute in the template

        Returns:
            The query string with variables substituted

        Note:
            User-supplied string values are escaped for Scala string literal
            safety, and values containing {{ are neutralized to prevent
            template injection attacks.

        Example:
            query = QueryLoader.load(
                "call_graph",
                method_name="main",
                depth=5,
                direction="outgoing"
            )
        """
        if query_name not in cls._cache:
            query_path = os.path.join(cls._queries_dir, f"{query_name}.scala")
            with open(query_path, "r", encoding="utf-8") as f:
                cls._cache[query_name] = f.read()

        template = cls._cache[query_name]

        # Substitute placeholders like {{variable_name}}
        # Sanitize values to prevent template injection via {{ in user input
        for key, value in kwargs.items():
            placeholder = f"{{{{{key}}}}}"  # {{key}}
            sanitized_value = cls._sanitize_value(str(value))
            template = template.replace(placeholder, sanitized_value)

        # Restore escaped {{ sequences to literal {{ in the final output
        template = template.replace(cls._ESCAPE_SENTINEL, "{{")

        return template

    @classmethod
    def clear_cache(cls):
        """Clear the query cache."""
        cls._cache.clear()

    @classmethod
    def get_query_path(cls, query_name: str) -> str:
        """Get the full path to a query file.

        Args:
            query_name: Name of the query file (without .scala extension)

        Returns:
            Full path to the query file
        """
        return os.path.join(cls._queries_dir, f"{query_name}.scala")

    @classmethod
    def query_exists(cls, query_name: str) -> bool:
        """Check if a query file exists.

        Args:
            query_name: Name of the query file (without .scala extension)

        Returns:
            True if the query file exists, False otherwise
        """
        return os.path.exists(cls.get_query_path(query_name))
