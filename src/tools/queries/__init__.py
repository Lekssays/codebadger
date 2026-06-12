"""
Query Loader Utility for CodeBadger

Provides utilities to load Scala query templates from files and substitute variables.
"""

import os
from typing import Dict

from ...utils.query_rendering import escape_scala_string
from ...utils.validators import clamp_int
from ...defaults import MAX_RESULT_ROWS, MAX_TRAVERSAL_DEPTH


class QueryLoader:
    """Utility to load Scala query templates from files."""

    _cache: Dict[str, str] = {}
    _queries_dir = os.path.dirname(__file__)
    # Sentinel used to escape {{ in user values to prevent template injection
    _ESCAPE_SENTINEL = "\x00__ESCAPED_OPEN_BRACE__\x00"

    # Caller-supplied numeric placeholders are clamped before substitution so an
    # LLM can't request an unbounded `.take(n)` or a runaway graph traversal. Maps
    # placeholder name -> ceiling.
    _NUMERIC_CEILINGS = {
        "limit": MAX_RESULT_ROWS,
        "max_results": MAX_RESULT_ROWS,
        "max_nodes": MAX_RESULT_ROWS,
        "depth": MAX_TRAVERSAL_DEPTH,
        "max_depth": MAX_TRAVERSAL_DEPTH,
    }

    # Placeholders interpolated into the query as BARE integers (line numbers,
    # node ids — e.g. `val sourceLine = {{source_line}}`, `{{source_node_id}}L`),
    # not inside a string literal. They have no natural ceiling, but they MUST be
    # integers: string-escaping them (the default path) would let a non-numeric
    # value land as a raw Scala token — a syntax break at best, an injection at
    # worst. Coerce to int and fail fast otherwise.
    _INT_PLACEHOLDERS = frozenset({
        "line_num", "source_line", "sink_line", "source_node_id", "sink_node_id",
    })

    # Placeholders interpolated as bare Scala booleans (`val includeForward =
    # {{include_forward}}`). Rendered as lowercase true/false so a stray Python
    # `True` (which str()s to "True") can't produce invalid Scala.
    _BOOL_PLACEHOLDERS = frozenset({
        "include_backward", "include_forward", "include_control_flow",
    })

    _TRUE_STRINGS = frozenset({"true", "1", "yes"})
    _FALSE_STRINGS = frozenset({"false", "0", "no"})

    @classmethod
    def _coerce_int(cls, key: str, value) -> str:
        """Render a bare-integer placeholder, raising on a non-integer value."""
        try:
            return str(int(value))
        except (TypeError, ValueError):
            raise ValueError(
                f"Query placeholder '{key}' must be an integer, got {value!r}"
            )

    @classmethod
    def _coerce_bool(cls, key: str, value) -> str:
        """Render a bare-boolean placeholder as lowercase Scala true/false."""
        if isinstance(value, bool):
            return "true" if value else "false"
        s = str(value).strip().lower()
        if s in cls._TRUE_STRINGS:
            return "true"
        if s in cls._FALSE_STRINGS:
            return "false"
        raise ValueError(
            f"Query placeholder '{key}' must be a boolean, got {value!r}"
        )

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
        # Sanitize values to prevent template injection via {{ in user input;
        # clamp known numeric placeholders to their resource ceiling.
        for key, value in kwargs.items():
            placeholder = f"{{{{{key}}}}}"  # {{key}}
            if key in cls._NUMERIC_CEILINGS:
                sanitized_value = str(clamp_int(value, cls._NUMERIC_CEILINGS[key]))
            elif key in cls._INT_PLACEHOLDERS:
                sanitized_value = cls._coerce_int(key, value)
            elif key in cls._BOOL_PLACEHOLDERS:
                sanitized_value = cls._coerce_bool(key, value)
            else:
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
