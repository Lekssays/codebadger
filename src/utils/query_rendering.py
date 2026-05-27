"""Helpers for rendering user input into CPGQL/Scala query strings safely."""

from typing import Any


def escape_scala_string(value: Any) -> str:
    """Escape a value for safe embedding inside a Scala string literal.

    This preserves the caller's text or regex semantics while preventing the
    value from terminating the surrounding string literal and injecting
    additional Scala/CPGQL fragments.
    """
    text = str(value)
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("\b", "\\b")
        .replace("\f", "\\f")
    )