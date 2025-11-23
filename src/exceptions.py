"""
Custom exceptions for CodeBadger Server
"""


class JoernMCPException(Exception):
    """Base exception for CodeBadger"""

    pass


# Alias for backward compatibility
JoernMCPError = JoernMCPException


class CPGGenerationError(JoernMCPException):
    """CPG generation failed"""

    pass


class QueryExecutionError(JoernMCPException):
    """Query execution failed"""

    pass


class ResourceLimitError(JoernMCPException):
    """Resource limit exceeded"""

    pass


class ValidationError(JoernMCPException):
    """Input validation failed"""

    pass


class GitOperationError(JoernMCPException):
    """Git operation failed"""

    pass
