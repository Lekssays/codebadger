"""
Input validation utilities
"""

import hashlib
import re
from typing import Optional
from urllib.parse import urlparse

from ..exceptions import ValidationError
from ..models import SourceType


def validate_source_type(source_type: str):
    """Validate source type"""
    valid_types = [e.value for e in SourceType]
    if source_type not in valid_types:
        raise ValidationError(
            f"Invalid source_type '{source_type}'. Must be one of: {', '.join(valid_types)}"
        )


def validate_language(language: str):
    """Validate programming language"""
    supported = [
        "java",
        "c",
        "cpp",
        "javascript",
        "python",
        "go",
        "kotlin",
        "csharp",
        "ghidra",
        "jimple",
        "php",
        "ruby",
        "swift",
    ]
    if language not in supported:
        raise ValidationError(
            f"Unsupported language '{language}'. Supported: {', '.join(supported)}"
        )


def validate_codebase_hash(codebase_hash: str):
    """Validate codebase hash format"""
    if not codebase_hash or not isinstance(codebase_hash, str):
        raise ValidationError("codebase_hash must be a non-empty string")

    # Hash pattern (16 character hex string)
    hash_pattern = r"^[a-f0-9]{16}$"
    if not re.match(hash_pattern, codebase_hash):
        raise ValidationError("codebase_hash must be a valid 16-character hex string")


def validate_session_id(session_id: str):
    """Validate session ID format"""
    if not session_id or not isinstance(session_id, str):
        raise ValidationError("session_id must be a non-empty string")
    
    # Session IDs should be UUIDs or similar format
    if len(session_id) < 8:
        raise ValidationError("session_id must be at least 8 characters long")

    # Hash pattern (16 character hex string)
    hash_pattern = r"^[a-f0-9]{16}$"
    if not re.match(hash_pattern, session_id):
        raise ValidationError("session_id must be a valid 16-character hex string")


def validate_github_url(url: str) -> bool:
    """Validate GitHub URL format"""
    try:
        parsed = urlparse(url)
        if parsed.netloc not in ["github.com", "www.github.com"]:
            raise ValidationError("Only GitHub URLs are supported")

        # Check for valid path format: /owner/repo
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2:
            raise ValidationError(
                "Invalid GitHub URL format. Expected: https://github.com/owner/repo"
            )

        return True
    except Exception as e:
        raise ValidationError(f"Invalid GitHub URL: {str(e)}")


def validate_local_path(path: str) -> bool:
    """Validate local file path"""
    import os

    if not os.path.isabs(path):
        raise ValidationError("Local path must be absolute")

    # Note: We don't check if the path exists here because it might be a host path
    # that is not accessible from the container. The copying logic will handle
    # existence validation.

    return True


def validate_cpgql_query(query: str):
    """Validate CPGQL query"""
    if not query or not isinstance(query, str):
        raise ValidationError("Query must be a non-empty string")

    if len(query) > 10000:
        raise ValidationError("Query too long (max 10000 characters)")

    # Basic safety checks
    dangerous_patterns = [
        r"System\.exit",
        r"Runtime\.getRuntime",
        r"ProcessBuilder",
        r"java\.io\.File.*delete",
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            raise ValidationError(
                f"Query contains potentially dangerous operation: {pattern}"
            )


def hash_query(query: str) -> str:
    """Generate hash for query caching"""
    return hashlib.sha256(query.encode()).hexdigest()


def sanitize_path(path: str, allowed_root: Optional[str] = None) -> str:
    """
    Sanitize file path by resolving it to an absolute canonical path
    and optionally validating it's within an allowed root directory.

    This prevents path traversal attacks by:
    1. Resolving all symbolic links and relative path components
    2. Converting to absolute canonical path
    3. Validating against allowed root (if provided)

    Args:
        path: File path to sanitize
        allowed_root: Optional root directory to validate against.
                     If provided, the path must be within this directory.

    Returns:
        Sanitized absolute path

    Raises:
        ValidationError: If path traversal is detected or path is outside allowed_root

    Examples:
        >>> sanitize_path("../etc/passwd", "/home/user")
        ValidationError: Path traversal attempt detected

        >>> sanitize_path("/home/user/data/../file.txt", "/home/user")
        "/home/user/file.txt"
    """
    import os

    # Detect obvious path traversal attempts before resolution
    if ".." in path:
        if allowed_root is None:
            # Without a root constraint, just remove .. patterns
            path = re.sub(r"\.\.+/?", "", path)
            return path
        else:
            # With a root constraint, we'll validate after canonicalization
            pass

    # For paths with allowed_root, canonicalize and validate
    if allowed_root is not None:
        # Canonicalize both paths (resolve symlinks, relative components)
        canonical_root = os.path.realpath(os.path.abspath(allowed_root))

        # Join with root if path is relative
        if not os.path.isabs(path):
            path = os.path.join(canonical_root, path)

        canonical_path = os.path.realpath(os.path.abspath(path))

        # Validate that canonical path is within allowed root
        # Use os.path.commonpath to check if they share a common prefix
        try:
            common = os.path.commonpath([canonical_root, canonical_path])
            if common != canonical_root:
                raise ValidationError(
                    f"Path traversal attempt detected: {path} is outside allowed root {allowed_root}"
                )
        except ValueError:
            # Different drives on Windows
            raise ValidationError(
                f"Path traversal attempt detected: {path} is outside allowed root {allowed_root}"
            )

        return canonical_path

    # Without allowed_root, just return the path (already cleaned above if it had ..)
    return path


def validate_timeout(timeout: int, max_timeout: int = 300):
    """Validate timeout value"""
    if timeout < 1:
        raise ValidationError("Timeout must be at least 1 second")

    if timeout > max_timeout:
        raise ValidationError(f"Timeout cannot exceed {max_timeout} seconds")


def resolve_host_path(host_path: str) -> str:
    """
    Validate and resolve a host path.
    
    Since the MCP server runs on the host, we can properly validate
    that the path exists and is a directory.
    
    Args:
        host_path: Absolute path on the host
        
    Returns:
        The resolved absolute path
        
    Raises:
        ValidationError: If path doesn't exist, isn't a directory, or is unsafe
    """
    import os
    
    if not os.path.isabs(host_path):
        raise ValidationError(f"Host path must be absolute: {host_path}")
    
    # Check for dangerous patterns
    if ".." in host_path or host_path.startswith("/etc") or host_path.startswith("/sys"):
        raise ValidationError(f"Invalid host path: {host_path}")
    
    # Now we can properly validate existence (running on host)
    if not os.path.exists(host_path):
        raise ValidationError(f"Path does not exist: {host_path}")
    
    if not os.path.isdir(host_path):
        raise ValidationError(f"Path is not a directory: {host_path}")
    
    return os.path.abspath(host_path)
