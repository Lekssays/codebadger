"""
Input validation utilities
"""

import hashlib
import re
from typing import Optional
from urllib.parse import urlparse

from ..exceptions import ValidationError
from ..models import SourceType


def validate_source_type(source_type: str) -> None:
    """Validate source type"""
    valid_types = [e.value for e in SourceType]
    if source_type not in valid_types:
        raise ValidationError(
            f"Invalid source_type '{source_type}'. Must be one of: {', '.join(valid_types)}"
        )


def validate_language(language: str) -> None:
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


def validate_codebase_hash(codebase_hash: str) -> None:
    """Validate codebase hash format"""
    if not codebase_hash or not isinstance(codebase_hash, str):
        raise ValidationError("codebase_hash must be a non-empty string")

    # Hash pattern (16 character hex string)
    hash_pattern = r"^[a-f0-9]{16}$"
    if not re.match(hash_pattern, codebase_hash):
        raise ValidationError("codebase_hash must be a valid 16-character hex string")



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


def validate_cpgql_query(query: str) -> None:
    """Validate CPGQL query"""
    if not query or not isinstance(query, str):
        raise ValidationError("Query must be a non-empty string")

    if len(query) > 10000:
        raise ValidationError("Query too long (max 10000 characters)")

    # Block patterns that enable shell execution, filesystem writes, or network access.
    # Joern CPGQL runs inside an Ammonite Scala REPL, so all of these are reachable.
    dangerous_patterns = [
        # Process / shell execution
        (r"System\.exit",                       "process execution"),
        (r"Runtime\.getRuntime",                "process execution"),
        (r"Runtime\.exec",                      "process execution"),
        (r"ProcessBuilder",                     "process execution"),
        (r"scala\.sys\.process",                "shell execution"),
        (r"import\s+sys\.process",              "shell execution"),
        # Filesystem writes / deletes
        (r"java\.io\.File.*\.delete",           "file deletion"),
        (r"java\.io\.FileWriter",               "file write"),
        (r"java\.io\.FileOutputStream",         "file write"),
        (r"java\.io\.PrintWriter",              "file write"),
        (r"java\.nio\.file\.Files\s*\.\s*(write|delete|move|copy)\b",
                                                "file write/delete"),
        (r"\bos\s*\.\s*(write|remove|move|copy)\s*\(", "file write/delete (Ammonite os-lib)"),
        # Network access
        (r"java\.net\.(Socket|ServerSocket)\b", "network access"),
        (r"java\.net\.URL\b.*\.(openStream|openConnection|getContent)\b",
                                                "network access"),
        (r"java\.net\.HttpURLConnection",       "network access"),
        # Reflection (can bypass the above checks)
        (r"java\.lang\.reflect\b",              "reflection"),
        (r"Class\.forName\b",                   "reflection"),
        (r"\.(getDeclaredMethod|getDeclaredField)\b", "reflection"),
    ]

    for pattern, category in dangerous_patterns:
        if re.search(pattern, query, re.IGNORECASE | re.DOTALL):
            raise ValidationError(
                f"Query contains a potentially dangerous operation ({category})"
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
                    "Path traversal attempt detected: requested path is outside the allowed root"
                )
        except ValueError:
            # Different drives on Windows
            raise ValidationError(
                "Path traversal attempt detected: requested path is outside the allowed root"
            )

        return canonical_path

    # Without allowed_root, just return the path (already cleaned above if it had ..)
    return path


def validate_timeout(timeout: int, max_timeout: int = 300) -> None:
    """Validate timeout value"""
    if timeout < 1:
        raise ValidationError("Timeout must be at least 1 second")

    if timeout > max_timeout:
        raise ValidationError(f"Timeout cannot exceed {max_timeout} seconds")


_BLOCKED_PATH_PREFIXES = (
    "/etc", "/sys", "/proc", "/dev",
    "/boot", "/run", "/var/run",
    "/root", "/var/log",
)


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
        raise ValidationError("Host path must be absolute")

    # Resolve symlinks before checking prefixes so symlink tricks can't bypass the check.
    canonical = os.path.realpath(os.path.abspath(host_path))

    if any(canonical == p or canonical.startswith(p + "/") for p in _BLOCKED_PATH_PREFIXES):
        raise ValidationError("Invalid host path")

    if not os.path.exists(canonical):
        raise ValidationError("Path does not exist")

    if not os.path.isdir(canonical):
        raise ValidationError("Path is not a directory")

    return canonical
