"""
Input validation utilities
"""

import hashlib
import os
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


def validate_code_snippet(code: Optional[str]) -> None:
    """Validate a pasted code snippet (source_type='snippet')."""
    from ..defaults import MAX_SNIPPET_BYTES

    if not code or not isinstance(code, str) or not code.strip():
        raise ValidationError(
            "code is required and must be a non-empty string when source_type='snippet'"
        )

    if "\x00" in code:
        raise ValidationError("code must not contain null bytes")

    size = len(code.encode("utf-8"))
    if size > MAX_SNIPPET_BYTES:
        raise ValidationError(
            f"Code snippet is too large ({size} bytes, max {MAX_SNIPPET_BYTES}). "
            "Stage larger code as a local path or GitHub repo instead."
        )


# A snippet filename must be a single, plain path segment.
_SNIPPET_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def snippet_filename(language: str, filename: Optional[str] = None) -> str:
    """Resolve a safe, single-segment filename for a pasted snippet.

    Honors a caller-supplied name only if it's a plain, single path segment
    (no directories, no traversal, conservative charset); otherwise falls back
    to `snippet.<ext>` derived from the language.
    """
    from ..defaults import LANGUAGE_EXTENSIONS

    if filename:
        # Strip any directory components — the snippet must land directly in the
        # codebase dir, never escape it — then enforce a conservative charset.
        base = os.path.basename(filename.strip()).strip()
        if base and base not in (".", "..") and _SNIPPET_NAME_RE.match(base):
            return base

    ext = LANGUAGE_EXTENSIONS.get(language, "txt")
    return f"snippet.{ext}"


def validate_snippet_label(label: Optional[str]) -> str:
    """Validate/sanitize the human label stored for a snippet (source_path).

    Cosmetic only (stored + echoed to the client), so we bound length and strip
    control characters rather than rejecting outright. Returns the cleaned label.
    """
    if not label:
        return ""
    if not isinstance(label, str):
        raise ValidationError("source_path must be a string")
    # Drop control characters; collapse to a bounded single-line label.
    cleaned = "".join(ch for ch in label if ch.isprintable()).strip()
    return cleaned[:256]


# Git branch / ref name: conservative whitelist. Blocks the classic
# `--upload-pack=...` style argument injection and other ref-name abuses before
# the value ever reaches `git clone --branch`.
_GIT_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def validate_git_branch(branch: Optional[str]) -> None:
    """Validate a git branch/ref name (no-op when not provided)."""
    if branch is None:
        return
    if not isinstance(branch, str) or not branch.strip():
        raise ValidationError("branch must be a non-empty string when provided")

    branch = branch.strip()
    if len(branch) > 255:
        raise ValidationError("branch name too long (max 255 characters)")
    if (
        branch.startswith("-")
        or branch.startswith("/")
        or branch.endswith("/")
        or branch.endswith(".lock")
        or ".." in branch
        or "@{" in branch
        or "//" in branch
    ):
        raise ValidationError(f"Invalid git branch name: {branch!r}")
    if not _GIT_BRANCH_RE.match(branch):
        raise ValidationError(
            "branch name may only contain letters, digits, '.', '_', '/', and '-'"
        )


def validate_github_token(token: Optional[str]) -> None:
    """Validate a GitHub token's shape (no-op when not provided).

    The token is injected into the clone URL (`https://<token>@github.com/...`),
    so reject anything that could break out of that context or inject creds/host.
    """
    if token is None:
        return
    if not isinstance(token, str) or not token.strip():
        raise ValidationError("github_token must be a non-empty string when provided")
    if len(token) > 512:
        raise ValidationError("github_token too long")
    if any(ch.isspace() for ch in token) or any(c in token for c in ("@", "/", ":", "#", "?")):
        raise ValidationError("github_token contains invalid characters")


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


# Resolve each blocked prefix through the host's symlink tree so the comparison
# works correctly on macOS, where e.g. /etc -> /private/etc.
_BLOCKED_PATH_PREFIXES = tuple(
    os.path.realpath(p)
    for p in (
        "/etc", "/sys", "/proc", "/dev",
        "/boot", "/run", "/var/run",
        "/root", "/var/log",
    )
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
