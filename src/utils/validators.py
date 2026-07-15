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


# Single source of truth for the languages Joern can build a CPG for. Reused by
# validate_language and the snippet helpers so error messages can list the exact
# accepted ids and the LLM can self-correct in one shot.
SUPPORTED_LANGUAGES = [
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
    "rust",
]


def validate_language(language: str) -> None:
    """Validate programming language"""
    if language not in SUPPORTED_LANGUAGES:
        raise ValidationError(
            f"Unsupported language '{language}'. Use one of the supported ids: "
            f"{', '.join(SUPPORTED_LANGUAGES)}."
        )


def validate_codebase_hash(codebase_hash: str) -> None:
    """Validate codebase hash format"""
    if not codebase_hash or not isinstance(codebase_hash, str):
        raise ValidationError("codebase_hash must be a non-empty string")

    # Hash pattern (16 character hex string)
    hash_pattern = r"^[a-f0-9]{16}$"
    if not re.match(hash_pattern, codebase_hash):
        raise ValidationError("codebase_hash must be a valid 16-character hex string")



# Only these hosts may be cloned. Anything else — alternate git hosts, raw IPs,
# localhost, cloud metadata endpoints (169.254.169.254), etc. — is rejected so a
# repo URL can't be turned into an SSRF probe or an undefined-behavior clone.
ALLOWED_REPO_HOSTS = frozenset(
    {"github.com", "www.github.com", "gitlab.com", "www.gitlab.com"}
)

# Literal `https://<host>/` prefixes derived from the allowlist. Used as a cheap
# first gate alongside the structural hostname check below: the URL must *begin*
# with one of these exact strings, which also rejects userinfo smuggling
# (`https://github.com@evil.com/…` starts with `https://github.com@`, not `…/`)
# and ports (`https://github.com:22/…`) before any parsing.
ALLOWED_REPO_URL_PREFIXES = tuple(
    sorted(f"https://{host}/" for host in ALLOWED_REPO_HOSTS)
)


def validate_repo_url(url: str) -> bool:
    """Strictly validate a remote git repository URL (github.com / gitlab.com).

    Hardened against SSRF and undefined clone behavior. The URL MUST:
      * be a string with no whitespace or control characters,
      * use the ``https`` scheme (rejects ``git://``, ``ssh://``, ``http://``,
        ``file://``, ``data:``, scp-style ``git@host:path``, …),
      * carry no embedded credentials (``https://user:tok@…`` is rejected so the
        host can't be smuggled past the allowlist via the userinfo field),
      * resolve to an exact allowlisted host (``parsed.hostname`` is lowercased
        and excludes userinfo/port, so ``github.com@evil.com`` → host ``evil.com``
        → rejected),
      * use no non-default port,
      * have an ``/owner/repo`` path (gitlab subgroups, i.e. extra segments, are
        allowed).
    """
    if not url or not isinstance(url, str):
        raise ValidationError("Repository URL must be a non-empty string")

    # Whitespace / control chars could smuggle a second git arg or a CRLF.
    if any(ord(c) < 0x20 or ord(c) == 0x7F or c.isspace() for c in url):
        raise ValidationError(
            "Repository URL must not contain whitespace or control characters"
        )

    # Literal prefix gate: the string must START with an exact allowed
    # `https://<host>/` prefix. Belt-and-suspenders with the parsed hostname
    # check below — the literal match is case-sensitive and rejects anything
    # that isn't canonically lowercase https://github.com/ or https://gitlab.com/.
    if not url.startswith(ALLOWED_REPO_URL_PREFIXES):
        raise ValidationError(
            "Repository URL must start with one of: "
            + ", ".join(ALLOWED_REPO_URL_PREFIXES)
        )

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValidationError(f"Invalid repository URL: {e}")

    if parsed.scheme != "https":
        raise ValidationError(
            f"Repository URL must use https:// (got '{parsed.scheme or 'no scheme'}')"
        )

    if parsed.username or parsed.password:
        raise ValidationError("Repository URL must not contain embedded credentials")

    if parsed.hostname not in ALLOWED_REPO_HOSTS:
        raise ValidationError(
            "Only github.com and gitlab.com repositories are supported "
            f"(got host '{parsed.hostname}')"
        )

    try:
        port = parsed.port
    except ValueError:
        raise ValidationError("Repository URL has an invalid port")
    if port is not None and port != 443:
        raise ValidationError("Repository URL must not specify a non-default port")

    # Path must be at least /owner/repo.
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise ValidationError(
            "Invalid repository URL. Expected https://github.com/owner/repo "
            "or https://gitlab.com/owner/repo"
        )

    return True


# Backwards-compatible alias. The validator now also accepts gitlab.com, but the
# old name is imported across the codebase and in tests.
validate_github_url = validate_repo_url


# LLMs are instructed (in the generate_cpg tool description) to wrap pasted code
# as <code language="c"> ... </code>. We extract the language + body here rather
# than trusting a free-form field, so the snippet is self-describing and parsing
# is unambiguous. The language attribute is required; attribute order/extras and
# single or double quotes are tolerated.
_SNIPPET_BLOCK_RE = re.compile(
    r"<code\b[^>]*?\b(?:language|lang)\s*=\s*[\"'](?P<lang>[^\"']+)[\"'][^>]*>"
    r"(?P<body>.*?)"
    r"</code\s*>",
    re.IGNORECASE | re.DOTALL,
)


def parse_snippet_blocks(text: Optional[str]):
    """Extract (language, code) from one or more <code language="..."> blocks.

    Returns ``(language, combined_code)`` when at least one well-formed block is
    present, or ``None`` when the text contains no such tag (the caller then
    falls back to the raw ``code`` + explicit ``language`` arguments). The
    language is NOT validated here — the caller runs ``validate_language`` on the
    result so snippet and non-snippet paths share one check.

    Raises ValidationError when blocks are present but malformed: blocks
    declaring different languages (one CPG is single-language), or all-empty
    bodies.
    """
    if not text or not isinstance(text, str):
        return None

    matches = list(_SNIPPET_BLOCK_RE.finditer(text))
    if not matches:
        return None

    langs = {m.group("lang").strip().lower() for m in matches}
    if len(langs) != 1:
        raise ValidationError(
            f"All <code> blocks in one snippet must declare the same language, but "
            f"found {', '.join(sorted(langs))}. One CPG is single-language — send one "
            f"language per generate_cpg call (split the others into separate calls)."
        )
    language = langs.pop()

    bodies = [m.group("body").strip("\n") for m in matches]
    code = "\n\n".join(b for b in bodies if b.strip())
    if not code.strip():
        raise ValidationError(
            "The <code language=\"...\"> tag is empty. Put the source code between the "
            "opening and closing tags, e.g. <code language=\"c\">int main(){...}</code>."
        )

    return language, code


# Distinctive per-language content signals (pattern, weight) used to infer or
# cross-check a snippet's language. Intentionally heuristic and conservative —
# the goal is to catch an obviously-mislabeled tag and to infer when no language
# is declared, NOT to be a full language classifier. ghidra/jimple are omitted on
# purpose: they are decompiled/IR formats that look like other languages and must
# be declared explicitly (never inferred, never contradicted).
_LANG_SIGNALS = {
    "python": [
        (r"\bdef\s+\w+\s*\(", 2), (r"\bimport\s+\w+", 1), (r"\bself\b", 1),
        (r"\belif\b", 2), (r"__name__", 2), (r"\bprint\s*\(", 1), (r":\s*$", 1),
    ],
    "c": [
        (r"#include\s*<\w+\.h>", 2), (r"\bint\s+main\s*\(", 1), (r"\bprintf\s*\(", 1),
        (r"\bmalloc\s*\(", 2), (r"\bstruct\s+\w+", 1), (r"\bsizeof\b", 1),
    ],
    "cpp": [
        (r"\bstd::", 3), (r"\btemplate\s*<", 2), (r"\bnamespace\b", 2),
        (r"\bcout\b", 2), (r"\bnullptr\b", 2), (r"::\w", 1),
    ],
    "java": [
        (r"\bpublic\s+class\b", 2), (r"\bimport\s+java\.", 3), (r"System\.out\.print", 2),
        (r"\bpackage\s+[\w.]+;", 2), (r"@Override", 2), (r"\bpublic\s+static\s+void\s+main", 2),
    ],
    "javascript": [
        (r"\bfunction\s+\w*\s*\(", 1), (r"\bconst\s+\w+\s*=", 1), (r"\blet\s+\w+", 1),
        (r"=>", 1), (r"console\.log\s*\(", 2), (r"\brequire\s*\(", 2), (r"module\.exports", 2),
    ],
    "go": [
        (r"\bpackage\s+\w+", 2), (r"\bfunc\s+\w*\s*\(", 1), (r":=", 2),
        (r"\bfmt\.", 2), (r"\bchan\b", 2),
    ],
    "kotlin": [
        (r"\bfun\s+\w+\s*\(", 2), (r"\bval\s+\w+", 1), (r"\bimport\s+kotlin", 3),
        (r"\bprintln\s*\(", 1), (r":\s*Unit\b", 2),
    ],
    "csharp": [
        (r"\busing\s+System", 3), (r"\bnamespace\s+\w+", 2), (r"Console\.Write", 2),
        (r"\bstatic\s+void\s+Main", 2),
    ],
    "php": [
        (r"<\?php", 3), (r"\$\w+", 1), (r"\becho\b", 1), (r"->\w", 1),
    ],
    "ruby": [
        (r"\bend\b", 1), (r"\bputs\b", 2), (r"\bdo\s*\|", 2), (r"\bnil\b", 1),
        (r"@\w+", 1), (r"\brequire\b", 1),
    ],
    "swift": [
        (r"\bguard\b", 2), (r"\bimport\s+Swift", 3), (r"\bfunc\s+\w+\s*\(", 1),
        (r"\blet\s+\w+", 1), (r"\bvar\s+\w+\s*:", 1),
    ],
    "rust": [
        (r"\bfn\s+\w+\s*\(", 2), (r"\blet\s+mut\b", 3), (r"\w+!\s*\(", 2),
        (r"\buse\s+std::", 3), (r"->\s*\w", 1), (r"\bimpl\b", 2),
        (r"#\[\w+", 2), (r"::\w", 1),
    ],
}
_LANG_SIGNALS_COMPILED = {
    lang: [(re.compile(p, re.MULTILINE), w) for p, w in sigs]
    for lang, sigs in _LANG_SIGNALS.items()
}
# Languages that can never be inferred or contradicted from content alone.
_UNINFERABLE_LANGS = frozenset({"ghidra", "jimple"})


def _language_signal_score(code: str, language: str) -> int:
    """Summed weight of distinctive markers for ``language`` found in ``code``."""
    return sum(w for pat, w in _LANG_SIGNALS_COMPILED.get(language, []) if pat.search(code))


def infer_snippet_language(code: str) -> Optional[str]:
    """Best-guess language for a code snippet, or None when not confident.

    Confident = a single clear winner: top score >= 2 and at least double the
    runner-up. Ambiguous or signal-less code returns None (the caller then
    refuses and asks for an explicit language).
    """
    if not code or not code.strip():
        return None
    scores = {lang: _language_signal_score(code, lang) for lang in _LANG_SIGNALS_COMPILED}
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_lang, top = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0
    if top >= 2 and top >= 2 * max(second, 1):
        return top_lang
    return None


def validate_and_infer_snippet_language(
    code: Optional[str], declared: Optional[str] = None
) -> str:
    """Validate + infer the language of a snippet; refuse if anything is off.

    - Empty code -> ValidationError.
    - ``declared`` given: must be a supported language. If the code shows zero
      signals for it AND confidently looks like a different language, the tag is
      mislabeled -> ValidationError. (Overlapping families like c/cpp are NOT
      refused — only a clear contradiction is.) ghidra/jimple are accepted as
      declared without a content cross-check.
    - ``declared`` absent: infer from content; a confident guess is returned,
      otherwise ValidationError asking the caller to declare it.

    Returns the resolved, supported language id.
    """
    if not code or not code.strip():
        raise ValidationError(
            "No snippet code was provided. Pass the code wrapped in a "
            "<code language=\"...\"> ... </code> tag in the `code` argument."
        )

    if declared:
        declared = declared.strip().lower()
        validate_language(declared)  # raises (with the supported list) if unsupported
        if declared in _UNINFERABLE_LANGS:
            return declared
        inferred = infer_snippet_language(code)
        if (
            inferred
            and inferred != declared
            and _language_signal_score(code, declared) == 0
        ):
            raise ValidationError(
                f"Declared language '{declared}' does not match the snippet, which "
                f"looks like '{inferred}'. Set the <code language=\"...\"> tag to the "
                f"language the code is actually written in (or fix the code)."
            )
        return declared

    inferred = infer_snippet_language(code)
    if not inferred:
        raise ValidationError(
            "Could not determine the snippet's language from its content. Declare it "
            "explicitly with a <code language=\"...\"> tag, e.g. "
            "<code language=\"c\">...</code>. Supported languages: "
            f"{', '.join(SUPPORTED_LANGUAGES)}."
        )
    return inferred


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
    """Validate a raw CPGQL query before it reaches Joern's Ammonite Scala REPL.

    IMPORTANT: this is a denylist and therefore *defense-in-depth*, not a security
    boundary. The REPL is a full Scala interpreter; a determined attacker can
    obfuscate around literal patterns. The real containment is the Joern worker
    sandbox (cgroup-capped container, restricted mounts/network). This filter
    stops casual/accidental misuse and the obvious exec/IO/network/reflection
    constructs. Only call it on UNTRUSTED raw queries (run_cpgql_query), never on
    the internally-built, already-escaped parameterized queries (a safely-escaped
    user value could legitimately contain one of these substrings).
    """
    if not query or not isinstance(query, str):
        raise ValidationError("Query must be a non-empty string")

    if len(query) > 10000:
        raise ValidationError("Query too long (max 10000 characters)")

    # Joern CPGQL runs inside an Ammonite Scala REPL, so all of these are reachable.
    dangerous_patterns = [
        # Process / shell execution
        (r"System\.exit",                       "process execution"),
        (r"\bsys\s*\.\s*exit",                  "process execution"),
        (r"Runtime\.getRuntime",                "process execution"),
        (r"Runtime\.exec",                      "process execution"),
        (r"ProcessBuilder",                     "process execution"),
        (r"ProcessImpl",                        "process execution"),
        # `scala.sys.process` and any aliased/partial import of it
        (r"sys\s*\.\s*process",                 "shell execution"),
        (r"import\s+scala\.sys\.\{?\s*process", "shell execution"),
        (r"stringToProcess",                    "shell execution"),
        (r"\.lazyLines\b",                      "shell execution"),
        # Filesystem writes / deletes
        (r"java\.io\.File.*\.delete",           "file deletion"),
        (r"java\.io\.FileWriter",               "file write"),
        (r"java\.io\.FileOutputStream",         "file write"),
        (r"java\.io\.PrintWriter",              "file write"),
        (r"java\.nio\.file\.Files\s*\.\s*(write|delete|move|copy|createFile|createDirectory|newOutputStream)\b",
                                                "file write/delete"),
        (r"\bos\s*\.\s*(write|remove|move|copy)\s*", "file write/delete (Ammonite os-lib)"),
        # Filesystem reads (host file exfiltration)
        (r"scala\.io\.Source",                  "file read"),
        (r"Source\.fromFile",                   "file read"),
        (r"java\.io\.File(Reader|InputStream)", "file read"),
        (r"java\.nio\.file\.Files\s*\.\s*(read|lines|newInputStream|newBufferedReader)",
                                                "file read"),
        (r"\bos\s*\.\s*(read|list|walk)\b",     "file read (Ammonite os-lib)"),
        # Network access
        (r"java\.net\.(Socket|ServerSocket|DatagramSocket)\b", "network access"),
        (r"java\.net\.URL\b.*\.(openStream|openConnection|getContent)\b",
                                                "network access"),
        (r"java\.net\.(URI|URL)\b",             "network access"),
        (r"java\.net\.HttpURLConnection",       "network access"),
        (r"javax\.net\b",                       "network access"),
        # Dynamic dependency / code loading (network + arbitrary code)
        (r"\$ivy",                              "dynamic dependency load"),
        (r"\$file",                             "dynamic file import"),
        (r"\binterp\s*\.",                      "Ammonite interpreter access"),
        # Reflection (can bypass the above checks)
        (r"java\.lang\.reflect\b",              "reflection"),
        (r"scala\.reflect\b",                   "reflection"),
        (r"Class\.forName\b",                   "reflection"),
        (r"\.loadClass\b",                      "reflection"),
        (r"\.(getDeclaredMethod|getDeclaredField|getMethod|getField|getClass)\b", "reflection"),
    ]

    for pattern, category in dangerous_patterns:
        if re.search(pattern, query, re.IGNORECASE | re.DOTALL):
            raise ValidationError(
                f"Query contains a potentially dangerous operation ({category})"
            )


# Catch the common catastrophic-backtracking (ReDoS) shapes: a group containing
# an inner quantifier or an alternation, immediately followed by an outer
# quantifier — e.g. (a+)+, (a*)*, (a|a)+, (.*,)+ . Heuristic, not exhaustive.
_REDOS_RE = re.compile(r"\([^)]*(?:[+*]|\|)[^)]*\)\s*[+*]")


def validate_search_pattern(pattern: Optional[str], field: str = "pattern") -> None:
    """Validate a caller-supplied regex / name filter (no-op when empty).

    Bounds length and rejects obviously catastrophic-backtracking shapes before
    the pattern is compiled (Python side) or handed to Joern's JVM regex engine.
    """
    from ..defaults import MAX_SEARCH_PATTERN_LEN

    if pattern is None or pattern == "":
        return
    if not isinstance(pattern, str):
        raise ValidationError(f"{field} must be a string")
    if len(pattern) > MAX_SEARCH_PATTERN_LEN:
        raise ValidationError(
            f"{field} too long (max {MAX_SEARCH_PATTERN_LEN} characters)"
        )
    if _REDOS_RE.search(pattern):
        raise ValidationError(
            f"{field} contains a nested-quantifier pattern that risks "
            "catastrophic backtracking; simplify it"
        )


def clamp_int(value, maximum: int, minimum: int = 1, default: Optional[int] = None) -> int:
    """Coerce value to int and clamp to [minimum, maximum].

    Used to bound caller-supplied `limit` / `take(n)` / depth parameters so an LLM
    can't request an unbounded traversal or result set. Non-numeric input falls back
    to `default` (or `minimum` when no default is given).
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default if default is not None else minimum
    return max(minimum, min(n, maximum))


def sanitize_error_text(text: Optional[str], max_len: int = 600) -> str:
    """Redact absolute filesystem paths from text echoed back to the client.

    Joern/Ammonite stack traces and OS errors embed host paths (CPG path, source
    snapshot, JVM classpath). Collapse any absolute path to its basename and bound
    the length so internal layout isn't disclosed.
    """
    if not text:
        return ""
    text = str(text)
    # Replace absolute paths like /a/b/c.scala with <path>/c.scala
    text = re.sub(r"(/[^\s'\"]+/)([^\s'\"/]+)", r"<path>/\2", text)
    if len(text) > max_len:
        text = text[:max_len] + " …(truncated)"
    return text


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


def _allowed_source_roots() -> tuple:
    """Canonical allowlisted local-source roots from ALLOWED_SOURCE_ROOTS.

    Read at call time (not import) so deployments/tests can set the env var.
    Empty/unset => no allowlist (denylist + canonicalization still apply).
    """
    raw = os.getenv("ALLOWED_SOURCE_ROOTS", "")
    return tuple(
        os.path.realpath(os.path.abspath(r)) for r in raw.split(":") if r.strip()
    )


def _is_within(canonical: str, root: str) -> bool:
    return canonical == root or canonical.startswith(root.rstrip("/") + "/")


def resolve_host_path(host_path: str, require_local_access: bool = True) -> str:
    """
    Validate and resolve a host path.

    All string-level security checks (control chars, absoluteness, blocked
    prefixes, ALLOWED_SOURCE_ROOTS containment) are always applied.

    The existence / is-directory checks require the path to be readable by THIS
    process. That holds when the MCP runs on the host (or the path is mounted
    in), but not when the MCP is containerized and the path lives on the host
    filesystem. In that case the caller copies the tree via a host-daemon helper
    container instead, so pass require_local_access=False to skip the local
    existence checks (the helper validates existence on the host).

    Args:
        host_path: Absolute path on the host
        require_local_access: When True (default), verify the path exists and is
            a directory using this process's filesystem view.

    Returns:
        The resolved absolute path

    Raises:
        ValidationError: If path doesn't exist, isn't a directory, or is unsafe
    """
    if not host_path or not isinstance(host_path, str):
        raise ValidationError("Host path must be a non-empty string")

    # Null bytes / control chars can truncate or smuggle past downstream checks.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in host_path):
        raise ValidationError("Host path must not contain control characters")

    if not os.path.isabs(host_path):
        raise ValidationError("Host path must be absolute")

    # Resolve symlinks before checking prefixes so symlink tricks (and any ".."
    # traversal) collapse to a real canonical path the checks below can trust.
    canonical = os.path.realpath(os.path.abspath(host_path))

    if any(_is_within(canonical, p) for p in _BLOCKED_PATH_PREFIXES):
        raise ValidationError("Invalid host path")

    # Optional hard containment: when ALLOWED_SOURCE_ROOTS is configured, the
    # resolved path MUST live under one of them. This is the strong traversal /
    # arbitrary-access guard for trusted (non-chat) deployments.
    roots = _allowed_source_roots()
    if roots and not any(_is_within(canonical, r) for r in roots):
        raise ValidationError("Host path is outside the allowed source roots")

    if require_local_access:
        if not os.path.exists(canonical):
            raise ValidationError("Path does not exist")

        if not os.path.isdir(canonical):
            raise ValidationError("Path is not a directory")

    return canonical
