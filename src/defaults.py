"""
Centralized default configuration values.

This module contains all default configuration values used throughout the application.
This ensures a single source of truth for all configuration defaults, eliminating
duplication across config files and Python code.
"""

# Server defaults
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 4242
SERVER_LOG_LEVEL = "INFO"

# Joern defaults
JOERN_BINARY_PATH = "joern"
JOERN_MEMORY_LIMIT = "4g"
JOERN_JAVA_OPTS = "-Xmx4G -Xms2G -XX:+UseG1GC -XX:+UseStringDeduplication -Dfile.encoding=UTF-8"
JOERN_SERVER_HOST = "localhost"
JOERN_SERVER_PORT = 8080
JOERN_PORT_MIN = 13371
JOERN_PORT_MAX = 13870
JOERN_SERVER_INIT_SLEEP_TIME = 3.0
JOERN_SERVER_STARTUP_TIMEOUT = 300

# Joern HTTP connection pooling defaults
HTTP_POOL_CONNECTIONS = 10
HTTP_POOL_MAXSIZE = 10
HTTP_CONNECT_TIMEOUT = 5.0
HTTP_READ_TIMEOUT = 300.0
HTTP_MAX_RETRIES = 3
HTTP_BACKOFF_FACTOR = 0.3

# CPG defaults
CPG_GENERATION_TIMEOUT = 600
MAX_REPO_SIZE_MB = 1024
MIN_CPG_FILE_SIZE = 1024
OUTPUT_TRUNCATION_LENGTH = 2000

# Supported languages for CPG generation
SUPPORTED_LANGUAGES = [
    "java", "c", "cpp", "javascript", "python", "go",
    "kotlin", "csharp", "ghidra", "jimple", "php", "ruby", "swift"
]

# Languages with exclusion pattern support
LANGUAGES_WITH_EXCLUSIONS = [
    "c", "cpp", "java", "javascript", "python", "go",
    "kotlin", "csharp", "php", "ruby"
]

# Default exclusion patterns for CPG generation
EXCLUSION_PATTERNS = [
    ".*/\\..*", "\\..*",
    ".*/test.*", "test.*",
    ".*/fuzz.*", "fuzz.*",
    ".*/Testing.*", "Testing.*",
    ".*/spec.*", "spec.*",
    ".*/__tests__/.*", "__tests__/.*",
    ".*/e2e.*", "e2e.*",
    ".*/integration.*", "integration.*",
    ".*/unit.*", "unit.*",
    ".*/benchmark.*", "benchmark.*",
    ".*/perf.*", "perf.*",
    ".*/docs?/.*", "docs?/.*",
    ".*/documentation.*", "documentation.*",
    ".*/example.*", "example.*",
    ".*/sample.*", "sample.*",
    ".*/demo.*", "demo.*",
    ".*/tutorial.*", "tutorial.*",
    ".*/guide.*", "guide.*",
    ".*/build.*/.*", ".*_build/.*",
    ".*/target/.*", ".*/out/.*",
    ".*/dist/.*", ".*/bin/.*",
    ".*/obj/.*", ".*/Debug/.*",
    ".*/Release/.*", ".*/cmake/.*",
    ".*/m4/.*", ".*/autom4te.*/.*",
    ".*/autotools/.*", ".*/\\.git/.*",
    ".*/\\.svn/.*", ".*/\\.hg/.*",
    ".*/\\.deps/.*", ".*/node_modules/.*",
    ".*/vendor/.*", ".*/third_party/.*",
    ".*/extern/.*", ".*/external/.*",
    ".*/packages/.*", ".*/benchmark.*/.*",
    ".*/perf.*/.*", ".*/profile.*/.*",
    ".*/bench/.*", ".*/tool.*/.*",
    ".*/script.*/.*", ".*/utils/.*",
    ".*/util/.*", ".*/helper.*/.*",
    ".*/misc/.*", ".*/python/.*",
    ".*/java/.*", ".*/ruby/.*",
    ".*/perl/.*", ".*/php/.*",
    ".*/csharp/.*", ".*/dotnet/.*",
    ".*/go/.*", ".*/generated/.*",
    ".*/gen/.*", ".*/temp/.*",
    ".*/tmp/.*", ".*/cache/.*",
    ".*/\\.cache/.*", ".*/log.*/.*",
    ".*/logs/.*", ".*/result.*/.*",
    ".*/results/.*", ".*/output/.*",
    ".*\\.md$", ".*\\.txt$",
    ".*\\.xml$", ".*\\.json$",
    ".*\\.yaml$", ".*\\.yml$",
    ".*\\.toml$", ".*\\.ini$",
    ".*\\.cfg$", ".*\\.conf$",
    ".*\\.properties$", ".*\\.cmake$",
    ".*Makefile.*", ".*makefile.*",
    ".*configure.*", ".*\\.am$",
    ".*\\.in$", ".*\\.ac$",
    ".*\\.log$", ".*\\.cache$",
    ".*\\.lock$", ".*\\.tmp$",
    ".*\\.bak$", ".*\\.orig$",
    ".*\\.swp$", ".*~$",
    ".*/\\.vscode/.*", ".*/\\.idea/.*",
    ".*/\\.eclipse/.*", ".*\\.DS_Store$",
    ".*Thumbs\\.db$"
]

# Query defaults
QUERY_TIMEOUT = 300
CPG_LOAD_TIMEOUT = 300  # importCpg triggers overlay computation; kill if it exceeds this
QUERY_CACHE_ENABLED = True
QUERY_CACHE_TTL = 300

# Storage defaults
WORKSPACE_ROOT = "/tmp/codebadger"
CLEANUP_ON_SHUTDOWN = True

# Joern server pool (LRU eviction)
MAX_ACTIVE_JOERN_SERVERS = 16
JOERN_EVICTION_POLICY = "lru"

# MCP connection concurrency limit
MAX_MCP_CONNECTIONS = 16

# CPG build queue
CPG_BUILD_WORKERS = 4

# Language-specific Joern frontend binaries (full paths inside the container)
LANGUAGE_COMMANDS = {
    "java":       "/opt/joern/joern-cli/javasrc2cpg",
    "c":          "/opt/joern/joern-cli/c2cpg.sh",
    "cpp":        "/opt/joern/joern-cli/c2cpg.sh",
    "javascript": "/opt/joern/joern-cli/jssrc2cpg.sh",
    "python":     "/opt/joern/joern-cli/pysrc2cpg",
    "go":         "/opt/joern/joern-cli/gosrc2cpg",
    "kotlin":     "/opt/joern/joern-cli/kotlin2cpg",
    "csharp":     "/opt/joern/joern-cli/csharpsrc2cpg",
    "ghidra":     "/opt/joern/joern-cli/ghidra2cpg",
    "jimple":     "/opt/joern/joern-cli/jimple2cpg",
    "php":        "/opt/joern/joern-cli/php2cpg",
    "ruby":       "/opt/joern/joern-cli/rubysrc2cpg",
    "swift":      "/opt/joern/joern-cli/swiftsrc2cpg.sh",
}
