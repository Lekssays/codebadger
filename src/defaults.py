"""
Centralized default configuration values.

This module contains all default configuration values used throughout the application.
This ensures a single source of truth for all configuration defaults, eliminating
duplication across config files and Python code.
"""

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 4242
SERVER_LOG_LEVEL = "INFO"
# Per-run file logging. When enabled, every run writes a timestamped log file
# under SERVER_LOG_DIR (rotated) in addition to stdout, so a `screen` run can be
# consulted after the fact instead of scrolling a firehose.
SERVER_LOG_DIR = "logs"
SERVER_LOG_TO_FILE = True
# Rotation: cap each log file and keep this many backups (per run file).
SERVER_LOG_MAX_BYTES = 50 * 1024 * 1024
SERVER_LOG_BACKUP_COUNT = 5

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

# 30 min: c2cpg/frontends on large repos (v8, full wireshark) routinely exceed
# 10 min. Scope the source path or lower this for small-only batches.
CPG_GENERATION_TIMEOUT = 1800
MAX_REPO_SIZE_MB = 1024
MIN_CPG_FILE_SIZE = 1024
OUTPUT_TRUNCATION_LENGTH = 2000

SUPPORTED_LANGUAGES = [
    "java", "c", "cpp", "javascript", "python", "go",
    "kotlin", "csharp", "ghidra", "jimple", "php", "ruby", "swift"
]

LANGUAGES_WITH_EXCLUSIONS = [
    "c", "cpp", "java", "javascript", "python", "go",
    "kotlin", "csharp", "php", "ruby"
]

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

QUERY_TIMEOUT = 300
CPG_LOAD_TIMEOUT = 300  # importCpg triggers overlay computation; kill if it exceeds this
QUERY_CACHE_ENABLED = True
QUERY_CACHE_TTL = 300
# Don't cache tool outputs larger than this (bytes) — large query results (e.g.
# full list_methods dumps) bloat the DB without much reuse benefit. Override via
# MAX_CACHE_OUTPUT_BYTES. 0 disables the cap.
MAX_CACHE_OUTPUT_BYTES = 262144

WORKSPACE_ROOT = "/tmp/codebadger"
CLEANUP_ON_SHUTDOWN = True

# Joern server pool (LRU eviction)
MAX_ACTIVE_JOERN_SERVERS = 16
JOERN_EVICTION_POLICY = "lru"

# Worker mode. "shared" = run all Joern query servers as processes
# inside the single codebadger-joern-server container (default; also the build
# container). "pool" = run each CPG's Joern server in its OWN cgroup-capped
# Docker container, so an OOM kills just that worker, not every server at once.
JOERN_WORKER_MODE = "shared"
# Image used for per-CPG worker containers in pool mode.
JOERN_WORKER_IMAGE = "codebadger-joern-server:latest"
# Port Joern binds INSIDE each pool worker container (published to a unique host
# port from the worker range below). Fixed because each container has its own
# network namespace.
JOERN_WORKER_INTERNAL_PORT = 8080
# Host-port range for pool workers. MUST be disjoint from JOERN_PORT_MIN/MAX
# (which the shared container already publishes) to avoid bind conflicts.
JOERN_WORKER_PORT_MIN = 14000
JOERN_WORKER_PORT_MAX = 14999

# Memory-aware admission. When > 0, the Joern pool admits servers
# while the sum of their per-CPG heap *reservations* stays under this budget
# (MB), evicting LRU servers to make room — instead of a fixed server count.
# 0 = auto-derive from host RAM at startup (see src/utils/recommend.py); the
# count cap above then acts only as a safety ceiling.
JOERN_MEMORY_BUDGET_MB = 0

# Evict the LRU server when the container's RSS exceeds this (MB). A backstop
# on top of the reservation ledger. 0 = auto-derive from host RAM at startup.
JOERN_RSS_EVICTION_THRESHOLD_MB = 0

# Idle reaping. A Joern query worker that hasn't served a query for this many
# seconds is offloaded (container torn down, CPG marked SLEEPING) so it stops
# pinning RAM; the next query for that codebase transparently reactivates it
# (spawn + reload CPG). This is what bounds steady-state memory to the set of
# *recently active* codebases rather than every codebase ever queried. 0 = off.
JOERN_IDLE_TTL_SECONDS = 600
# How often the background reaper scans for idle workers (seconds).
JOERN_REAPER_INTERVAL_SECONDS = 60

# MCP connection concurrency limit
MAX_MCP_CONNECTIONS = 16

# CPG build queue
CPG_BUILD_WORKERS = 4
# Max heap (GB) for each CPG-build frontend (c2cpg/javasrc2cpg/...). CRITICAL:
# without this the frontend JVM defaults its heap to ~25% of the container limit
# (~25 GB on a 100 GB cap), and N concurrent unbounded frontends exhaust host
# RAM and trigger the OOM-killer. Keep build_workers * build_heap within the
# generation reserve from scripts/recommend_config.py.
CPG_BUILD_HEAP_GB = 6
# Queue backend: "durable" = Postgres-backed jobs table (survives restart, never
# silently dropped, dedup + backpressure via the DB) — the default. "memory" =
# in-process asyncio.Queue (drops on full, lost on restart); use only for a
# throwaway single-process run.
CPG_QUEUE_BACKEND = "durable"

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
