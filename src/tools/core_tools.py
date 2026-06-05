"""
Core MCP Tools for CodeBadger Server - Simplified hash-based version

Provides core CPG management functionality
"""

import asyncio
import docker
import hashlib
import io
import logging
import os
import re
import shutil
import tarfile
from typing import Any, Dict, Optional, Annotated, Set
from pydantic import Field

from ..defaults import LANGUAGE_COMMANDS
from ..exceptions import ValidationError
from ..models import CodebaseInfo, SessionStatus
from ..utils.validators import (
    validate_github_url,
    validate_language,
    validate_local_path,
    validate_source_type,
    resolve_host_path,
)

logger = logging.getLogger(__name__)

REDACTED_HOST_PATH = "<redacted:host-path>"
REDACTED_CONTAINER_PATH = "<redacted:container-path>"
REDACTED_LOCAL_SOURCE = "<redacted:local-source>"


def _public_source_path(source_type: str, source_path: Optional[str]) -> Optional[str]:
    """Redact local source paths before returning them to clients."""
    if not source_path:
        return source_path
    if source_type == "local":
        return REDACTED_LOCAL_SOURCE
    return source_path


def _redact_public_path(path: Optional[str], replacement: str) -> Optional[str]:
    if not path:
        return path
    return replacement


def _public_codebase_fields(
    *,
    source_type: str,
    source_path: Optional[str],
    language: str,
    cpg_path: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    include_internal_paths: bool = False,
    include_repository: bool = False,
) -> Dict[str, Any]:
    """Return client-safe codebase fields without exposing host or container paths."""
    metadata = metadata or {}
    fields: Dict[str, Any] = {
        "cpg_path": _redact_public_path(cpg_path, REDACTED_HOST_PATH),
        "source_type": source_type,
        "source_path": _public_source_path(source_type, source_path),
        "language": language,
    }

    if include_internal_paths:
        fields["container_codebase_path"] = _redact_public_path(
            metadata.get("container_codebase_path"), REDACTED_CONTAINER_PATH
        )
        fields["container_cpg_path"] = _redact_public_path(
            metadata.get("container_cpg_path"), REDACTED_CONTAINER_PATH
        )

    if include_repository:
        fields["repository"] = metadata.get("repository")

    return fields


def _get_restart_task_registry(services: dict) -> Dict[str, asyncio.Task]:
    return services.setdefault("restart_tasks", {})


def _get_active_restart_task(services: dict, codebase_hash: str) -> Optional[asyncio.Task]:
    registry = _get_restart_task_registry(services)
    task = registry.get(codebase_hash)
    if task is not None and task.done():
        registry.pop(codebase_hash, None)
        return None
    return task


def _schedule_restart_server_task(codebase_hash: str, container_cpg_path: str, services: dict) -> bool:
    if _get_active_restart_task(services, codebase_hash):
        return False

    task = asyncio.create_task(
        _restart_server_async(
            codebase_hash=codebase_hash,
            container_cpg_path=container_cpg_path,
            services=services,
        )
    )

    registry = _get_restart_task_registry(services)
    registry[codebase_hash] = task

    def _cleanup(done_task: asyncio.Task) -> None:
        current_task = registry.get(codebase_hash)
        if current_task is done_task:
            registry.pop(codebase_hash, None)

    task.add_done_callback(_cleanup)
    return True


def _get_git_commit_hash(path: str) -> Optional[str]:
    """
    Get the current git commit hash for a path if it's in a git repo.
    """
    try:
        import subprocess
        # Run git rev-parse HEAD
        process = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=path,
            capture_output=True,
            text=True,
            check=True
        )
        commit_hash = process.stdout.strip()
        return commit_hash
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None

def get_cpg_cache_key(source_type: str, source_path: str, language: str, commit_hash: Optional[str] = None) -> str:
    """
    Generate a deterministic CPG cache key based on source type, path, language, and optional commit hash.
    """
    if source_type == "github":
        # Extract owner/repo from GitHub URL
        if "github.com/" in source_path:
            parts = source_path.split("github.com/")[-1].split("/")
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1].replace(".git", "")
                identifier = f"github:{owner}/{repo}:{language}"
            else:
                identifier = f"github:{source_path}:{language}"
        else:
            identifier = f"github:{source_path}:{language}"
    else:
        # For local paths, use absolute path
        source_path = os.path.abspath(source_path)
        identifier = f"local:{source_path}:{language}"

    if commit_hash:
        identifier += f":{commit_hash}"

    hash_digest = hashlib.sha256(identifier.encode()).hexdigest()[:16]
    return hash_digest


def get_cpg_cache_path(cache_key: str, playground_path: str) -> str:
    """
    Generate the CPG cache file path for a given cache key and playground path.
    """
    return os.path.join(playground_path, "cpgs", cache_key, "cpg.bin")


_SKIP_DIRS = {'.git', '.svn', '.hg', '.idea', '.vscode', 'node_modules', '__pycache__'}
_TEXT_EXTENSIONS = {
    '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx',
    '.java', '.kt', '.kts', '.scala',
    '.py', '.js', '.ts', '.jsx', '.tsx',
    '.go', '.cs', '.php', '.rb', '.swift',
    '.rs', '.sh', '.bash', '.xml', '.json', '.yaml', '.yml',
}


def _scan_repo(source_path: str) -> tuple:
    """Single-pass directory walk returning (size_mb: int, loc: int).

    Combining both metrics into one walk halves filesystem I/O versus calling
    _calculate_repo_size_mb and _count_lines_of_code separately.
    """
    total_size = 0
    total_lines = 0
    try:
        for dirpath, dirnames, filenames in os.walk(source_path):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except OSError as e:
                    logger.warning(f"Failed to get size of {filepath}: {e}")
                    continue
                if os.path.splitext(filename)[1].lower() in _TEXT_EXTENSIONS:
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            total_lines += sum(1 for _ in f)
                    except OSError:
                        pass
    except Exception as e:
        logger.error(f"Failed to scan repository: {e}")
        raise
    return int(total_size / (1024 * 1024)), total_lines


def _count_lines_of_code(source_path: str) -> int:
    """Count total lines of code in a repository, skipping binary and non-source files."""
    try:
        _, loc = _scan_repo(source_path)
        return loc
    except Exception as e:
        logger.error(f"Failed to count lines of code: {e}")
        return 0


def _calculate_repo_size_mb(source_path: str) -> int:
    """Calculate total repository size in MB."""
    size_mb, _ = _scan_repo(source_path)
    return size_mb


def _estimate_processing_time(source_path: str, language: str, has_cpg: bool = False) -> str:
    """Estimate processing time based on codebase size and whether CPG already exists.
    
    Returns a human-readable time estimate string.
    """
    try:
        size_mb = _calculate_repo_size_mb(source_path)
    except Exception:
        size_mb = 0

    if has_cpg:
        # Only need to load CPG into Joern + warm cache
        if size_mb > 200:
            return "~3-8 minutes (loading large CPG into Joern server)"
        elif size_mb > 50:
            return "~1-3 minutes (loading CPG into Joern server)"
        else:
            return "~30-60 seconds (loading CPG into Joern server)"
    else:
        # Full pipeline: CPG generation + Joern load + cache warm-up
        if size_mb > 200:
            return "~5-15 minutes (large codebase: CPG generation + server loading)"
        elif size_mb > 50:
            return "~2-5 minutes (CPG generation + server loading)"
        elif size_mb > 10:
            return "~1-3 minutes (CPG generation + server loading)"
        else:
            return "~30-90 seconds (CPG generation + server loading)"


async def _restart_server_async(
    codebase_hash: str,
    container_cpg_path: str,
    services: dict,
):
    """Async task to restart Joern server and reload CPG for an existing codebase."""
    logger = logging.getLogger(__name__)
    try:
        joern_server_manager = services.get("joern_server_manager")
        codebase_tracker = services["codebase_tracker"]

        if not joern_server_manager:
            logger.error(f"No joern_server_manager available for restart of {codebase_hash}")
            return

        logger.info(f"Async: starting Joern server for {codebase_hash}")
        loop = asyncio.get_running_loop()
        joern_port = await loop.run_in_executor(
            None, joern_server_manager.spawn_server, codebase_hash
        )
        logger.info(f"Async: Joern server started on port {joern_port}, loading CPG...")

        await loop.run_in_executor(
            None, joern_server_manager.load_cpg, codebase_hash, container_cpg_path
        )
        logger.info(f"Async: CPG loaded into Joern server on port {joern_port}")

        # Update DB
        codebase_tracker.update_codebase(
            codebase_hash=codebase_hash,
            joern_port=joern_port,
            metadata={"status": SessionStatus.READY}
        )

        # Trigger cache warm-up
        if "code_browsing_service" in services:
            logger.info(f"Async: starting cache warm-up for {codebase_hash}")
            try:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, services["code_browsing_service"].warm_up_cache, codebase_hash)
                logger.info(f"Async: cache warm-up complete for {codebase_hash}")
            except Exception as e:
                logger.warning(f"Async: cache warm-up failed for {codebase_hash}: {e}")

        logger.info(f"Async: server restart complete for {codebase_hash}")
    except Exception as e:
        logger.error(f"Async: failed to restart server for {codebase_hash}: {e}", exc_info=True)
        try:
            codebase_tracker = services["codebase_tracker"]
            codebase_tracker.update_codebase(
                codebase_hash=codebase_hash,
                metadata={"status": SessionStatus.FAILED, "error": f"Server restart failed: {e}"}
            )
        except Exception:
            pass


async def _generate_cpg_async(
    codebase_hash: str,
    codebase_dir: str,
    cpg_path: str,
    language: str,
    container_cpg_path: str,
    services: dict
):
    """Async task to generate CPG and start Joern server"""
    import logging
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"Starting async CPG generation for {codebase_hash}")

        # Get services
        codebase_tracker = services["codebase_tracker"]
        joern_server_manager = services.get("joern_server_manager")
        config = services.get("config")

        # Validate repository size before CPG generation
        if config:
            repo_size_mb = _calculate_repo_size_mb(codebase_dir)
            max_size_mb = config.cpg.max_repo_size_mb
            logger.info(f"Repository size: {repo_size_mb}MB, max allowed: {max_size_mb}MB")

            if repo_size_mb > max_size_mb:
                error_msg = (
                    f"Repository size ({repo_size_mb}MB) exceeds maximum allowed "
                    f"({max_size_mb}MB). Please reduce the repository size or increase "
                    f"the max_repo_size_mb configuration."
                )
                logger.error(error_msg)
                codebase_tracker.update_codebase(
                    codebase_hash=codebase_hash,
                    metadata={"status": SessionStatus.FAILED, "error": error_msg}
                )
                return

        # Use Docker API to generate CPG inside container
        docker_client = docker.from_env()
        container_name = (
            joern_server_manager.container_name
            if joern_server_manager
            else os.getenv("JOERN_CONTAINER_NAME", "codebadger-joern-server")
        )
        try:
            container = docker_client.containers.get(container_name)
        except docker.errors.NotFound:
            error_msg = (
                f"Docker container '{container_name}' not found. "
                f"Please start it with: docker compose up -d"
            )
            logger.error(error_msg)
            codebase_tracker.update_codebase(
                codebase_hash=codebase_hash,
                metadata={"status": SessionStatus.FAILED, "error": error_msg}
            )
            return
        except docker.errors.DockerException as e:
            error_msg = f"Docker error: {e}"
            logger.error(error_msg)
            codebase_tracker.update_codebase(
                codebase_hash=codebase_hash,
                metadata={"status": SessionStatus.FAILED, "error": error_msg}
            )
            return

        cmd_binary = LANGUAGE_COMMANDS.get(language)
        if not cmd_binary:
            raise ValueError(f"Unsupported language: {language}")

        # Build command
        cmd = [cmd_binary, f"/playground/codebases/{codebase_hash}", "-o", container_cpg_path]

        # Apply exclusion patterns if config is available
        if config and language in config.cpg.languages_with_exclusions and config.cpg.exclusion_patterns:
            # Validate and combine exclusion patterns
            escaped_patterns = []
            for pattern in config.cpg.exclusion_patterns:
                try:
                    re.compile(pattern)
                    escaped_patterns.append(pattern)
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {e}. Using literal match.")
                    escaped_patterns.append(re.escape(pattern))

            combined_regex = "|".join(f"({p})" for p in escaped_patterns)
            cmd.extend(["--exclude-regex", combined_regex])
            logger.info(f"Applied {len(config.cpg.exclusion_patterns)} exclusion patterns")

        logger.info(f"Executing CPG generation in container: {' '.join(cmd)}")

        # exec_run is a synchronous blocking Docker SDK call.  Running it bare in an
        # async coroutine would freeze the entire asyncio event loop for the duration
        # of the Joern process (potentially hours if c2cpg hangs on certain C codebases).
        # We offload it to a thread-pool executor and wrap with wait_for so we can
        # enforce the configured generation_timeout and keep the event loop responsive.
        generation_timeout = config.cpg.generation_timeout if config else 600
        loop = asyncio.get_running_loop()
        try:
            exec_result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: container.exec_run(cmd=cmd, stream=False)),
                timeout=generation_timeout,
            )
        except asyncio.TimeoutError:
            error_msg = f"CPG generation timed out after {generation_timeout}s"
            logger.error(f"{error_msg} for {codebase_hash}")
            try:
                # pkill by the codebase source path rather than the frontend script name.
                # The shell wrapper (c2cpg.sh, javasrc2cpg, …) passes the source path to the
                # JVM as a positional argument, so both the shell process and the Java child
                # have it in their command lines.  pkill -f on the script name alone would
                # only kill the wrapper; the JVM child would survive as an orphan at 100% CPU
                # and the executor thread running exec_run would stay blocked forever.
                # Using -9 (SIGKILL) ensures the JVM can't defer or ignore the signal.
                source_path_in_container = f"/playground/codebases/{codebase_hash}"
                container.exec_run(["pkill", "-9", "-f", source_path_in_container], stream=False)
                logger.info(f"Killed hung {cmd_binary} process in container for {codebase_hash}")
            except Exception as kill_err:
                logger.warning(f"Failed to kill hung frontend in container: {kill_err}")
            codebase_tracker.update_codebase(
                codebase_hash=codebase_hash,
                metadata={"status": SessionStatus.FAILED, "error": error_msg}
            )
            return

        if exec_result.exit_code != 0:
            error_msg = f"CPG generation failed: {exec_result.output.decode('utf-8')}"
            logger.error(error_msg)
            codebase_tracker.update_codebase(
                codebase_hash=codebase_hash,
                metadata={"status": SessionStatus.FAILED, "error": error_msg}
            )
            return

        logger.info(f"CPG generated successfully: {cpg_path}")

        # Persist cpg_path before attempting server spawn so that the watchdog's
        # _respawn_server can find it even if spawn_server fails mid-flight.
        codebase_tracker.update_codebase(
            codebase_hash=codebase_hash,
            cpg_path=cpg_path,
            metadata={
                "status": SessionStatus.GENERATING,
                "container_codebase_path": f"/playground/codebases/{codebase_hash}",
                "container_cpg_path": container_cpg_path,
            }
        )

        # Step 4: Start Joern server with randomly assigned port (13371-13870)
        # spawn_server polls with time.sleep and load_cpg blocks on HTTP for up to
        # cpg_load_timeout seconds.  Both must run in the executor so they do not
        # freeze the event loop (which would drop SSE heartbeats and cause the
        # client's httpx stream to ReadTimeout).
        joern_port = None
        if joern_server_manager:
            try:
                logger.info(f"Spawning Joern server for {codebase_hash}")
                joern_port = await loop.run_in_executor(
                    None, joern_server_manager.spawn_server, codebase_hash
                )
                logger.info(f"Joern server started on port {joern_port}")

                # Load CPG into server (use container path, not host path)
                loaded = await loop.run_in_executor(
                    None, joern_server_manager.load_cpg, codebase_hash, container_cpg_path
                )
                if loaded:
                    logger.info(f"CPG loaded into Joern server on port {joern_port}")
                else:
                    logger.warning("Failed to load CPG into Joern server")
                    error_msg = "CPG generated but failed to load into Joern server"
                    codebase_tracker.update_codebase(
                        codebase_hash=codebase_hash,
                        cpg_path=cpg_path,
                        joern_port=None,
                        metadata={
                            "status": SessionStatus.FAILED,
                            "error": error_msg,
                            "container_codebase_path": f"/playground/codebases/{codebase_hash}",
                            "container_cpg_path": container_cpg_path
                        }
                    )
                    logger.error(f"CPG generation complete but server load failed for {codebase_hash}")
                    return
            except Exception as e:
                logger.error(f"Failed to start Joern server: {e}", exc_info=True)

        # Update DB with final metadata (preserving container paths)
        codebase_tracker.update_codebase(
            codebase_hash=codebase_hash,
            cpg_path=cpg_path,
            joern_port=joern_port,
            metadata={
                "status": "ready",
                "container_codebase_path": f"/playground/codebases/{codebase_hash}",
                "container_cpg_path": container_cpg_path
            }
        )
        
        logger.info(f"CPG generation complete for {codebase_hash}, port: {joern_port}")

        # Trigger cache warm-up
        if "code_browsing_service" in services:
            logger.info(f"Starting cache warm-up for {codebase_hash}")
            try:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, services["code_browsing_service"].warm_up_cache, codebase_hash)
                logger.info(f"Cache warm-up complete for {codebase_hash}")
            except Exception as e:
                logger.error(f"Cache warm-up failed for {codebase_hash}: {e}")
        
    except Exception as e:
        logger.error(f"Error in async CPG generation for {codebase_hash}: {e}", exc_info=True)
        try:
            codebase_tracker = services["codebase_tracker"]
            codebase_tracker.update_codebase(
                codebase_hash=codebase_hash,
                metadata={"status": SessionStatus.FAILED, "error": str(e)}
            )
        except Exception as tracker_error:
            logger.error(f"Failed to update codebase status in error handler: {tracker_error}")


class CPGGenerationQueue:
    """Bounded async queue for CPG generation jobs (B1 dedup + B3 concurrency limit)."""

    # Sentinel values returned by submit() so callers can distinguish outcomes.
    SUBMITTED = "submitted"
    DUPLICATE = "duplicate"
    QUEUE_FULL = "queue_full"

    def __init__(self, workers: int = 2, maxsize: int = 0):
        # maxsize=0 means unlimited; default is capped by the caller based on workers.
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._maxsize = maxsize
        self._workers = workers
        self._in_flight: Set[str] = set()
        self._tasks: list = []

    async def start(self) -> None:
        for _ in range(self._workers):
            task = asyncio.create_task(self._worker())
            self._tasks.append(task)

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def submit(self, codebase_hash: str, job: dict) -> str:
        """Submit a CPG generation job.

        Returns SUBMITTED, DUPLICATE (already in-flight), or QUEUE_FULL.
        """
        if codebase_hash in self._in_flight:
            return self.DUPLICATE
        if self._maxsize and self._queue.qsize() >= self._maxsize:
            return self.QUEUE_FULL
        self._in_flight.add(codebase_hash)
        await self._queue.put((codebase_hash, job))
        return self.SUBMITTED

    @property
    def depth(self) -> int:
        return self._queue.qsize()

    async def _worker(self) -> None:
        while True:
            codebase_hash, job = await self._queue.get()
            try:
                await _generate_cpg_async(**job)
            except Exception as e:
                logger.error(f"CPG generation job for {codebase_hash} failed: {e}", exc_info=True)
            finally:
                self._in_flight.discard(codebase_hash)
                self._queue.task_done()


def register_core_tools(mcp, services: dict):
    """Register core MCP tools with the FastMCP server"""

    @mcp.tool(
        description="""Generate a Code Property Graph (CPG) for a codebase.

This tool initiates the analysis process by generating a CPG for the specified codebase.
For GitHub repositories, it clones the repo first. For local paths, it copies the source code.
The CPG is cached by a hash of the codebase.

IMPORTANT — large project guard:
Before calling this tool for a local path, check the project size. If the project has more than
15,000 lines of code OR is larger than 150 MB, you MUST warn the user first:
  "This project is large (X lines / Y MB). CPG generation may take a long time and consume
   significant resources. Consider providing the absolute path to a specific sub-component
   (e.g. /path/to/repo/src/module) to scope the analysis. If you still want to analyze the
   full project, I will proceed."
Only call generate_cpg after the user either provides a scoped path or explicitly confirms
they want the full project. Pass force=True when the user confirms the full project.
This guard does NOT apply to GitHub URLs — size is unknown until cloned.

Args:
    source_type: Either 'local' or 'github'.
    source_path: Absolute path (local) or full GitHub URL.
    language: Programming language (java, c, cpp, python, javascript, go, etc.).
    github_token: Optional PAT for private repos.
    branch: Optional specific git branch.
    force: Set to True to skip the large-project size warning (use when the user has
           explicitly confirmed they want to analyze the full project).

Returns:
    {
        "codebase_hash": "hash of the codebase",
        "status": "ready" | "generating" | "cached",
        "message": "Status message",
        "cpg_path": "path to CPG file"
    }

Notes:
    - This is an async operation. Use get_cpg_status to check progress.
    - Large codebases may take several minutes to analyze.
    - Supported languages: c, cpp, java, javascript, python, go, kotlin, csharp, php, ruby, swift.

Examples:
    generate_cpg(
        source_type="github",
        source_path="https://github.com/joernio/sample-repo",
        language="java"
    )""",
    )
    async def generate_cpg(
        source_type: Annotated[str, Field(description="Either 'local' or 'github'")],
        source_path: Annotated[str, Field(description="For local: absolute path to source directory. For github: full GitHub URL (e.g., https://github.com/user/repo)")],
        language: Annotated[str, Field(description="Programming language - one of: java, c, cpp, javascript, python, go, kotlin, csharp, ghidra, jimple, php, ruby, swift")],
        github_token: Annotated[Optional[str], Field(description="GitHub Personal Access Token for private repositories (optional)")] = None,
        branch: Annotated[Optional[str], Field(description="Specific git branch to checkout (optional, defaults to default branch)")] = None,
        force: Annotated[bool, Field(description="Skip the large-project size warning. Set to True only after the user has explicitly confirmed they want to analyze the full project.")] = False,
    ) -> Dict[str, Any]:
        """Create a Code Property Graph from source code for analysis."""
        try:
            # Validate inputs
            validate_source_type(source_type)
            validate_language(language)

            codebase_tracker = services["codebase_tracker"]

            # Large-project guard: warn before committing to an expensive full-project CPG
            if source_type == "local" and not force:
                resolved = resolve_host_path(source_path)
                size_mb, loc = _scan_repo(resolved)
                if size_mb > 150 or loc > 15000:
                    return {
                        "status": "large_project_warning",
                        "size_mb": size_mb,
                        "lines_of_code": loc,
                        "message": (
                            f"This project is large ({loc:,} lines of code, {size_mb} MB). "
                            "CPG generation may take a long time and consume significant resources. "
                            "Consider providing the absolute path to a specific sub-component "
                            "(e.g. /path/to/repo/src/module) to scope the analysis. "
                            "If you still want to analyze the full project, call generate_cpg "
                            "again with force=True."
                        ),
                    }

            # Try to get git commit hash for local repos
            commit_hash = None
            if source_type == "local":
                 try:
                     RESOLVED_PATH = resolve_host_path(source_path)
                     commit_hash = _get_git_commit_hash(RESOLVED_PATH)
                     if commit_hash:
                         logger.info(f"Detected git commit hash: {commit_hash}")
                 except Exception as e:
                     logger.warning(f"Failed to get git commit hash: {e}")

            # Generate CPG cache key (codebase_hash)
            codebase_hash = get_cpg_cache_key(source_type, source_path, language, commit_hash)
            logger.info(f"Processing codebase with hash: {codebase_hash}")

            # Check if codebase already exists in DB
            existing_codebase = codebase_tracker.get_codebase(codebase_hash)
            if existing_codebase and existing_codebase.cpg_path and os.path.exists(existing_codebase.cpg_path):
                logger.info(f"Found existing codebase in DB: {codebase_hash}")

                prev_status = existing_codebase.metadata.get("status", "")
                if prev_status == "failed":
                    # CPG binary exists but a previous attempt (e.g. importCpg timeout) left it
                    # in a failed state.  Don't silently retry — return the failure so the caller
                    # can decide whether to regenerate (delete the CPG and call again).
                    logger.warning(f"Codebase {codebase_hash} has a failed CPG — returning failed status")
                    return {
                        "codebase_hash": codebase_hash,
                        "status": SessionStatus.FAILED,
                        "message": existing_codebase.metadata.get("error", "Previous CPG generation or load failed."),
                        **_public_codebase_fields(
                            source_type=existing_codebase.source_type,
                            source_path=existing_codebase.source_path,
                            language=existing_codebase.language,
                            cpg_path=existing_codebase.cpg_path,
                        ),
                    }

                # Check if Joern server is still running
                joern_server_manager = services.get("joern_server_manager")
                joern_port = existing_codebase.joern_port
                server_running = False

                if joern_server_manager:
                    if joern_port and joern_server_manager.is_server_running(codebase_hash):
                        server_running = True
                    else:
                        if joern_port:
                            logger.info(f"Joern server recorded on port {joern_port} but not running for {codebase_hash}")
                        joern_port = None

                if server_running:
                    # Server is already running, return ready immediately
                    return {
                        "codebase_hash": codebase_hash,
                        "status": SessionStatus.READY,
                        "message": "CPG already exists and Joern server is running.",
                        "joern_port": joern_port,
                        **_public_codebase_fields(
                            source_type=existing_codebase.source_type,
                            source_path=existing_codebase.source_path,
                            language=existing_codebase.language,
                            cpg_path=existing_codebase.cpg_path,
                        ),
                    }
                else:
                    if prev_status == "loading" and _get_active_restart_task(services, codebase_hash):
                        codebase_dir = os.path.join(
                            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "playground")),
                            "codebases", codebase_hash
                        )
                        estimate = _estimate_processing_time(codebase_dir, existing_codebase.language, has_cpg=True)
                        return {
                            "codebase_hash": codebase_hash,
                            "status": SessionStatus.LOADING,
                            "message": (
                                "CPG exists and Joern server restart is already in progress. "
                                f"Estimated time: {estimate}. Use get_cpg_status to check progress."
                            ),
                            "estimated_time": estimate,
                            **_public_codebase_fields(
                                source_type=existing_codebase.source_type,
                                source_path=existing_codebase.source_path,
                                language=existing_codebase.language,
                                cpg_path=existing_codebase.cpg_path,
                            ),
                        }

                    # Server not running — kick off async restart and return immediately
                    container_cpg_path = existing_codebase.metadata.get("container_cpg_path")
                    if not container_cpg_path:
                        container_cpg_path = f"/playground/cpgs/{codebase_hash}/cpg.bin"

                    # Mark as loading in DB
                    codebase_tracker.update_codebase(
                        codebase_hash=codebase_hash,
                        joern_port=None,
                        metadata={"status": SessionStatus.LOADING, **{k: v for k, v in existing_codebase.metadata.items() if k != "status"}}
                    )

                    scheduled_restart = _schedule_restart_server_task(
                        codebase_hash=codebase_hash,
                        container_cpg_path=container_cpg_path,
                        services=services,
                    )

                    # Estimate time
                    codebase_dir = os.path.join(
                        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "playground")),
                        "codebases", codebase_hash
                    )
                    estimate = _estimate_processing_time(codebase_dir, existing_codebase.language, has_cpg=True)

                    return {
                        "codebase_hash": codebase_hash,
                        "status": SessionStatus.LOADING,
                        "message": (
                            f"CPG exists but Joern server needs to restart. Loading in background. Estimated time: {estimate}. "
                            "Use get_cpg_status to check progress."
                            if scheduled_restart
                            else f"CPG exists and Joern server restart is already in progress. Estimated time: {estimate}. Use get_cpg_status to check progress."
                        ),
                        "estimated_time": estimate,
                        **_public_codebase_fields(
                            source_type=existing_codebase.source_type,
                            source_path=existing_codebase.source_path,
                            language=existing_codebase.language,
                            cpg_path=existing_codebase.cpg_path,
                        ),
                    }

            # Get services
            git_manager = services["git_manager"]
            
            # Get playground path (absolute)
            playground_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "playground")
            )

            # Step 1 & 2: Prepare source code - copy local path or clone repo
            codebase_dir = os.path.join(playground_path, "codebases", codebase_hash)
            container_codebase_path = f"/playground/codebases/{codebase_hash}"
            
            logger.info(f"Preparing source code for {codebase_hash}")
            
            # Store repository URL if git
            repository_url = source_path if source_type == "github" else None
            
            if source_type == "github":
                validate_github_url(source_path)
                
                # Clone to playground/codebases/<hash>
                if not os.path.exists(codebase_dir):
                    os.makedirs(codebase_dir, exist_ok=True)
                    await git_manager.clone_repository(
                        repo_url=source_path,
                        target_path=codebase_dir,
                        branch=branch,
                        token=github_token,
                    )
                    logger.info(f"Cloned repository to {codebase_dir}")
                else:
                    logger.info(f"Using existing cloned repository at {codebase_dir}")
            else:
                # Local path - copy to playground/codebases/<hash>
                host_path = resolve_host_path(source_path)
                
                if not os.path.exists(codebase_dir):
                    os.makedirs(codebase_dir, exist_ok=True)
                    logger.info(f"Copying source from {host_path} to {codebase_dir}")
                    
                    try:
                        for item in os.listdir(host_path):
                            src_item = os.path.join(host_path, item)
                            dst_item = os.path.join(codebase_dir, item)
                            
                            if os.path.isdir(src_item):
                                shutil.copytree(src_item, dst_item, dirs_exist_ok=True)
                            else:
                                shutil.copy2(src_item, dst_item)
                        logger.info(f"Source copied successfully to {codebase_dir}")
                    except OSError as e:
                        logger.error(f"Failed to copy local source directory for {codebase_hash}: {e}")
                        raise ValidationError("Failed to copy local source directory")
                else:
                    logger.info(f"Using existing source at {codebase_dir}")

            # Step 3: Create CPG directory
            cpg_dir = os.path.join(playground_path, "cpgs", codebase_hash)
            cpg_path = os.path.join(cpg_dir, "cpg.bin")
            container_cpg_path = f"/playground/cpgs/{codebase_hash}/cpg.bin"
            os.makedirs(cpg_dir, exist_ok=True)
            logger.info(f"CPG directory ready: {cpg_dir}")

            # Step 5: Store initial metadata in DB (before CPG generation)
            codebase_tracker.save_codebase(
                codebase_hash=codebase_hash,
                source_type=source_type,
                source_path=source_path,
                language=language,
                cpg_path=None,  # Will be updated after generation
                joern_port=None,  # Will be updated after server starts
                metadata={
                    "container_codebase_path": container_codebase_path,
                    "container_cpg_path": container_cpg_path,
                    "repository": repository_url,
                    "status": SessionStatus.GENERATING
                }
            )

            # Submit to bounded queue (B1 dedup + B3 concurrency limit)
            job = dict(
                codebase_hash=codebase_hash,
                codebase_dir=codebase_dir,
                cpg_path=cpg_path,
                language=language,
                container_cpg_path=container_cpg_path,
                services=services,
            )
            cpg_queue = services.get("cpg_queue")
            if cpg_queue:
                submit_result = await cpg_queue.submit(codebase_hash, job)
                if submit_result == CPGGenerationQueue.DUPLICATE:
                    return {
                        "codebase_hash": codebase_hash,
                        "status": SessionStatus.GENERATING,
                        "message": "CPG build already in progress for this codebase.",
                    }
                if submit_result == CPGGenerationQueue.QUEUE_FULL:
                    return {
                        "codebase_hash": codebase_hash,
                        "status": "queue_full",
                        "message": "CPG generation queue is full. Try again shortly.",
                    }
            else:
                asyncio.create_task(_generate_cpg_async(**job))

            # Estimate time
            estimate = _estimate_processing_time(codebase_dir, language, has_cpg=False)

            # Return immediately with generating status
            return {
                "codebase_hash": codebase_hash,
                "status": SessionStatus.GENERATING,
                "message": f"CPG generation started in background. Estimated time: {estimate}. Use get_cpg_status to check progress.",
                "estimated_time": estimate,
                **_public_codebase_fields(
                    source_type=source_type,
                    source_path=source_path,
                    language=language,
                ),
            }

        except ValidationError as e:
            logger.error(f"Validation error: {e}")
            return {
                "success": False,
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Failed to generate CPG: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }

    @mcp.tool(
        description="""Get the status of a CPG generation or check if CPG exists.

Check if the analysis for a given codebase hash is complete and the CPG is ready.
Also retrieves the connection port for the Joern server if running.

Args:
    codebase_hash: The unique hash identifier returned by generate_cpg.

Returns:
    {
        "codebase_hash": "hash",
        "status": "ready" | "generating" | "failed" | "not_found",
        "cpg_path": "path to CPG if exists",
        "joern_port": port number or null,
        "language": "programming language"
    }

Notes:
    - If status is 'ready', the CPG is available for queries.
    - If status is 'generating', wait and retry.
    - Filesystem paths in responses are redacted.

Examples:
    get_cpg_status(codebase_hash="abc123456789")""",
    )
    def get_cpg_status(
        codebase_hash: Annotated[str, Field(description="The hash identifier of the codebase")]
    ) -> Dict[str, Any]:
        """Check CPG generation status or verify if a CPG exists and is ready."""
        try:
            codebase_tracker = services["codebase_tracker"]
            
            # Step 6: If codebase exists in DB, return metadata
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            
            if not codebase_info:
                return {
                    "codebase_hash": codebase_hash,
                    "status": "not_found",
                    "message": "Codebase not found. Please generate CPG first.",
                }
            
            # Get status from metadata
            status = codebase_info.metadata.get("status", "unknown")
            if status == "unknown" and codebase_info.cpg_path and os.path.exists(codebase_info.cpg_path):
                status = "ready"

            joern_port = codebase_info.joern_port
            joern_server_manager = services.get("joern_server_manager")

            # Sleeping means CPG on disk but server evicted — treat like ready-but-not-running
            needs_restart = status in ("ready", "sleeping")
            if needs_restart and joern_server_manager:
                is_running = bool(joern_port and joern_server_manager.is_server_running(codebase_hash))

                if not is_running:
                    logger.info(f"Joern server not running for {status} codebase {codebase_hash}, restarting in background...")
                    joern_port = None
                    status = "loading"

                    container_cpg_path = codebase_info.metadata.get("container_cpg_path")
                    if not container_cpg_path:
                        container_cpg_path = f"/playground/cpgs/{codebase_hash}/cpg.bin"

                    if not _get_active_restart_task(services, codebase_hash):
                        codebase_tracker.update_codebase(
                            codebase_hash=codebase_hash,
                            joern_port=None,
                            metadata={"status": SessionStatus.LOADING, **{k: v for k, v in codebase_info.metadata.items() if k != "status"}}
                        )

                        try:
                            _schedule_restart_server_task(
                                codebase_hash=codebase_hash,
                                container_cpg_path=container_cpg_path,
                                services=services,
                            )
                        except RuntimeError:
                            logger.warning(f"No event loop for async restart of {codebase_hash}")
            
            return {
                "codebase_hash": codebase_hash,
                "status": status,
                "joern_port": joern_port,
                **_public_codebase_fields(
                    source_type=codebase_info.source_type,
                    source_path=codebase_info.source_path,
                    language=codebase_info.language,
                    cpg_path=codebase_info.cpg_path,
                    metadata=codebase_info.metadata,
                    include_internal_paths=True,
                    include_repository=True,
                ),
                "created_at": codebase_info.created_at.isoformat(),
                "last_accessed": codebase_info.last_accessed.isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get CPG status: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }

    @mcp.tool(
        description="""Free resources held by a codebase.

delete_files=False (default):
    Terminate the Joern process and release the port.
    CPG binary is kept on disk for fast re-activation later.
    Status is set to 'sleeping'.

delete_files=True:
    Full removal: kill the Joern process, delete the CPG binary and the
    copied/cloned source under /playground/, and remove the DB row.
    Requires a full CPG rebuild to use the codebase again.
    Returns freed_mb in the response.
""",
    )
    async def remove_cpg(
        codebase_hash: Annotated[str, Field(description="The hash identifier of the codebase")],
        delete_files: Annotated[bool, Field(description="If True, permanently delete CPG and source files")] = False,
    ) -> Dict[str, Any]:
        """Free resources held by a codebase (evict server and optionally delete files)."""
        try:
            codebase_tracker = services["codebase_tracker"]
            joern_server_manager = services.get("joern_server_manager")

            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info:
                return {"success": False, "error": f"Codebase {codebase_hash} not found"}

            # Kill Joern process and release port
            if joern_server_manager and joern_server_manager.get_server_port(codebase_hash):
                joern_server_manager.terminate_server(codebase_hash)

            if not delete_files:
                codebase_tracker.update_codebase(
                    codebase_hash=codebase_hash,
                    joern_port=None,
                    metadata={"status": SessionStatus.SLEEPING},
                )
                return {
                    "success": True,
                    "codebase_hash": codebase_hash,
                    "status": SessionStatus.SLEEPING,
                    "message": "Joern process terminated. CPG kept on disk for fast re-activation.",
                }

            # delete_files=True: remove everything
            playground_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "playground")
            )
            freed_bytes = 0

            cpg_dir = os.path.join(playground_path, "cpgs", codebase_hash)
            if os.path.exists(cpg_dir):
                for dirpath, _, filenames in os.walk(cpg_dir):
                    for fname in filenames:
                        try:
                            freed_bytes += os.path.getsize(os.path.join(dirpath, fname))
                        except OSError:
                            pass
                shutil.rmtree(cpg_dir, ignore_errors=True)

            codebase_dir = os.path.join(playground_path, "codebases", codebase_hash)
            if os.path.exists(codebase_dir):
                for dirpath, _, filenames in os.walk(codebase_dir):
                    for fname in filenames:
                        try:
                            freed_bytes += os.path.getsize(os.path.join(dirpath, fname))
                        except OSError:
                            pass
                shutil.rmtree(codebase_dir, ignore_errors=True)

            db_manager = services["db_manager"]
            db_manager.delete_codebase(codebase_hash)

            return {
                "success": True,
                "codebase_hash": codebase_hash,
                "status": "removed",
                "freed_mb": round(freed_bytes / (1024 * 1024), 2),
                "message": "CPG, source files, and DB record deleted.",
            }

        except Exception as e:
            logger.error(f"Failed to remove CPG {codebase_hash}: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
