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

from ..defaults import LANGUAGE_COMMANDS, SUPPORTED_LANGUAGES
from ..exceptions import ValidationError
from ..models import CodebaseInfo, SessionStatus
from ..utils.validators import (
    parse_snippet_blocks,
    validate_and_infer_snippet_language,
    validate_code_snippet,
    validate_codebase_hash,
    validate_git_branch,
    validate_github_token,
    validate_github_url,
    validate_language,
    validate_local_path,
    validate_snippet_label,
    validate_source_type,
    resolve_host_path,
    snippet_filename,
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
    """Schedule a background Joern-server restart.

    Returns True if a restart task was started (or is already running), False if
    no event loop was available to run it. Sync MCP tools (get_cpg_status) run in
    a worker thread with no running loop, so we fall back to scheduling onto the
    captured main loop via run_coroutine_threadsafe — otherwise the coroutine is
    dropped and the codebase is stranded in "loading" forever.
    """
    if _get_active_restart_task(services, codebase_hash):
        return True

    registry = _get_restart_task_registry(services)

    def _cleanup(done_handle) -> None:
        if registry.get(codebase_hash) is done_handle:
            registry.pop(codebase_hash, None)

    coro = _restart_server_async(
        codebase_hash=codebase_hash,
        container_cpg_path=container_cpg_path,
        services=services,
    )

    try:
        # Fast path: we're already on the event loop (async caller).
        task = asyncio.get_running_loop().create_task(coro)
        registry[codebase_hash] = task
        task.add_done_callback(_cleanup)
        return True
    except RuntimeError:
        # No running loop in this thread — schedule onto the main server loop.
        main_loop = services.get("event_loop")
        if main_loop is None or main_loop.is_closed():
            coro.close()  # avoid "coroutine was never awaited" warning
            logger.warning(
                f"No usable event loop to restart Joern server for {codebase_hash}"
            )
            return False
        future = asyncio.run_coroutine_threadsafe(coro, main_loop)
        registry[codebase_hash] = future
        future.add_done_callback(_cleanup)
        return True


def _get_git_commit_hash(path: str) -> Optional[str]:
    """
    Get the current git commit hash for a path if it's in a git repo.
    """
    try:
        import subprocess
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

def get_cpg_cache_key(source_type: str, source_path: str, language: str, commit_hash: Optional[str] = None, content: Optional[str] = None) -> str:
    """
    Generate a deterministic CPG cache key based on source type, path, language, and optional commit hash.

    For snippets the key is derived from the code content (not the path), so pasting
    the same snippet twice reuses the cached CPG regardless of the label.
    """
    if source_type == "snippet":
        digest = hashlib.sha256((content or "").encode("utf-8")).hexdigest()
        identifier = f"snippet:{digest}:{language}"
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]
    elif source_type == "github":
        if "github.com/" in source_path:
            parts = source_path.split("github.com/")[-1].split("/")
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1].replace(".git", "")
                identifier = f"github:{owner}/{repo}:{language}"
            else:
                identifier = f"github:{source_path}:{language}"
        elif "gitlab.com/" in source_path:
            # gitlab supports nested groups, so the project path can be deeper
            # than owner/repo — key off the whole path (sans trailing .git) so
            # the hash is stable and collision-free across subgroups.
            path = source_path.split("gitlab.com/")[-1].strip("/")
            if path.endswith(".git"):
                path = path[:-4]
            identifier = f"gitlab:{path}:{language}"
        else:
            identifier = f"github:{source_path}:{language}"
    else:
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


_OOM_MARKERS = (
    "OutOfMemoryError",
    "java.lang.OutOfMemoryError",
    "GC overhead limit exceeded",
    "unable to create new native thread",
    "Cannot allocate memory",
    "There is insufficient memory",
    "Killed",
)


def _classify_cpg_build_failure(exit_code, output: str, build_heap_gb: int) -> tuple:
    """Map a failed c2cpg/frontend run to (error_code, human message).

    Distinguishes an out-of-memory build (the dominant large-project failure) from a
    generic build error, and bounds the stored output so a multi-MB frontend dump
    doesn't bloat the DB / response. Exit 137 = SIGKILL, which for a build is almost
    always the cgroup OOM-killer.
    """
    text = output or ""
    tail = text[-2000:]
    is_oom = exit_code == 137 or any(m in text for m in _OOM_MARKERS)
    if is_oom:
        return "OOM", (
            f"CPG generation ran out of memory (build heap -Xmx{build_heap_gb}G, exit {exit_code}). "
            f"Raise CPG_BUILD_HEAP_GB / JOERN_MEM_LIMIT, lower CPG_BUILD_WORKERS, or analyze a "
            f"sub-component. Frontend tail: {tail}"
        )
    return "BUILD_ERROR", f"CPG generation failed (exit {exit_code}). Frontend tail: {tail}"


def _copy_local_source_tree(host_path: str, codebase_dir: str) -> None:
    """Copy a local source tree into the playground snapshot dir.

    Symlink-safe: never dereferences symlinks whose target escapes the source root
    (prevents pulling arbitrary host files into the readable snapshot).

    Blocking I/O — invoke via asyncio.to_thread so it never runs on the event loop.
    Doing it on the loop serializes concurrent generate_cpg calls, which inflates
    the latency between request receipt and source capture; under a batch driver
    that cleans up its source dirs on a timer, a delayed copy races the cleanup and
    fails with "Path does not exist".
    """
    os.makedirs(codebase_dir, exist_ok=True)
    real_root = os.path.realpath(host_path)
    for item in os.listdir(host_path):
        src_item = os.path.join(host_path, item)
        dst_item = os.path.join(codebase_dir, item)

        if os.path.islink(src_item):
            if not os.path.realpath(src_item).startswith(real_root + os.sep):
                logger.warning(f"Skipping symlink escaping source root: {item}")
                continue

        if os.path.isdir(src_item):
            # symlinks=True: copy nested links as links, never dereference out of tree.
            shutil.copytree(src_item, dst_item, dirs_exist_ok=True, symlinks=True)
        else:
            shutil.copy2(src_item, dst_item, follow_symlinks=False)


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
        if size_mb > 200:
            return "~3-8 minutes (loading large CPG into Joern server)"
        elif size_mb > 50:
            return "~1-3 minutes (loading CPG into Joern server)"
        else:
            return "~30-60 seconds (loading CPG into Joern server)"
    else:
        if size_mb > 200:
            return "~5-15 minutes (large codebase: CPG generation + server loading)"
        elif size_mb > 50:
            return "~2-5 minutes (CPG generation + server loading)"
        elif size_mb > 10:
            return "~1-3 minutes (CPG generation + server loading)"
        else:
            return "~30-90 seconds (CPG generation + server loading)"


# Strong refs to in-flight fire-and-forget warm-up futures so they aren't GC'd
# before they finish (asyncio only weakly references bare tasks/futures).
_warmup_tasks: set = set()


def _schedule_warmup(services: dict, codebase_hash: str) -> None:
    """Warm the query cache OFF the build-worker critical path (fire-and-forget).

    The CPG is marked READY and is fully queryable before this runs, so warm-up
    is a best-effort cache optimization. Awaiting it inline pinned a build worker
    (and an executor thread) for the serial cost of several heavy queries before
    it could claim the next build, throttling generation throughput. Schedule it
    on the loop and return immediately; the per-codebase query lock serializes it
    against any real user query that arrives in the meantime.
    """
    if "code_browsing_service" not in services:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return  # no running loop (e.g. a sync test) — skip warm-up
    logger.info(f"Scheduling background cache warm-up for {codebase_hash}")
    fut = loop.run_in_executor(
        None, services["code_browsing_service"].warm_up_cache, codebase_hash
    )
    _warmup_tasks.add(fut)

    def _done(f) -> None:
        _warmup_tasks.discard(f)
        exc = None if f.cancelled() else f.exception()
        if exc is not None:
            logger.warning(f"Background cache warm-up failed for {codebase_hash}: {exc}")
        else:
            logger.info(f"Background cache warm-up complete for {codebase_hash}")

    fut.add_done_callback(_done)


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

        loaded = await loop.run_in_executor(
            None, joern_server_manager.load_cpg, codebase_hash, container_cpg_path
        )
        if not loaded:
            # The reload failed (load_cpg already terminated the server). Mark
            # FAILED so we don't leave a "ready" codebase whose server is dead —
            # that caused the restart-fail churn (server not running for ready
            # codebase -> retry -> fail -> repeat).
            logger.error(f"Async: CPG reload failed for {codebase_hash}; marking failed")
            codebase_tracker.update_codebase(
                codebase_hash=codebase_hash,
                joern_port=None,
                metadata={
                    "status": SessionStatus.FAILED,
                    "error": "CPG exists but failed to reload into a Joern server",
                },
            )
            return
        logger.info(f"Async: CPG loaded into Joern server on port {joern_port}")

        codebase_tracker.update_codebase(
            codebase_hash=codebase_hash,
            joern_port=joern_port,
            metadata={"status": SessionStatus.READY}
        )

        # Fire-and-forget so the restart returns promptly; warm-up runs in the
        # background (the CPG is already READY and queryable).
        _schedule_warmup(services, codebase_hash)

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

        codebase_tracker = services["codebase_tracker"]
        joern_server_manager = services.get("joern_server_manager")
        config = services.get("config")

        # Validate repository size before CPG generation. The walk is blocking I/O
        # over the whole tree — keep it OFF the event loop (a pathologically large
        # tree here once spun the loop and hung the entire MCP).
        if config:
            repo_size_mb = await asyncio.to_thread(_calculate_repo_size_mb, codebase_dir)
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

        cmd = [cmd_binary, f"/playground/codebases/{codebase_hash}", "-o", container_cpg_path]

        if config and language in config.cpg.languages_with_exclusions and config.cpg.exclusion_patterns:
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

        # CRITICAL: cap the frontend JVM heap. Without -Xmx the frontend defaults
        # to ~25% of the container limit (~25 GB on a 100 GB cap); N concurrent
        # unbounded frontends exhaust host RAM and trip the OOM-killer (it took
        # the server down on a large batch). Pass JAVA_OPTS so each build is
        # bounded and fits build_workers * build_heap within the budget.
        build_heap_gb = config.cpg.build_heap_gb if config else 6
        frontend_java_opts = (
            f"-Xmx{build_heap_gb}G -XX:+UseG1GC -XX:+UseStringDeduplication -Dfile.encoding=UTF-8"
        )
        logger.info(
            f"Executing CPG generation in container (frontend -Xmx{build_heap_gb}G): {' '.join(cmd)}"
        )

        # exec_run is a synchronous blocking Docker SDK call.  Running it bare in an
        # async coroutine would freeze the entire asyncio event loop for the duration
        # of the Joern process (potentially hours if c2cpg hangs on certain C codebases).
        # We offload it to a thread-pool executor and wrap with wait_for so we can
        # enforce the configured generation_timeout and keep the event loop responsive.
        generation_timeout = config.cpg.generation_timeout if config else 600
        loop = asyncio.get_running_loop()
        try:
            exec_result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: container.exec_run(
                        cmd=cmd, stream=False, environment={"JAVA_OPTS": frontend_java_opts}
                    ),
                ),
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
                metadata={"status": SessionStatus.FAILED, "error_code": "TIMEOUT", "error": error_msg}
            )
            return

        if exec_result.exit_code != 0:
            output = exec_result.output.decode("utf-8", errors="replace") if exec_result.output else ""
            error_code, error_msg = _classify_cpg_build_failure(
                exec_result.exit_code, output, build_heap_gb
            )
            logger.error(f"CPG generation failed for {codebase_hash} [{error_code}]: {error_msg}")
            codebase_tracker.update_codebase(
                codebase_hash=codebase_hash,
                metadata={"status": SessionStatus.FAILED, "error_code": error_code, "error": error_msg}
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

                # Load CPG using the container path, not the host path
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

        # Final metadata update preserves the container paths recorded above.
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

        # Fire-and-forget: the CPG is already marked READY above, so the build
        # worker can claim its next job without waiting on warm-up queries.
        _schedule_warmup(services, codebase_hash)

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

    @property
    def in_flight(self) -> int:
        """Jobs currently queued or being generated (dedup set size)."""
        return len(self._in_flight)

    @property
    def maxsize(self) -> int:
        return self._maxsize

    @property
    def is_full(self) -> bool:
        return bool(self._maxsize) and self._queue.qsize() >= self._maxsize

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


class DurableCPGQueue:
    """Postgres-backed CPG generation queue.

    Same interface as CPGGenerationQueue, but jobs live in the durable `jobs`
    table instead of an in-memory asyncio.Queue, so a 300-CVE batch survives a
    restart and is never silently dropped. Workers poll the DB and claim jobs
    atomically (one per worker) via FOR UPDATE SKIP LOCKED, so this is
    multi-process / multi-host. DB dedup (partial unique index) replaces the
    in-flight set.
    """

    SUBMITTED = "submitted"
    DUPLICATE = "duplicate"
    QUEUE_FULL = "queue_full"
    JOB_TYPE = "generate_cpg"

    def __init__(self, job_store, services: dict, workers: int = 2, maxsize: int = 0,
                 poll_interval: float = 1.0, max_poll_interval: float = 5.0):
        # job_store implements the queue method surface (enqueue_job /
        # claim_next_job / complete_job / fail_job / count_jobs /
        # requeue_running_jobs): a PostgresJobStore / PostgresDBManager.
        self.store = job_store
        self.services = services
        self._workers = workers
        self._maxsize = maxsize
        # Empty-queue polling backs off from poll_interval up to max_poll_interval
        # so idle workers don't hammer Postgres with a claim query every second
        # (and, with pooling, don't keep a connection hot for nothing). It snaps
        # back to poll_interval the moment a job is claimed, so a busy batch stays
        # responsive. max_poll_interval <= poll_interval disables backoff.
        self._poll_interval = poll_interval
        self._max_poll_interval = max(poll_interval, max_poll_interval)
        self._tasks: list = []
        self._stopping = False

    async def start(self) -> None:
        # Recover jobs a previous run left mid-flight so they're retried.
        try:
            requeued = self.store.requeue_running_jobs()
            if requeued:
                logger.info(f"Requeued {requeued} interrupted CPG generation job(s)")
        except Exception as e:
            logger.warning(f"Could not requeue interrupted jobs: {e}")
        for _ in range(self._workers):
            self._tasks.append(asyncio.create_task(self._worker()))

    async def stop(self) -> None:
        self._stopping = True
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def submit(self, codebase_hash: str, job: dict) -> str:
        # `services` is the live process state — not serializable; the worker
        # re-injects it. Persist only the plain job parameters.
        payload = {k: v for k, v in job.items() if k != "services"}
        loop = asyncio.get_running_loop()
        _job_id, status = await loop.run_in_executor(
            None, self.store.enqueue_job, codebase_hash, self.JOB_TYPE, payload, self._maxsize
        )
        if status == "error":
            return self.QUEUE_FULL  # treat a DB error as backpressure; client retries
        return status

    async def _worker(self) -> None:
        loop = asyncio.get_running_loop()
        idle_delay = self._poll_interval
        while not self._stopping:
            try:
                job = await loop.run_in_executor(None, self.store.claim_next_job, self.JOB_TYPE)
            except Exception as e:
                logger.error(f"Error claiming CPG job: {e}")
                job = None
            if not job:
                await asyncio.sleep(idle_delay)
                # Exponential backoff while the queue stays empty (capped).
                idle_delay = min(idle_delay * 2, self._max_poll_interval)
                continue
            # Queue is active again — reset to the responsive base interval.
            idle_delay = self._poll_interval
            job_id = job["id"]
            payload = dict(job["payload"])
            payload["services"] = self.services
            try:
                await _generate_cpg_async(**payload)
                await loop.run_in_executor(None, self.store.complete_job, job_id)
            except Exception as e:
                logger.error(f"CPG generation job {job_id} for {job['codebase_hash']} failed: {e}", exc_info=True)
                await loop.run_in_executor(None, self.store.fail_job, job_id, str(e))

    @property
    def depth(self) -> int:
        return self.store.count_jobs("queued")

    @property
    def in_flight(self) -> int:
        return self.store.count_jobs("queued") + self.store.count_jobs("running")

    @property
    def maxsize(self) -> int:
        return self._maxsize

    @property
    def is_full(self) -> bool:
        return bool(self._maxsize) and self.store.count_jobs("queued") >= self._maxsize


def register_core_tools(mcp, services: dict):
    """Register core MCP tools with the FastMCP server"""

    @mcp.tool(
        description="""Generate a Code Property Graph (CPG) for a codebase.

This tool initiates the analysis process by generating a CPG for the specified codebase.
For git repositories, it clones the repo first. For local paths, it copies the source code.
The CPG is cached by a hash of the codebase.

Accepted git repositories (source_type='github'):
  - ONLY public/private repos on github.com or gitlab.com.
  - The URL MUST be an https:// URL of the form:
      https://github.com/<owner>/<repo>   or   https://gitlab.com/<owner>/<repo>
    (gitlab nested subgroups are allowed; a trailing .git is fine).
  - Other hosts, schemes (git://, ssh://, http://), embedded credentials, or
    custom ports are rejected. Use github_token for a private repo, do NOT embed
    the token in the URL.

Pasting code directly (source_type='snippet'):
  Wrap the code in a <code> tag whose `language` attribute is one of the supported
  languages, and pass the whole tagged string in the `code` argument. The server
  parses the language and body out of the tag — do not also rely on the `language`
  argument, the tag wins. Use the EXACT supported language id (see Notes).
    Single block:
      <code language="c">
      int main(void){ char b[8]; gets(b); return 0; }
      </code>
    Multiple blocks are concatenated into one file, but they MUST all declare the
    SAME language (one CPG is single-language).

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
    source_type: One of 'local', 'github' (a github.com/gitlab.com repo), or 'snippet'.
    source_path: REQUIRED for local (absolute path) and github (an https
                 github.com/gitlab.com URL). OPTIONAL for snippet — a short label;
                 when omitted the server derives one from the filename/language.
    language: Programming language (java, c, cpp, python, javascript, go, etc.).
              REQUIRED for local/github. Optional for snippets that carry a
              <code language="..."> tag (the tag wins) or whose language is inferable.
    code: For snippets, the code wrapped in <code language="..."> ... </code> tag(s).
    github_token: Optional PAT for private repos (never embed it in the URL).
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
    - Git repos: only https://github.com/... and https://gitlab.com/... are accepted.

Examples:
    generate_cpg(
        source_type="github",
        source_path="https://gitlab.com/owner/repo",
        language="java"
    )
    generate_cpg(
        source_type="snippet",
        source_path="overflow_demo",
        code="<code language=\\"c\\">int main(void){ char b[8]; gets(b); }</code>"
    )""",
    )
    async def generate_cpg(
        source_type: Annotated[str, Field(description="One of 'local', 'github', or 'snippet' (code pasted directly into the chat)")],
        source_path: Annotated[Optional[str], Field(description="REQUIRED for local (absolute path to source directory) and github (an https URL on github.com or gitlab.com ONLY, e.g. https://github.com/user/repo — other hosts/schemes/credentials/ports are rejected). OPTIONAL for snippet: a short human label for the pasted code (e.g. a function name); when omitted the server derives one from the filename/language.")] = None,
        language: Annotated[str, Field(description="Programming language - one of: java, c, cpp, javascript, python, go, kotlin, csharp, ghidra, jimple, php, ruby, swift. REQUIRED for local/github. For a snippet whose code carries a <code language=\"...\"> tag, the tag's language wins and this is optional.")] = "",
        code: Annotated[Optional[str], Field(description="Required when source_type='snippet'. Wrap the code in a <code language=\"LANG\"> ... </code> tag where LANG is a supported language id, e.g. <code language=\"c\">int main(){...}</code>. Multiple blocks are concatenated but must share one language. Ignored for local/github.")] = None,
        filename: Annotated[Optional[str], Field(description="Optional filename for a snippet (e.g. 'parser.c'); defaults to snippet.<ext> from the language. Ignored for local/github.")] = None,
        github_token: Annotated[Optional[str], Field(description="GitHub Personal Access Token for private repositories (optional)")] = None,
        branch: Annotated[Optional[str], Field(description="Specific git branch to checkout (optional, defaults to default branch)")] = None,
        force: Annotated[bool, Field(description="Skip the large-project size warning. Set to True only after the user has explicitly confirmed they want to analyze the full project.")] = False,
    ) -> Dict[str, Any]:
        """Create a Code Property Graph from source code for analysis.

        Source can be a GitHub repo, a local directory, or a code snippet pasted
        straight into the chat (source_type='snippet' with the code in `code`).
        """
        try:
            validate_source_type(source_type)
            # source_path is only optional for snippets (the server derives a label
            # on the fly). local/github have nowhere to read the source from without it.
            if source_type in ("local", "github"):
                if not (source_path and source_path.strip()):
                    raise ValidationError(
                        f"source_path is required for source_type='{source_type}' "
                        f"({'absolute path to the source directory' if source_type == 'local' else 'an https github.com/gitlab.com repository URL'})."
                    )
                if not (language and language.strip()):
                    raise ValidationError(
                        f"language is required for source_type='{source_type}'."
                    )
            # Chat/hosted deployment: never expose arbitrary host filesystem paths
            # through a chat-facing MCP. Disable local sources entirely; callers
            # must use a github.com/gitlab.com URL or paste the code as a snippet.
            if source_type == "local":
                _cfg = services.get("config")
                if _cfg and getattr(_cfg.server, "chat_deploy", False):
                    raise ValidationError(
                        "source_type='local' is disabled in this deployment. Provide a "
                        "github.com or gitlab.com repository URL with source_type='github', "
                        "or paste the code with source_type='snippet'."
                    )
            # For snippets the code may be wrapped in <code language="..."> tags;
            # extract the language + body from them so the snippet is
            # self-describing. The tag (when present) provides the declared
            # language; otherwise fall back to the explicit `language` arg. The
            # helper then validates the language, infers it when absent, and
            # refuses (with an actionable message) on mismatch or ambiguity.
            if source_type == "snippet":
                parsed = parse_snippet_blocks(code)
                # A snippet must carry its language somewhere: either a
                # <code language="..."> tag or the explicit `language` arg. With
                # neither, don't silently guess from content — ask for one clearly.
                if not parsed and not (language and language.strip()):
                    raise ValidationError(
                        "For source_type='snippet', the language must be specified: "
                        "either wrap the code in a <code language=\"...\"> ... </code> "
                        "tag (e.g. <code language=\"c\">int main(){...}</code>) or pass "
                        "the `language` argument. Supported languages: "
                        f"{', '.join(SUPPORTED_LANGUAGES)}."
                    )
                declared = parsed[0] if parsed else language
                if parsed:
                    code = parsed[1]
                language = validate_and_infer_snippet_language(code, declared or None)
            validate_language(language)
            # Validate every caller-supplied input up front (no-ops when unset).
            validate_git_branch(branch)
            validate_github_token(github_token)
            if source_type == "snippet":
                validate_code_snippet(code)
                source_path = validate_snippet_label(source_path)

            codebase_tracker = services["codebase_tracker"]
            config = services.get("config")

            # Large-project guard: warn before committing to an expensive full-project CPG.
            # Thresholds are configurable and the whole guard can be turned off
            # (CPG_LARGE_PROJECT_GUARD=false) for unattended/batch drivers that always
            # intend to build and can't pass force=True per call. resolve + scan are
            # blocking FS work — run them off the event loop so a big project's tree
            # walk can't freeze every other concurrent generate_cpg call.
            guard_on = config.cpg.large_project_guard if config else True
            if source_type == "local" and not force and guard_on:
                max_mb = config.cpg.large_project_max_mb if config else 2000
                max_loc = config.cpg.large_project_max_loc if config else 2_000_000
                resolved = await asyncio.to_thread(resolve_host_path, source_path)
                size_mb, loc = await asyncio.to_thread(_scan_repo, resolved)
                if size_mb > max_mb or loc > max_loc:
                    return {
                        "success": True,  # no error; an informational soft-decline
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

            # Git commit hash, when available, becomes part of the cache key so a
            # checkout of a different revision produces a distinct CPG.
            commit_hash = None
            if source_type == "local":
                 try:
                     RESOLVED_PATH = await asyncio.to_thread(resolve_host_path, source_path)
                     commit_hash = await asyncio.to_thread(_get_git_commit_hash, RESOLVED_PATH)
                     if commit_hash:
                         logger.info(f"Detected git commit hash: {commit_hash}")
                 except Exception as e:
                     logger.warning(f"Failed to get git commit hash: {e}")

            codebase_hash = get_cpg_cache_key(source_type, source_path, language, commit_hash, content=code)
            logger.info(f"Processing codebase with hash: {codebase_hash}")

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
                        "success": False,
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
                    return {
                        "success": True,
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
                            "success": True,
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

                    codebase_dir = os.path.join(
                        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "playground")),
                        "codebases", codebase_hash
                    )
                    estimate = _estimate_processing_time(codebase_dir, existing_codebase.language, has_cpg=True)

                    return {
                        "success": True,
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

            git_manager = services["git_manager"]

            playground_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "playground")
            )

            codebase_dir = os.path.join(playground_path, "codebases", codebase_hash)
            container_codebase_path = f"/playground/codebases/{codebase_hash}"

            logger.info(f"Preparing source code for {codebase_hash}")

            repository_url = source_path if source_type == "github" else None

            if source_type == "github":
                validate_github_url(source_path)

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
            elif source_type == "snippet":
                snippet_name = snippet_filename(language, filename)
                # Label the DB record with the filename when no explicit label was given.
                if not source_path:
                    source_path = snippet_name

                if not os.path.exists(codebase_dir):
                    os.makedirs(codebase_dir, exist_ok=True)
                    snippet_file = os.path.join(codebase_dir, snippet_name)
                    try:
                        with open(snippet_file, "w", encoding="utf-8") as f:
                            f.write(code)
                        logger.info(f"Wrote snippet to {snippet_file}")
                    except OSError as e:
                        logger.error(f"Failed to write snippet for {codebase_hash}: {e}")
                        raise ValidationError("Failed to stage code snippet")
                else:
                    logger.info(f"Using existing snippet at {codebase_dir}")
            else:
                # resolve + copy are blocking FS work — keep them off the event loop
                # (see _copy_local_source_tree) so concurrent requests don't serialize
                # and race the caller's source-dir cleanup.
                host_path = await asyncio.to_thread(resolve_host_path, source_path)

                # Refuse a source that contains (or is) the CodeBadger playground.
                # Copying it would recursively pull in every cached codebase/CPG, and
                # the pre-build size walk over that explosion blocks the event loop —
                # a single such request takes the whole MCP down (observed outage).
                real_src = os.path.realpath(host_path)
                real_pg = os.path.realpath(playground_path)
                if real_pg == real_src or real_pg.startswith(real_src + os.sep):
                    raise ValidationError(
                        "Source path contains the CodeBadger playground directory; "
                        "refusing to analyze it (would recursively include all cached "
                        "codebases and CPGs)."
                    )

                if not os.path.exists(codebase_dir):
                    logger.info(f"Copying source from {host_path} to {codebase_dir}")
                    try:
                        await asyncio.to_thread(_copy_local_source_tree, host_path, codebase_dir)
                        logger.info(f"Source copied successfully to {codebase_dir}")
                    except OSError as e:
                        logger.error(f"Failed to copy local source directory for {codebase_hash}: {e}")
                        raise ValidationError("Failed to copy local source directory")
                else:
                    logger.info(f"Using existing source at {codebase_dir}")

            cpg_dir = os.path.join(playground_path, "cpgs", codebase_hash)
            cpg_path = os.path.join(cpg_dir, "cpg.bin")
            container_cpg_path = f"/playground/cpgs/{codebase_hash}/cpg.bin"
            os.makedirs(cpg_dir, exist_ok=True)
            logger.info(f"CPG directory ready: {cpg_dir}")

            # Store initial metadata in DB before CPG generation begins.
            codebase_tracker.save_codebase(
                codebase_hash=codebase_hash,
                source_type=source_type,
                source_path=source_path,
                language=language,
                cpg_path=None,  # Updated after generation
                joern_port=None,  # Updated after the server starts
                metadata={
                    "container_codebase_path": container_codebase_path,
                    "container_cpg_path": container_cpg_path,
                    "repository": repository_url,
                    "status": SessionStatus.GENERATING
                }
            )

            # Submit to the bounded queue (dedup + concurrency limit).
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
                        "success": True,
                        "codebase_hash": codebase_hash,
                        "status": SessionStatus.GENERATING,
                        "message": "CPG build already in progress for this codebase.",
                    }
                if submit_result == CPGGenerationQueue.QUEUE_FULL:
                    return {
                        "success": False,
                        "codebase_hash": codebase_hash,
                        "status": "queue_full",
                        "message": "CPG generation queue is full. Try again shortly.",
                    }
            else:
                asyncio.create_task(_generate_cpg_async(**job))

            estimate = _estimate_processing_time(codebase_dir, language, has_cpg=False)

            return {
                "success": True,
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
        description="""Get the current status of a CPG and its Joern server.

USE THIS TO WAIT FOR generate_cpg: generate_cpg starts the build in the background
and returns immediately with status 'generating'. Poll this tool with the returned
codebase_hash until status becomes 'ready' (or 'failed') — that is the intended way
to wait for a CPG to finish generating. It returns the CPG's current status and, once
ready, the Joern server port to use for queries.

Args:
    codebase_hash: The unique hash identifier returned by generate_cpg.

Returns:
    {
        "codebase_hash": "hash",
        "status": "generating" | "loading" | "ready" | "sleeping" | "failed" | "not_found",
        "cpg_path": "path to CPG if exists",
        "joern_port": port number or null,
        "language": "programming language"
    }

Notes:
    - 'generating'/'loading' → build or server startup in progress; wait briefly and poll again.
    - 'ready' → the CPG is loaded and available for queries (use joern_port).
    - 'sleeping' → CPG exists on disk but the server was evicted; it auto-wakes on the next query
      (polling also triggers a restart).
    - 'failed' → generation or load failed; regenerate with generate_cpg.
    - 'not_found' → no such codebase; call generate_cpg first.
    - Filesystem paths in responses are redacted.

Examples:
    # Poll until ready after generate_cpg:
    get_cpg_status(codebase_hash="abc123456789")  # repeat while status is 'generating'""",
    )
    def get_cpg_status(
        codebase_hash: Annotated[str, Field(description="The hash identifier of the codebase")]
    ) -> Dict[str, Any]:
        """Check CPG generation status or verify if a CPG exists and is ready."""
        try:
            validate_codebase_hash(codebase_hash)
            codebase_tracker = services["codebase_tracker"]

            codebase_info = codebase_tracker.get_codebase(codebase_hash)

            if not codebase_info:
                return {
                    "codebase_hash": codebase_hash,
                    "status": "not_found",
                    "message": "Codebase not found. Please generate CPG first.",
                }
            
            status = codebase_info.metadata.get("status", "unknown")
            if status == "unknown" and codebase_info.cpg_path and os.path.exists(codebase_info.cpg_path):
                status = "ready"

            joern_port = codebase_info.joern_port
            joern_server_manager = services.get("joern_server_manager")

            # Reconcile a stranded "loading": a codebase left in LOADING with a
            # recorded error, or with no active restart task behind it, is a
            # zombie from a restart that never ran (e.g. the old sync-thread
            # create_task drop). Surface it as failed so callers stop polling
            # forever instead of waiting on a load that will never complete.
            if status in ("loading", SessionStatus.LOADING):
                has_error = bool(codebase_info.metadata.get("error"))
                if has_error or not _get_active_restart_task(services, codebase_hash):
                    status = "failed"
                    if not codebase_info.metadata.get("error"):
                        codebase_info.metadata["error"] = (
                            "Joern server load was interrupted and never completed"
                        )
                    codebase_tracker.update_codebase(
                        codebase_hash=codebase_hash,
                        joern_port=None,
                        metadata={**codebase_info.metadata, "status": SessionStatus.FAILED},
                    )

            # Sleeping means CPG on disk but server evicted — treat like ready-but-not-running
            needs_restart = status in ("ready", "sleeping")
            if needs_restart and joern_server_manager:
                is_running = bool(joern_port and joern_server_manager.is_server_running(codebase_hash))

                if not is_running:
                    container_cpg_path = codebase_info.metadata.get("container_cpg_path")
                    if not container_cpg_path:
                        container_cpg_path = f"/playground/cpgs/{codebase_hash}/cpg.bin"

                    # Only report/persist "loading" if a background restart
                    # actually started — otherwise leave the prior status so the
                    # next poll retries instead of stranding it in "loading".
                    scheduled = _schedule_restart_server_task(
                        codebase_hash=codebase_hash,
                        container_cpg_path=container_cpg_path,
                        services=services,
                    )
                    if scheduled:
                        logger.info(f"Joern server not running for {status} codebase {codebase_hash}, restarting in background...")
                        joern_port = None
                        status = "loading"
                        codebase_tracker.update_codebase(
                            codebase_hash=codebase_hash,
                            joern_port=None,
                            metadata={"status": SessionStatus.LOADING, **{k: v for k, v in codebase_info.metadata.items() if k != "status"}}
                        )
                    else:
                        logger.warning(
                            f"Could not start background restart for {codebase_hash}; "
                            f"reporting '{status}' so the next poll retries"
                        )

            response = {
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

            # Surface the failure cause so a failed build is debuggable via the API
            # (e.g. error_code "OOM" / "TIMEOUT" / "BUILD_ERROR") rather than a bare
            # "failed" status that forces digging through container logs.
            if status in (SessionStatus.FAILED, "failed"):
                if codebase_info.metadata.get("error_code"):
                    response["error_code"] = codebase_info.metadata["error_code"]
                if codebase_info.metadata.get("error"):
                    response["error"] = codebase_info.metadata["error"]

            return response

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
            validate_codebase_hash(codebase_hash)
            codebase_tracker = services["codebase_tracker"]
            joern_server_manager = services.get("joern_server_manager")

            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info:
                return {"success": False, "error": f"Codebase {codebase_hash} not found"}

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

            def _under_playground(p: str) -> bool:
                # Defense-in-depth: never rmtree outside the playground, even if a
                # bad hash somehow reached here (it can't — it's hex-validated above).
                real = os.path.realpath(p)
                root = os.path.realpath(playground_path)
                return real == root or real.startswith(root + os.sep)

            cpg_dir = os.path.join(playground_path, "cpgs", codebase_hash)
            if not _under_playground(cpg_dir):
                raise ValidationError("refusing to delete outside the playground")
            if os.path.exists(cpg_dir):
                for dirpath, _, filenames in os.walk(cpg_dir):
                    for fname in filenames:
                        try:
                            freed_bytes += os.path.getsize(os.path.join(dirpath, fname))
                        except OSError:
                            pass
                shutil.rmtree(cpg_dir, ignore_errors=True)

            codebase_dir = os.path.join(playground_path, "codebases", codebase_hash)
            if not _under_playground(codebase_dir):
                raise ValidationError("refusing to delete outside the playground")
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
