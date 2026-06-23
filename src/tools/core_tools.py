"""
Core MCP Tools for CodeBadger Server - Simplified hash-based version

Provides core CPG management functionality
"""

import asyncio
import uuid
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import docker
import hashlib
import io
import logging
import os
import re
import shlex
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


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp, tolerating a missing tz (assume UTC)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _build_job_alive(services: dict, codebase_hash: str) -> bool:
    """True if a CPG build for this codebase is still queued or running.

    Used to distinguish a genuinely in-progress/queued build from one whose
    worker died. On any uncertainty (no queue, queue lacks the probe), return
    True so we never condemn a live build.
    """
    queue = services.get("cpg_queue")
    if queue is None or not hasattr(queue, "is_in_flight"):
        return True
    try:
        return bool(queue.is_in_flight(codebase_hash))
    except Exception as e:
        logger.warning(f"_build_job_alive probe failed for {codebase_hash}: {e}")
        return True


def _playground_path() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "playground"))


def _teardown_codebase(services: dict, codebase_hash: str, delete_files: bool = True) -> int:
    """Evict a codebase's Joern server and (optionally) delete its on-disk
    artifacts + DB row. Returns freed bytes. Shared by remove_cpg and the
    cold-CPG GC sweeper so both tear down identically and safely (never rmtree
    outside the playground). Synchronous — safe to call from a worker thread."""
    joern_server_manager = services.get("joern_server_manager")
    if joern_server_manager and joern_server_manager.get_server_port(codebase_hash):
        joern_server_manager.terminate_server(codebase_hash)

    if not delete_files:
        tracker = services.get("codebase_tracker")
        if tracker is not None:
            tracker.update_codebase(
                codebase_hash=codebase_hash,
                joern_port=None,
                metadata={"status": SessionStatus.SLEEPING},
            )
        return 0

    playground_path = _playground_path()
    root = os.path.realpath(playground_path)
    freed_bytes = 0

    def _under_playground(p: str) -> bool:
        real = os.path.realpath(p)
        return real == root or real.startswith(root + os.sep)

    for sub in ("cpgs", "codebases"):
        target = os.path.join(playground_path, sub, codebase_hash)
        if not _under_playground(target):
            raise ValidationError("refusing to delete outside the playground")
        if os.path.exists(target):
            for dirpath, _, filenames in os.walk(target):
                for fname in filenames:
                    try:
                        freed_bytes += os.path.getsize(os.path.join(dirpath, fname))
                    except OSError:
                        pass
            shutil.rmtree(target, ignore_errors=True)

    db_manager = services.get("db_manager")
    if db_manager is not None:
        db_manager.delete_codebase(codebase_hash)
    return freed_bytes


def _cpgs_disk_usage() -> tuple:
    """(count, total_mb) of on-disk CPG directories under playground/cpgs."""
    cpgs_dir = os.path.join(_playground_path(), "cpgs")
    count, total = 0, 0
    try:
        for entry in os.scandir(cpgs_dir):
            if not entry.is_dir():
                continue
            count += 1
            for dirpath, _, filenames in os.walk(entry.path):
                for fname in filenames:
                    try:
                        total += os.path.getsize(os.path.join(dirpath, fname))
                    except OSError:
                        pass
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.debug(f"_cpgs_disk_usage failed: {e}")
    return count, round(total / (1024 * 1024), 1)


def gc_cold_cpgs(
    services: dict,
    max_age_seconds: int,
    max_count: int,
    delete_cold: bool = False,
) -> dict:
    """Reclaim allocations from cold CPGs. Keeps cpg.bin on disk by default.

    Default (delete_cold=False) — the requested behavior: a CPG with a live
    Joern server that hasn't been accessed for > max_age_seconds has its
    allocations released (server killed, port freed, memory reservation
    dropped) and is marked SLEEPING. The cpg.bin stays on disk and the CPG
    transparently reloads on its next query. Never touches an in-flight,
    generating/loading, or recently-used CPG.

    Opt-in (delete_cold=True) — also delete the on-disk binaries of cold
    sleeping CPGs, and enforce a max_count disk budget (LRU). Off by default.

    Returns a summary dict. Best-effort: a per-CPG failure is logged and skipped.
    """
    tracker = services.get("codebase_tracker")
    mgr = services.get("joern_server_manager")
    if tracker is None:
        return {"evaluated": 0, "deleted": [], "evicted": [], "freed_mb": 0.0}

    try:
        codebases = tracker.list_codebases_full()
    except Exception as e:
        logger.warning(f"cold-CPG GC: could not list codebases: {e}")
        return {"evaluated": 0, "deleted": [], "evicted": [], "freed_mb": 0.0}

    now = _now_utc()

    def _is_running(h: str) -> bool:
        if mgr is None:
            return False
        try:
            return bool(mgr.get_server_port(h) and mgr.is_server_running(h))
        except Exception:
            return False

    def _age(cb) -> float:
        la = cb.last_accessed
        if la is None:
            return float("inf")
        if la.tzinfo is None:
            la = la.replace(tzinfo=timezone.utc)
        return (now - la).total_seconds()

    def _busy(cb) -> bool:
        status = (cb.metadata or {}).get("status", "")
        if status in ("generating", "loading", SessionStatus.GENERATING, SessionStatus.LOADING):
            return True
        return _build_job_alive(services, cb.codebase_hash)

    deleted, evicted, freed = [], [], 0

    # Default path: free allocations of cold RUNNING servers (keep cpg.bin).
    for cb in codebases:
        if _busy(cb):
            continue
        if _is_running(cb.codebase_hash) and _age(cb) > max_age_seconds:
            try:
                _teardown_codebase(services, cb.codebase_hash, delete_files=False)
                evicted.append(_codebase_label(cb))
            except Exception as e:
                logger.warning(f"cold-CPG GC: failed to evict {cb.codebase_hash}: {e}")

    # Opt-in path: delete cold on-disk binaries by age and count budget.
    if delete_cold:
        not_running = [cb for cb in codebases if not _busy(cb) and not _is_running(cb.codebase_hash)]
        to_delete = {cb.codebase_hash: cb for cb in not_running if _age(cb) > max_age_seconds}
        if max_count and max_count > 0:
            on_disk_count, _ = _cpgs_disk_usage()
            survivors = [cb for cb in not_running if cb.codebase_hash not in to_delete]
            survivors.sort(key=_age, reverse=True)  # oldest first
            overflow = on_disk_count - len(to_delete) - max_count
            for cb in survivors:
                if overflow <= 0:
                    break
                to_delete[cb.codebase_hash] = cb
                overflow -= 1
        for h, cb in to_delete.items():
            try:
                freed += _teardown_codebase(services, h, delete_files=True)
                deleted.append(_codebase_label(cb))
            except Exception as e:
                logger.warning(f"cold-CPG GC: failed to delete {h}: {e}")

    if deleted or evicted:
        logger.info(
            f"cold-CPG GC: evicted {len(evicted)} cold server(s) (cpg.bin kept), "
            f"deleted {len(deleted)} binary(ies) ({round(freed / (1024 * 1024), 1)} MB)"
        )
    return {
        "evaluated": len(codebases),
        "deleted": deleted,
        "evicted": evicted,
        "freed_mb": round(freed / (1024 * 1024), 1),
    }


async def _cpg_gc_loop(services: dict, config) -> None:
    """Background loop: periodically GC cold sleeping CPGs (P2-8)."""
    cfg = config.cpg
    interval = max(60, int(getattr(cfg, "gc_interval_seconds", 600)))
    max_age = int(getattr(cfg, "gc_max_age_seconds", 86400))
    max_count = int(getattr(cfg, "gc_max_count", 50))
    delete_cold = bool(getattr(cfg, "gc_delete_cold", False))
    logger.info(
        f"Cold-CPG GC started (every {interval}s; evict servers cold > {max_age}s, "
        f"cpg.bin kept on disk; delete_binaries={delete_cold})"
    )
    loop = asyncio.get_running_loop()
    while True:
        try:
            await asyncio.sleep(interval)
            # The sweep does blocking FS + DB work — keep it off the event loop.
            await loop.run_in_executor(
                None, lambda: gc_cold_cpgs(services, max_age, max_count, delete_cold)
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Cold-CPG GC sweep failed: {e}", exc_info=True)


def _codebase_label(codebase_info) -> str:
    """Stable, non-sensitive label tying a hash back to what it built.

    Form: '<project>@<short-hash>'. The project component is derived from the
    repository URL / source basename / snippet label — never an absolute host
    path — so it's safe to surface to the agent while still being recognizable.
    """
    short = (codebase_info.codebase_hash or "")[:8] or "unknown"
    project = None
    meta = codebase_info.metadata or {}
    repo = meta.get("repository")
    src = codebase_info.source_path
    try:
        if repo:
            project = repo.rstrip("/").rsplit("/", 1)[-1]
            if project.endswith(".git"):
                project = project[:-4]
        elif src:
            # Use only the final path component to avoid leaking directory structure.
            project = os.path.basename(src.rstrip("/")) or src
    except Exception:
        project = None
    project = (project or codebase_info.source_type or "cpg").strip() or "cpg"
    return f"{project}@{short}"


def _set_build_phase(services: dict, codebase_hash: str, phase: str) -> None:
    """Record the current build phase so get_cpg_status can report progress.

    Best-effort: a failure here must never derail the build, so swallow errors.
    Metadata is merged under a row lock by the tracker, so this only touches the
    `phase` key.
    """
    try:
        tracker = services.get("codebase_tracker")
        if tracker is not None:
            tracker.update_codebase(codebase_hash=codebase_hash, metadata={"phase": phase})
    except Exception as e:
        logger.debug(f"Could not set build phase '{phase}' for {codebase_hash}: {e}")


# Maps a coarse status to a default phase when no finer phase was recorded.
_STATUS_TO_PHASE = {
    "generating": "building",
    "loading": "loading",
    "ready": "ready",
    "sleeping": "sleeping",
    "failed": "failed",
}


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

def _sanitize_build_opt_list(items, kind: str) -> list:
    """Validate + normalize a list of c2cpg build options (include paths / defines).

    Drops blanks; rejects control characters; and rejects `..` segments in a relative
    include path (which could escape the source root once joined to the container root).
    Absolute paths are allowed through. Raises ValidationError on a bad entry.
    """
    out = []
    for raw in (items or []):
        s = str(raw).strip()
        if not s:
            continue
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s):
            raise ValidationError(f"Invalid {kind}: control characters not allowed")
        if kind == "include path" and not os.path.isabs(s) and ".." in s.split("/"):
            raise ValidationError("Relative include paths must not contain '..'")
        out.append(s)
    return out


def get_cpg_cache_key(source_type: str, source_path: str, language: str, commit_hash: Optional[str] = None, content: Optional[str] = None, extra: Optional[str] = None, branch: Optional[str] = None) -> str:
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
        if content:
            # Content fingerprint: identical trees dedupe regardless of path, and
            # any content change yields a new key (no stale-CPG reuse). See
            # _fingerprint_local_source.
            identifier = f"local:{language}:{content}"
        else:
            # Fallback when fingerprinting is unavailable: path-based key.
            source_path = os.path.abspath(source_path)
            identifier = f"local:{source_path}:{language}"

    # A requested branch selects a distinct revision of a remote repo, so it must be
    # part of the key — otherwise two branches of the same repo collide on one CPG
    # (and the second request silently reuses the first branch's graph). Only applies
    # to remote sources; default branch (None) leaves the key unchanged for back-compat.
    if branch and source_type == "github":
        identifier += f"@{branch}"

    if commit_hash:
        identifier += f":{commit_hash}"

    # Build options (caller-supplied include paths / defines) change the produced CPG,
    # so they must be part of the cache key or a stale CPG would be reused.
    if extra:
        identifier += f":{extra}"

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
    """Copy a local source tree into the playground snapshot dir, atomically.

    Symlink-safe: never dereferences symlinks whose target escapes the source root
    (prevents pulling arbitrary host files into the readable snapshot).

    Atomic: the tree is built in a sibling temp dir and then os.replace()'d into
    place, so two concurrent generate_cpg calls for the same path can never produce
    a half-merged/corrupt snapshot (the cause of spurious empty/parse-failed CPGs).
    The first rename wins; a loser whose destination already exists discards its
    temp and reuses the winner's complete copy.

    Blocking I/O — invoke via asyncio.to_thread so it never runs on the event loop.
    Doing it on the loop serializes concurrent generate_cpg calls, which inflates
    the latency between request receipt and source capture; under a batch driver
    that cleans up its source dirs on a timer, a delayed copy races the cleanup and
    fails with "Path does not exist".
    """
    if os.path.exists(codebase_dir):
        return  # a concurrent caller already captured a complete snapshot
    # Build into a sibling temp dir on the same filesystem so the final move is a
    # cheap, atomic rename rather than a cross-device copy.
    tmp_dir = f"{codebase_dir}.tmp.{uuid.uuid4().hex}"
    os.makedirs(tmp_dir, exist_ok=True)
    real_root = os.path.realpath(host_path)
    try:
        for item in os.listdir(host_path):
            src_item = os.path.join(host_path, item)
            dst_item = os.path.join(tmp_dir, item)

            if os.path.islink(src_item):
                if not os.path.realpath(src_item).startswith(real_root + os.sep):
                    logger.warning(f"Skipping symlink escaping source root: {item}")
                    continue

            if os.path.isdir(src_item):
                # symlinks=True: copy nested links as links, never dereference out of tree.
                shutil.copytree(src_item, dst_item, dirs_exist_ok=True, symlinks=True)
            else:
                shutil.copy2(src_item, dst_item, follow_symlinks=False)

        try:
            os.replace(tmp_dir, codebase_dir)  # atomic when dest doesn't exist
        except OSError:
            # A concurrent caller won the race and populated codebase_dir first;
            # their snapshot is complete, so drop ours.
            shutil.rmtree(tmp_dir, ignore_errors=True)
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def _copy_local_source_tree_via_daemon(host_path: str, codebase_hash: str) -> None:
    """Copy a host source tree into the playground via a short-lived helper container.

    Used when the MCP is containerized and `host_path` lives on the host
    filesystem, so this process cannot read it directly (the in-process
    `_copy_local_source_tree` would fail). The host Docker daemon — reachable
    through the mounted socket — bind-mounts the real source's PARENT dir
    read-only and the shared playground read-write into an ephemeral helper
    container, which copies the tree to /playground/codebases/<hash>.

    Mirrors `_copy_local_source_tree`'s guarantees: existence is validated on the
    host (the source must exist and be non-empty — note `docker run` auto-creates
    a missing bind source, so we mount the parent and `test -d` the child rather
    than mounting the source itself), and the snapshot is built in a sibling
    `.tmp` dir then renamed so a partial/concurrent copy can't yield a corrupt
    tree. The helper reuses the joern-server image so no extra pull is needed.
    """
    playground_host = os.getenv("JOERN_PLAYGROUND_HOST_PATH", "").strip()
    if not playground_host:
        raise ValidationError(
            "JOERN_PLAYGROUND_HOST_PATH is not set; the containerized MCP cannot "
            "copy a host source path without knowing the playground's host path."
        )

    clean = host_path.rstrip("/")
    parent, base = os.path.dirname(clean), os.path.basename(clean)
    if not parent or not base:
        raise ValidationError("Invalid host source path")

    client = docker.from_env()
    joern_container = os.getenv("JOERN_CONTAINER_NAME", "codebadger-joern-server")
    try:
        image = client.containers.get(joern_container).image.id
    except docker.errors.NotFound:
        raise ValidationError(
            f"Helper image source container '{joern_container}' not found; "
            f"start it with: docker compose up -d"
        )

    src = "/src/" + shlex.quote(base)                       # source dir inside helper
    dst = "/pg/codebases/" + shlex.quote(codebase_hash)
    tmp = dst + ".tmp"
    script = (
        "set -e; "
        f"test -d {src}; "
        f'[ -n "$(ls -A {src})" ] || {{ echo "source is empty" >&2; exit 3; }}; '
        f"rm -rf {tmp} {dst}; "
        f"mkdir -p {tmp}; "
        f"cp -a {src}/. {tmp}/; "
        f"mv {tmp} {dst}"
    )
    try:
        client.containers.run(
            image=image,
            entrypoint=["/bin/sh", "-c", script],
            volumes={
                parent: {"bind": "/src", "mode": "ro"},
                playground_host: {"bind": "/pg", "mode": "rw"},
            },
            remove=True,
            network_disabled=True,
        )
    except docker.errors.ContainerError as e:
        raise ValidationError(
            f"Failed to copy host source via helper container (exit {e.exit_status}); "
            f"check that the path exists on the host and is non-empty"
        )


def _joern_helper_image() -> str:
    """Resolve an image id to use for short-lived playground helper containers.

    Reuses the running joern-server's image so nothing extra is pulled.
    """
    client = docker.from_env()
    name = os.getenv("JOERN_CONTAINER_NAME", "codebadger-joern-server")
    try:
        return client.containers.get(name).image.id
    except docker.errors.NotFound:
        raise ValidationError(
            f"Helper image source container '{name}' not found; "
            f"start it with: docker compose up -d"
        )


def _hash_tree_in_process(root: str) -> str:
    """Deterministic content fingerprint of a directory tree (this process reads it).

    Hashes (relative-path, file-content) for every regular file, excluding .git,
    in sorted order. Independent of mtime/path-prefix so identical trees collide
    (dedupe) and any content change yields a new digest (no stale-CPG reuse).
    """
    entries = []
    for dirpath, dirs, files in os.walk(root):
        if ".git" in dirs:
            dirs.remove(".git")
        for f in sorted(files):
            fp = os.path.join(dirpath, f)
            rel = os.path.relpath(fp, root)
            if os.path.islink(fp):
                h = hashlib.sha256(b"L" + os.readlink(fp).encode()).hexdigest()
            else:
                hsh = hashlib.sha256()
                with open(fp, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 16), b""):
                        hsh.update(chunk)
                h = hsh.hexdigest()
            entries.append(rel + "\0" + h)
    entries.sort()
    return hashlib.sha256("\n".join(entries).encode()).hexdigest()


def _fingerprint_local_source_via_daemon(host_path: str) -> str:
    """Content fingerprint of a host tree the MCP can't read, via a helper container.

    Deterministic within a deployment (always taken from the host daemon): hashes
    every file's content+name (excluding .git) in a stable order. Mirrors the
    intent of _hash_tree_in_process; the two need not match byte-for-byte since a
    given deployment uses exactly one of them.
    """
    clean = host_path.rstrip("/")
    parent, base = os.path.dirname(clean), os.path.basename(clean)
    if not parent or not base:
        raise ValidationError("Invalid host source path")

    src = "/src/" + shlex.quote(base)
    # find (excluding .git) -> stable sort -> per-file sha256 -> sha256 of the lot.
    script = (
        "set -e; "
        f"cd {src}; "
        "find . -path ./.git -prune -o -type f -print0 "
        "| LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -c1-64"
    )
    client = docker.from_env()
    try:
        out = client.containers.run(
            image=_joern_helper_image(),
            entrypoint=["/bin/sh", "-c", script],
            volumes={parent: {"bind": "/src", "mode": "ro"}},
            remove=True,
            network_disabled=True,
        )
    except docker.errors.ContainerError as e:
        raise ValidationError(
            f"Failed to fingerprint host source via helper container (exit {e.exit_status})"
        )
    digest = (out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)).strip()
    if not digest:
        raise ValidationError("Empty fingerprint from helper container")
    return digest


def _fingerprint_local_source(source_path: str) -> Optional[str]:
    """Content fingerprint for a local source, used as the CPG cache key.

    Reads the tree in-process when it is visible (MCP on host / bind-mounted),
    else computes it on the host via a helper container (containerized MCP).
    Returns None on failure so the caller can fall back to path-based keying.
    """
    host_path = resolve_host_path(source_path, require_local_access=False)
    if os.path.exists(host_path):
        return _hash_tree_in_process(host_path)
    return _fingerprint_local_source_via_daemon(host_path)


def _reclaim_source_snapshot(codebase_dir: str, cpg_path: str, config) -> bool:
    """Delete the source snapshot once the CPG exists (ephemeral source).

    The CPG (cpg.bin) is the sole persisted artifact and no tool reads source from
    disk, so the snapshot (and any github clone under the same dir) is reclaimed
    after a successful build. A later regenerate re-fetches source. Gated by
    config.cpg.ephemeral_source (default on). Best-effort — only deletes once the
    CPG is actually on disk, and never raises. Returns True if it deleted.
    """
    ephemeral = getattr(config.cpg, "ephemeral_source", True) if config else True
    if not ephemeral:
        return False
    if not (cpg_path and os.path.exists(cpg_path)):
        return False  # no CPG yet — keep source for retry/inspection
    if not os.path.isdir(codebase_dir):
        return False
    try:
        shutil.rmtree(codebase_dir, ignore_errors=True)
        logger.info(f"Reclaimed source snapshot {codebase_dir} (ephemeral source)")
        return True
    except Exception as e:  # noqa: BLE001 — cleanup must never fail a built CPG
        logger.warning(f"Could not delete source snapshot {codebase_dir}: {e}")
        return False


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
        # reload_with_retry spawns + loads, retrying transient failures (each
        # re-spawning) before giving up; an empty/broken build is not retried.
        joern_port = await loop.run_in_executor(
            None, joern_server_manager.reload_with_retry, codebase_hash, container_cpg_path
        )
        if not joern_port:
            # The reload failed after all retries (the server was already
            # terminated). Mark FAILED so we don't leave a "ready" codebase whose
            # server is dead — that caused the restart-fail churn (server not
            # running for ready codebase -> retry -> fail -> repeat).
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
        except Exception as tracker_error:
            logger.warning(
                f"Could not mark {codebase_hash} FAILED after restart error: {tracker_error}"
            )


def _autodetect_c_includes(codebase_dir: str, max_dirs: int = 24) -> list:
    """Lightweight C/C++ include-dir discovery for the c2cpg `--include` path.

    Returns directories (RELATIVE to codebase_dir) worth adding to the header
    search path: the source root, any `include/` dir, and any dir that directly
    contains config.h or a generated *version*.h. This lets angle-includes like
    <libxml/xmlversion.h> resolve so feature macros (e.g. LIBXML_CATALOG_ENABLED)
    are defined and #ifdef-gated modules are parsed instead of silently dropped.

    Bounded (depth + count) and never raises — it's a best-effort enrichment of
    the otherwise fuzzy parse, not a correctness requirement. System-header
    auto-discovery is intentionally NOT enabled here.
    """
    found = ["."]  # source root
    try:
        for dirpath, dirs, files in os.walk(codebase_dir):
            dirs[:] = [d for d in dirs if d not in (".git", ".svn", ".hg", "node_modules")]
            rel = os.path.relpath(dirpath, codebase_dir)
            depth = 0 if rel == "." else rel.count(os.sep) + 1
            if depth > 5:
                dirs[:] = []
                continue
            if rel != ".":
                is_include_dir = os.path.basename(dirpath) == "include"
                has_generated_hdr = ("config.h" in files) or any(
                    f.endswith(".h") and "version" in f.lower() for f in files
                )
                if is_include_dir or has_generated_hdr:
                    found.append(rel)
            if len(found) >= max_dirs:
                break
    except Exception:
        pass
    seen, out = set(), []
    for p in found:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


async def _generate_cpg_async(
    codebase_hash: str,
    codebase_dir: str,
    cpg_path: str,
    language: str,
    container_cpg_path: str,
    services: dict,
    include_paths: Optional[list] = None,
    defines: Optional[list] = None,
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

        # Header include paths + preprocessor defines (C/C++ only — these are c2cpg
        # flags). Without them, angle-includes of generated headers (e.g.
        # <libxml/xmlversion.h>) don't resolve and feature macros stay undefined, so
        # whole #ifdef-gated modules get preprocessed out of the CPG. We auto-detect
        # likely include roots (source root, include/, dirs with config.h/*version*.h)
        # and append any caller-supplied include_paths/defines. Relative paths are
        # resolved against the in-container source root; absolute paths pass through.
        if language in ("c", "cpp"):
            container_root = f"/playground/codebases/{codebase_hash}"

            def _to_container(p: str) -> str:
                p = p.strip()
                if not p:
                    return ""
                return p if os.path.isabs(p) else (container_root + "/" + p.lstrip("./")).rstrip("/")

            auto_rel = await asyncio.to_thread(_autodetect_c_includes, codebase_dir)
            inc_dirs, seen_inc = [], set()
            for p in [_to_container(x) for x in auto_rel] + [_to_container(x) for x in (include_paths or [])]:
                if p and p not in seen_inc:
                    seen_inc.add(p)
                    inc_dirs.append(p)
            for d in inc_dirs:
                cmd += ["--include", d]
            for macro in (defines or []):
                macro = str(macro).strip()
                if macro:
                    cmd += ["--define", macro]
            if inc_dirs or defines:
                logger.info(
                    f"c2cpg include dirs={len(inc_dirs)} (auto={len(auto_rel)}, "
                    f"explicit={len(include_paths or [])}), defines={len(defines or [])}"
                )

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
        # Worker has claimed the job and is now parsing the source (c2cpg frontend).
        _set_build_phase(services, codebase_hash, "frontend")
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

        # Load-size admission: a cpg.bin above the ceiling almost never loads
        # reliably into a memory-capped query worker (FFmpeg's full tree ~1.6 GB
        # was the motivating case). Fail fast HERE with actionable guidance —
        # scope the build — instead of letting reload_with_retry emit the opaque
        # "failed to reload into a Joern server" after a long stall.
        max_load_mb = config.cpg.max_load_mb if config else 2048
        if max_load_mb and max_load_mb > 0:
            try:
                cpg_size_mb = os.path.getsize(cpg_path) / (1024 * 1024)
            except OSError:
                cpg_size_mb = 0
            if cpg_size_mb > max_load_mb:
                error_msg = (
                    f"CPG is {cpg_size_mb:.0f} MB, above the {max_load_mb} MB load ceiling — "
                    f"it likely won't load into a query server. Scope the build to a "
                    f"sub-component (point source_path at a subdirectory, or pass include_paths/"
                    f"defines to narrow what is parsed), or raise CPG_MAX_LOAD_MB / the Joern "
                    f"load heap if you have the RAM."
                )
                logger.error(f"CPG too large to load for {codebase_hash}: {error_msg}")
                codebase_tracker.update_codebase(
                    codebase_hash=codebase_hash,
                    cpg_path=cpg_path,
                    metadata={
                        "status": SessionStatus.FAILED,
                        "error_code": "CPG_TOO_LARGE",
                        "error": error_msg,
                        "cpg_size_mb": round(cpg_size_mb, 1),
                    },
                )
                return

        # Persist cpg_path before attempting server spawn so that the watchdog's
        # _respawn_server can find it even if spawn_server fails mid-flight.
        codebase_tracker.update_codebase(
            codebase_hash=codebase_hash,
            cpg_path=cpg_path,
            metadata={
                "status": SessionStatus.GENERATING,
                "phase": "loading",
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
                logger.info(f"Spawning Joern server and loading CPG for {codebase_hash}")
                # reload_with_retry spawns + loads, retrying transient first-load
                # failures so a freshly-built CPG isn't condemned by a momentary
                # stall under host pressure; an empty build is not retried.
                joern_port = await loop.run_in_executor(
                    None, joern_server_manager.reload_with_retry, codebase_hash, container_cpg_path
                )
                if joern_port:
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
        # Record the verified user-method count (coverage sanity check) when the
        # load reported one, so get_cpg_status can surface user_method_count.
        ready_meta = {
            "status": "ready",
            "phase": "ready",
            "container_codebase_path": f"/playground/codebases/{codebase_hash}",
            "container_cpg_path": container_cpg_path,
        }
        user_method_count = getattr(joern_server_manager, "_last_user_method_count", None) if joern_server_manager else None
        if user_method_count is not None:
            ready_meta["user_method_count"] = user_method_count
        codebase_tracker.update_codebase(
            codebase_hash=codebase_hash,
            cpg_path=cpg_path,
            joern_port=joern_port,
            metadata=ready_meta,
        )

        logger.info(f"CPG generation complete for {codebase_hash}, port: {joern_port}")

        # Ephemeral source: the build is done and cpg.bin is the sole persisted
        # artifact (no tool reads source from disk), so drop the source snapshot —
        # and any github clone, which lives under the same dir — to reclaim disk.
        # A later regenerate re-fetches the source.
        _reclaim_source_snapshot(codebase_dir, cpg_path, services.get("config"))

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

    def is_in_flight(self, codebase_hash: str) -> bool:
        """True if a build for this codebase is queued or running."""
        return codebase_hash in self._in_flight

    def queue_position(self, codebase_hash: str) -> Optional[int]:
        """Best-effort queue position. The in-memory asyncio.Queue doesn't expose
        per-item ordering, so we can't compute a precise position — return None."""
        return None

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

    def is_in_flight(self, codebase_hash: str) -> bool:
        """True if a build for this codebase is queued or running in the DB."""
        return self.store.has_active_job(codebase_hash, self.JOB_TYPE)

    def queue_position(self, codebase_hash: str) -> Optional[int]:
        """1-based position among queued jobs, or None if not queued."""
        position = getattr(self.store, "queue_position", None)
        if position is None:
            return None
        return position(codebase_hash, self.JOB_TYPE)

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
        include_paths: Annotated[Optional[list], Field(description="C/C++ only: extra header include directories for c2cpg (--include). Relative paths resolve against the source root (e.g. 'include', '_build/include'); absolute paths pass through. Use when a project's generated headers (e.g. a configure/cmake-produced xmlversion.h or config.h) gate code behind feature macros — the source root, any include/ dir, and dirs containing config.h/*version*.h are auto-detected, so this is only needed for non-standard layouts.")] = None,
        defines: Annotated[Optional[list], Field(description="C/C++ only: preprocessor macros to define for c2cpg (--define), e.g. ['LIBXML_CATALOG_ENABLED', 'FOO=1']. Use to force-enable #ifdef-gated modules when the defining header can't be found.")] = None,
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
            content_fp = code  # snippet body, when source_type == "snippet"
            if source_type == "local":
                try:
                    # Content fingerprint of the tree (works for non-git sources and
                    # for a containerized MCP that can't read the host path directly).
                    content_fp = await asyncio.to_thread(_fingerprint_local_source, source_path)
                    if content_fp:
                        logger.info(f"Local source content fingerprint: {content_fp[:16]}")
                except Exception as e:
                    logger.warning(
                        f"Failed to fingerprint local source ({e}); falling back to path-based key"
                    )
                    content_fp = None

            # Normalize + validate C/C++ build options (no control chars; relative
            # include paths must stay within the source root). Build options are part
            # of the cache key so a different -I/-D set yields a distinct CPG.
            include_paths = _sanitize_build_opt_list(include_paths, "include path")
            defines = _sanitize_build_opt_list(defines, "define")
            if (include_paths or defines) and language not in ("c", "cpp"):
                logger.warning(f"include_paths/defines ignored for language '{language}' (C/C++ only)")
                include_paths, defines = [], []

            _opts = []
            if include_paths:
                _opts.append("inc=" + ",".join(sorted(include_paths)))
            if defines:
                _opts.append("def=" + ",".join(sorted(defines)))
            build_opts_key = ";".join(_opts) if _opts else None

            codebase_hash = get_cpg_cache_key(source_type, source_path, language, commit_hash, content=content_fp, extra=build_opts_key, branch=branch)
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

            # Single-flight: if another request is already preparing/submitting this
            # exact codebase, skip the duplicate source copy + enqueue. Correctness is
            # still guaranteed by the atomic copy and the durable queue's dedup index;
            # this only avoids wasted work. Best-effort, so a non-Redis coordinator just
            # proceeds (nullcontext yields True).
            _coordinator = services.get("coordinator")
            _gen_cm = (
                _coordinator.codebase_generation_lock(codebase_hash)
                if _coordinator is not None and hasattr(_coordinator, "codebase_generation_lock")
                else nullcontext(True)
            )
            with _gen_cm as _gen_acquired:
                if not _gen_acquired:
                    return {
                        "success": True,
                        "codebase_hash": codebase_hash,
                        "status": SessionStatus.GENERATING,
                        "message": "CPG build already in progress for this codebase.",
                    }

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
                    # require_local_access=False: a containerized MCP can't see a
                    # host source path, so defer the existence check — we copy via a
                    # host-daemon helper below (which validates existence on the host).
                    host_path = await asyncio.to_thread(
                        resolve_host_path, source_path, False
                    )

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
                            if os.path.exists(host_path):
                                # Path is visible to this process (MCP on host, or the
                                # source is bind-mounted in): copy in-process.
                                await asyncio.to_thread(
                                    _copy_local_source_tree, host_path, codebase_dir
                                )
                            else:
                                # Containerized MCP + host-only path: copy via the host
                                # Docker daemon using a short-lived helper container.
                                logger.info(
                                    f"{host_path} not visible to MCP; copying via host-daemon helper"
                                )
                                await asyncio.to_thread(
                                    _copy_local_source_tree_via_daemon, host_path, codebase_hash
                                )
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
                # Stamp a generation deadline so get_cpg_status can reconcile a
                # build whose worker died (status stuck on 'generating' forever).
                # Budget = timeout + a generous grace for queue wait, server spawn
                # and CPG load; only a past-deadline build with NO live worker is
                # condemned, so an over-grace estimate just delays the safety net.
                _gen_timeout = config.cpg.generation_timeout if config else 600
                _gen_grace = config.cpg.generation_deadline_grace if config else 600
                _started_at = _now_utc()
                _deadline = _started_at + timedelta(seconds=_gen_timeout + _gen_grace)
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
                        "status": SessionStatus.GENERATING,
                        "phase": "queued",
                        "generation_started_at": _started_at.isoformat(),
                        "generation_deadline": _deadline.isoformat(),
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
                    include_paths=include_paths or None,
                    defines=defines or None,
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
        "codebase_label": "<project>@<short-hash>",  # non-sensitive, ties hash to what it built
        "status": "generating" | "loading" | "ready" | "sleeping" | "failed" | "not_found",
        "cpg_path": "path to CPG if exists",
        "joern_port": port number or null,
        "language": "programming language",
        "phase": "queued" | "frontend" | "loading" | "ready" | ...,  # finer-grained than status
        "elapsed_seconds": seconds since the build started,
        "deadline_seconds": seconds of budget left before timeout reconciliation (0 = overdue),
        "queue_position": 1-based position behind other queued builds (only while queued),
        "user_method_count": verified user-defined methods in the loaded CPG (coverage check)
    }

Notes:
    - 'generating'/'loading' → build or server startup in progress; wait briefly and poll again.
      Use `phase`/`elapsed_seconds`/`queue_position` to tell "queued behind others" from
      "actively parsing" from "wedged" (deadline_seconds at 0 and still generating = likely stuck).
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

            # Reconcile a stranded "generating": a build can sit in GENERATING
            # forever if its worker died (process restart, OOM kill, in-memory
            # queue lost the job) — there is otherwise no terminal transition, so
            # pollers block indefinitely. Only condemn it once it is BOTH past its
            # deadline AND has no live build job (a queued/running job, however
            # long, is left alone). _build_job_alive fails safe (True on doubt).
            if status in ("generating", SessionStatus.GENERATING):
                deadline = _parse_iso(codebase_info.metadata.get("generation_deadline"))
                past_deadline = deadline is not None and _now_utc() > deadline
                if past_deadline and not _build_job_alive(services, codebase_hash):
                    config = services.get("config")
                    timeout = config.cpg.generation_timeout if config else 600
                    status = "failed"
                    new_meta = {
                        **codebase_info.metadata,
                        "status": SessionStatus.FAILED,
                        "error_code": "GENERATION_TIMEOUT",
                        "error": (
                            f"CPG build exceeded its deadline ({timeout}s + grace) with "
                            "no live worker — the build worker likely died or was lost. "
                            "Regenerate with generate_cpg."
                        ),
                    }
                    codebase_info.metadata.update(new_meta)
                    codebase_tracker.update_codebase(
                        codebase_hash=codebase_hash,
                        joern_port=None,
                        metadata=new_meta,
                    )
                    logger.warning(
                        f"Reconciled stranded 'generating' CPG {codebase_hash} to FAILED "
                        f"(past deadline, no live build job)"
                    )

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

            # Progress telemetry so a poller can tell "queued behind others" from
            # "actively building" from "wedged", instead of staring at a bare status.
            meta = codebase_info.metadata
            phase = meta.get("phase") or _STATUS_TO_PHASE.get(status, status)
            response["phase"] = phase

            # Stable, non-sensitive label so an agent can tie this hash back to
            # what it built (paths are redacted). Form: '<project>@<short-hash>'.
            response["codebase_label"] = _codebase_label(codebase_info)

            # Coverage sanity check: a tiny (or zero) user-method count on a build
            # that claims ready usually means most code was gated/preprocessed out.
            if meta.get("user_method_count") is not None:
                response["user_method_count"] = meta["user_method_count"]

            started = _parse_iso(meta.get("generation_started_at")) or codebase_info.created_at
            if started is not None:
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                response["elapsed_seconds"] = round((_now_utc() - started).total_seconds(), 1)

            deadline = _parse_iso(meta.get("generation_deadline"))
            if deadline is not None:
                response["deadline_seconds"] = max(0.0, round((deadline - _now_utc()).total_seconds(), 1))

            # Queue position only makes sense while still queued; surface it so a
            # caller knows it's behind N others rather than actively parsing.
            if status in ("generating", SessionStatus.GENERATING):
                cpg_queue = services.get("cpg_queue")
                if cpg_queue is not None and hasattr(cpg_queue, "queue_position"):
                    try:
                        pos = cpg_queue.queue_position(codebase_hash)
                    except Exception as e:
                        logger.debug(f"queue_position probe failed for {codebase_hash}: {e}")
                        pos = None
                    if pos is not None:
                        response["queue_position"] = pos
                        response["phase"] = "queued"

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
        description="""Inspect backend capacity and load so you can self-pace CPG generation.

Read-only. Use this BEFORE fanning out many generate_cpg calls (or when builds
seem to be queuing) to decide how many to run concurrently instead of melting the
backend. The safe concurrency is `recommended_max_concurrent_builds`.

Returns:
    {
        "build_workers": N,                       # parallel build slots
        "recommended_max_concurrent_builds": N,   # don't exceed this many in-flight builds
        "queue_depth": queued builds waiting,
        "queue_maxsize": 0 (unlimited) or the cap,
        "in_flight": queued + running builds,
        "active_servers": live Joern query servers,
        "max_active_servers": server admission cap,
        "memory": {budget_mb, reserved_mb, free_mb, utilization_pct, ...},
        "cpgs": [{codebase_label, status, phase, language, last_accessed}, ...],
        "cpg_count": total tracked CPGs
    }

Notes:
    - If `in_flight` >= `recommended_max_concurrent_builds`, wait (poll get_cpg_status)
      before submitting more — extra builds will just queue.
    - High memory `utilization_pct` (or active_servers at max_active_servers) means
      query servers are being evicted/serialized; expect sleeping CPGs to wake slowly.
    - Filesystem paths are not exposed; CPGs are identified by `codebase_label`.
""",
    )
    def get_backend_status() -> Dict[str, Any]:
        """Report build-queue, Joern-server and memory load for agent self-pacing."""
        try:
            config = services.get("config")
            cpg_queue = services.get("cpg_queue")
            mgr = services.get("joern_server_manager")
            tracker = services.get("codebase_tracker")

            build_workers = config.cpg.build_workers if config else None
            response: Dict[str, Any] = {
                "build_workers": build_workers,
                "recommended_max_concurrent_builds": build_workers,
            }

            if cpg_queue is not None:
                try:
                    response["queue_depth"] = cpg_queue.depth
                    response["queue_maxsize"] = cpg_queue.maxsize
                    response["in_flight"] = cpg_queue.in_flight
                except Exception as e:
                    logger.debug(f"get_backend_status: queue introspection failed: {e}")

            if mgr is not None:
                try:
                    running = mgr.get_running_servers()
                    response["active_servers"] = len(running)
                except Exception as e:
                    logger.debug(f"get_backend_status: running-server count failed: {e}")
                response["max_active_servers"] = getattr(mgr, "_max_active", None)
                try:
                    response["memory"] = mgr.get_memory_stats()
                except Exception as e:
                    logger.debug(f"get_backend_status: memory stats failed: {e}")

            if tracker is not None:
                try:
                    codebases = tracker.list_codebases_full()
                    cpgs = []
                    for cb in codebases:
                        meta = cb.metadata or {}
                        cpgs.append({
                            "codebase_label": _codebase_label(cb),
                            "status": meta.get("status", "unknown"),
                            "phase": meta.get("phase"),
                            "language": cb.language,
                            "last_accessed": cb.last_accessed.isoformat() if cb.last_accessed else None,
                        })
                    response["cpgs"] = cpgs
                    response["cpg_count"] = len(cpgs)
                except Exception as e:
                    logger.debug(f"get_backend_status: codebase listing failed: {e}")

            try:
                on_disk, disk_mb = _cpgs_disk_usage()
                response["cpgs_on_disk"] = on_disk
                response["disk_mb"] = disk_mb
            except Exception as e:
                logger.debug(f"get_backend_status: disk usage failed: {e}")

            return response
        except Exception as e:
            logger.error(f"Failed to get backend status: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

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

            if not delete_files:
                _teardown_codebase(services, codebase_hash, delete_files=False)
                return {
                    "success": True,
                    "codebase_hash": codebase_hash,
                    "status": SessionStatus.SLEEPING,
                    "message": "Joern process terminated. CPG kept on disk for fast re-activation.",
                }

            # delete_files=True: remove the server, on-disk artifacts and DB row.
            freed_bytes = _teardown_codebase(services, codebase_hash, delete_files=True)
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
