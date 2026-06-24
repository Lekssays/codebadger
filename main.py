#!/usr/bin/env python3
"""
CodeBadger Server - Main entry point using FastMCP

This is the main entry point for the CodeBadger Server that provides static code analysis
capabilities through the Model Context Protocol (MCP) using Joern's Code Property Graph.
"""

import asyncio
import logging
import os
import re
import shutil
import socket
import time
from contextlib import suppress
from datetime import datetime, timezone
from fastmcp import FastMCP
from fastmcp.server.lifespan import lifespan
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from src.config import load_config
from src import defaults
from src.tools.core_tools import CPGGenerationQueue, DurableCPGQueue, _cpg_gc_loop, _schedule_restart_server_task
from src.services import (
    CodebaseTracker,
    GitManager,
    JoernServerManager,
    PortManager,
    QueryExecutor,
    CodeBrowsingService
)
from src.utils import setup_logging
from src.utils import compute_recommendation, current_from_config, render_recommendation
from src.startup_tuning import apply_startup_tuning, container_mem_limit_mb, parse_mem_to_mb
from src.health import (
    aggregate_status as _aggregate_status,
    const as _const,
    describe_joern_container_issue as _describe_joern_container_issue,
    format_codebase_source as _format_codebase_source,
    format_uptime as _format_uptime,
    get_disk_usage as _get_disk_usage,
    get_process_memory_mb as _get_process_memory_mb,
    get_system_memory_available_gb as _get_system_memory_available_gb,
    run_probe as _run_probe,
)
from src.utils.postgres_db_manager import PostgresDBManager

# Postgres and Redis are the backing services. Connection URLs resolve from env
# (DATABASE_URL / REDIS_URL, or the component POSTGRES_* / REDIS_* vars that
# docker-compose also uses), defaulting to the compose services. A missing or
# unreachable Postgres/Redis fails the boot (fail-fast), see app_lifespan.
from src.defaults import resolve_database_url, resolve_redis_url
from src.tools import register_tools

VERSION = "0.6.0-beta"

services = {}

# Set when the lifespan starts — used for uptime calculation
_server_start_time: float = 0.0

logger = logging.getLogger(__name__)


def _setup_telemetry(config) -> None:
    """Configure OpenTelemetry SDK if telemetry is enabled.

    Must be called before FastMCP tools are invoked so the tracer provider
    is in place when FastMCP's built-in instrumentation fires.
    """
    telemetry = config.telemetry
    if not telemetry.enabled:
        logger.debug("Telemetry disabled, skipping OpenTelemetry setup")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({"service.name": telemetry.service_name})
        provider = TracerProvider(resource=resource)

        if telemetry.otlp_protocol == "grpc":
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        else:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        exporter = OTLPSpanExporter(endpoint=telemetry.otlp_endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        logger.info(f"OpenTelemetry enabled: exporting to {telemetry.otlp_endpoint} via {telemetry.otlp_protocol}")
    except ImportError:
        logger.warning("OpenTelemetry packages not installed. Install with: pip install opentelemetry-sdk opentelemetry-exporter-otlp")
    except Exception as e:
        logger.warning(f"Failed to initialize OpenTelemetry: {e}")


def _log_effective_config(config) -> None:
    """Log the RESOLVED runtime config and flag env-vs-effective mismatches.

    Env vars are only honored if config.yaml uses a ${VAR:default} placeholder, so
    `CPG_QUEUE_BACKEND=durable` (etc.) can be silently ignored. This prints what
    actually took effect and warns when the env you set disagrees with it — the
    "I set the env but it didn't take" class of boot-time surprise."""
    try:
        joern_mgr = services.get("joern_server_manager")
        coordinator = services.get("coordinator")
        cpg_queue = services.get("cpg_queue")
        container_name = services.get("joern_container_name", "codebadger-joern-server")

        database_url = resolve_database_url()
        db_target = database_url.split("@")[-1]
        redis_url = resolve_redis_url()

        worker_mode = getattr(config.joern, "worker_mode", "shared")
        queue_backend = getattr(config.cpg, "queue_backend", "memory")
        coord_backend = getattr(coordinator, "backend", "unknown") if coordinator else "none"
        queue_type = type(cpg_queue).__name__ if cpg_queue else "none"
        mem_budget = getattr(config.joern, "memory_budget_mb", 0)
        build_heap = getattr(config.cpg, "build_heap_gb", "?")
        build_workers = getattr(config.cpg, "build_workers", "?")

        logger.info("=" * 60)
        logger.info("Effective runtime configuration:")
        logger.info(f"  Database     : postgres @ {db_target} (required)")
        logger.info(f"  Redis        : {redis_url.split('@')[-1]} (required)")
        logger.info(f"  Coordinator  : {coord_backend}")
        logger.info(f"  Joern mode   : {worker_mode}")
        logger.info(f"  CPG queue    : {queue_backend} ({queue_type})")
        logger.info(f"  Query budget : {mem_budget}MB")
        logger.info(f"  Build        : {build_workers} workers × {build_heap}G heap")

        intended = os.getenv("JOERN_MEM_LIMIT")
        actual_mb = container_mem_limit_mb(joern_mgr, container_name) if joern_mgr else None
        if actual_mb is not None:
            logger.info(f"  Build cap    : {actual_mb}MB (live container '{container_name}')")
            intended_mb = parse_mem_to_mb(intended)
            if intended_mb is not None and abs(intended_mb - actual_mb) > 1:
                logger.warning(
                    f"  ⚠ JOERN_MEM_LIMIT={intended} (≈{intended_mb}MB) != live container cap "
                    f"{actual_mb}MB. A running container's mem_limit is fixed at compose-up; "
                    f"recreate it: `JOERN_MEM_LIMIT={intended} docker compose "
                    f"up -d --force-recreate {container_name}`."
                )
        logger.info("=" * 60)

        # Env-vs-effective drift: the env was set but the placeholder wasn't honored.
        def _drift(env_name, env_val, effective, label):
            if env_val and env_val.lower() != str(effective).lower():
                logger.warning(
                    f"  ⚠ {env_name}={env_val} but effective {label}={effective}. "
                    f"config.yaml likely lacks a ${{{env_name}:...}} placeholder, so the env "
                    f"was ignored. Edit config.yaml or unset config.yaml to use env defaults."
                )

        _drift("CPG_QUEUE_BACKEND", os.getenv("CPG_QUEUE_BACKEND", ""), queue_backend, "queue_backend")
        _drift("JOERN_WORKER_MODE", os.getenv("JOERN_WORKER_MODE", ""), worker_mode, "worker_mode")

        # Durable queue requested but jobs table never engaged is worth a hint.
        if queue_backend == "durable" and "Durable" not in queue_type:
            logger.warning(
                f"  ⚠ queue_backend=durable but the active queue is {queue_type}, not DurableCPGQueue."
            )
    except Exception as e:
        logger.warning(f"Could not log effective configuration: {e}")


async def _graceful_shutdown():
    """Gracefully shutdown all services"""
    logger.info("Performing graceful shutdown...")

    try:
        status_log_task = services.get('status_log_task')
        if status_log_task:
            status_log_task.cancel()
            with suppress(asyncio.CancelledError):
                await status_log_task

        cpg_gc_task = services.get('cpg_gc_task')
        if cpg_gc_task:
            cpg_gc_task.cancel()
            with suppress(asyncio.CancelledError):
                await cpg_gc_task

        joern_server_manager = services.get('joern_server_manager')
        if joern_server_manager:
            for task_attr in ('_watchdog_task', '_reaper_task'):
                task = getattr(joern_server_manager, task_attr, None)
                if task:
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task

            logger.info("Terminating all Joern servers...")
            joern_server_manager.terminate_all_servers()
            logger.info("All Joern servers terminated")

        if 'port_manager' in services:
            logger.info("Releasing allocated ports...")
            try:
                services['port_manager'].release_all_ports()
            except Exception as e:
                logger.warning(f"Error releasing ports: {e}")

        if 'cpg_queue' in services:
            await services['cpg_queue'].stop()

        restart_tasks = services.get('restart_tasks', {})
        for task in restart_tasks.values():
            task.cancel()
        for task in restart_tasks.values():
            with suppress(asyncio.CancelledError):
                await task

        if 'db_manager' in services:
            logger.info("Flushing database...")
            try:
                services['db_manager'].close()
            except Exception as e:
                logger.warning(f"Error closing database: {e}")

        logger.info("Graceful shutdown completed")
    except Exception as e:
        logger.error(f"Error during graceful shutdown: {e}", exc_info=True)
    finally:
        services.clear()


def _check_joern_container_status(container_name: str | None = None, joern_manager=None) -> dict:
    """Inspect the Joern Docker container without raising on Docker issues."""
    container_name = container_name or services.get("joern_container_name") or os.getenv(
        "JOERN_CONTAINER_NAME", "codebadger-joern-server"
    )

    try:
        import docker

        docker_client = None
        if joern_manager is not None:
            docker_client = getattr(joern_manager, "docker_client", None)
        if docker_client is None:
            docker_client = docker.from_env()

        container = docker_client.containers.get(container_name)
        status = getattr(container, "status", "unknown")
        return {
            "container_name": container_name,
            "running": status == "running",
            "status": status,
        }
    except ImportError as e:
        return {
            "container_name": container_name,
            "running": False,
            "status": "docker_unavailable",
            "error": str(e),
        }
    except docker.errors.NotFound:
        return {
            "container_name": container_name,
            "running": False,
            "status": "not_found",
        }
    except docker.errors.DockerException as e:
        return {
            "container_name": container_name,
            "running": False,
            "status": "docker_unavailable",
            "error": str(e),
        }
    except Exception as e:
        return {
            "container_name": container_name,
            "running": False,
            "status": "error",
            "error": str(e),
        }


def _get_active_servers() -> dict:
    """Return the active Joern server map and count."""
    joern_manager = services.get("joern_server_manager")
    if not joern_manager:
        return {"count": 0, "servers": {}}

    try:
        servers = joern_manager.get_running_servers()
        return {"count": len(servers), "servers": servers}
    except Exception as e:
        return {"count": 0, "servers": {}, "error": str(e)}


def _get_port_utilization() -> dict:
    """Return current Joern port allocation counts."""
    port_manager = services.get("port_manager")
    if not port_manager:
        return {"allocated_count": 0, "available_count": 0}

    try:
        return {
            "allocated_count": len(port_manager.get_all_allocations()),
            "available_count": port_manager.available_count(),
        }
    except Exception as e:
        return {"allocated_count": 0, "available_count": 0, "error": str(e)}


def _get_cache_size() -> dict:
    """Return basic information about the CPG cache on disk."""
    project_root = os.path.dirname(os.path.abspath(__file__))
    cache_path = os.path.join(project_root, "playground", "cpgs")
    return {
        "cache_path": cache_path,
        "size_mb": _get_cpg_cache_mb(),
        "exists": os.path.exists(cache_path),
    }


def _check_exposure(config) -> list:
    """Flag a fail-open network-exposure posture as startup issue(s).

    The riskiest shipped combination is: the MCP bound to all interfaces
    (MCP_HOST=0.0.0.0), source_type='local' enabled (CHAT_DEPLOY=false), and no
    ALLOWED_SOURCE_ROOTS containment — anyone who can reach the port can ask the
    server to build a CPG from an arbitrary host path and read it back. The MCP
    has no built-in auth, so this must be a deliberate, fronted deployment. Warn
    loudly (and surface in /health) so it can't pass unnoticed.
    """
    issues: list = []
    host = getattr(config.server, "host", "127.0.0.1")
    chat_deploy = getattr(config.server, "chat_deploy", False)
    allowed_roots = os.getenv("ALLOWED_SOURCE_ROOTS", "").strip()
    on_all_interfaces = host in ("0.0.0.0", "::", "")

    if on_all_interfaces and not chat_deploy and not allowed_roots:
        issues.append(
            "INSECURE EXPOSURE: MCP is bound to all interfaces (MCP_HOST=%s) with "
            "source_type='local' enabled (CHAT_DEPLOY=false) and no "
            "ALLOWED_SOURCE_ROOTS — any client that reaches this port can read "
            "arbitrary host paths. Bind to 127.0.0.1, set CHAT_DEPLOY=true, set "
            "ALLOWED_SOURCE_ROOTS, and/or front the MCP with authenticated TLS."
            % host
        )
    elif on_all_interfaces:
        issues.append(
            "MCP is bound to all interfaces (MCP_HOST=%s) and has no built-in "
            "auth; ensure it is fronted by an authenticated proxy / firewalled."
            % host
        )
    return issues


@lifespan
async def app_lifespan(server: FastMCP):
    """Startup and shutdown logic for the FastMCP server"""
    global _server_start_time
    services.clear()
    _server_start_time = time.monotonic()

    config = load_config("config.yaml")
    setup_logging(
        config.server.log_level,
        log_dir=config.server.log_dir,
        log_to_file=config.server.log_to_file,
        log_max_bytes=config.server.log_max_bytes,
        log_backup_count=config.server.log_backup_count,
    )
    logger.info("Starting CodeBadger Server")

    # Print the memory-aware configuration envelope before the heavy service
    # init, flag drift that risks an OOM cascade, and auto-derive an unset Joern
    # memory budget from host RAM (before the Joern manager is constructed).
    apply_startup_tuning(config)

    # Setup OpenTelemetry (must happen before tool invocations)
    _setup_telemetry(config)

    os.makedirs(config.storage.workspace_root, exist_ok=True)

    project_root = os.path.dirname(os.path.abspath(__file__))
    playground_dir = os.path.join(project_root, "playground")
    cpgs_dir = os.path.join(playground_dir, "cpgs")
    codebases_dir = os.path.join(playground_dir, "codebases")

    os.makedirs(cpgs_dir, exist_ok=True)
    os.makedirs(codebases_dir, exist_ok=True)
    logger.info("Created required directories")

    try:
        # Postgres and Redis are the backing services (shared catalog/cache/
        # findings/jobs + cross-process coordination). Both default to the
        # docker-compose services; override via DATABASE_URL / REDIS_URL. An
        # unreachable Postgres or Redis fails the boot (fail-fast) so the
        # orchestrator restarts us instead of running half-degraded.
        database_url = resolve_database_url()
        redis_url = resolve_redis_url()
        try:
            # Size the connection pool to cover the build workers plus headroom
            # for concurrent catalog/cache reads from MCP tool threads and the
            # health/status probes. Override with DB_POOL_MAX_SIZE.
            db_pool_max = int(os.getenv("DB_POOL_MAX_SIZE", "0")) or max(
                10, config.cpg.build_workers + 8
            )
            db_manager = PostgresDBManager(database_url, max_pool_size=db_pool_max)
            db_manager.init_schema()
        except Exception as e:
            logger.error(
                f"Cannot reach Postgres at {database_url.split('@')[-1]}: {e}. "
                f"Start it with `docker compose up -d` or set DATABASE_URL."
            )
            raise
        logger.info(f"DB Manager initialized (postgres: {database_url.split('@')[-1]})")

        services['config'] = config
        services['db_manager'] = db_manager
        # The main server event loop. Sync MCP tools (e.g. get_cpg_status) run in
        # worker threads with no running loop, so they schedule background work
        # (Joern server restarts) onto this loop via run_coroutine_threadsafe.
        services['event_loop'] = asyncio.get_running_loop()
        services['startup_issues'] = []
        for _issue in _check_exposure(config):
            services['startup_issues'].append(_issue)
            logger.warning(_issue)
        services['codebase_tracker'] = CodebaseTracker(db_manager)
        services['git_manager'] = GitManager(config.storage.workspace_root)

        container_name = os.getenv("JOERN_CONTAINER_NAME", "codebadger-joern-server")
        services['joern_container_name'] = container_name

        joern_server_manager = None
        container_status = _check_joern_container_status(container_name)
        container_issue = _describe_joern_container_issue(container_status)

        if container_status.get("running"):
            try:
                joern_server_manager = JoernServerManager(
                    joern_binary_path=config.joern.binary_path,
                    container_name=container_name,
                    config=config,
                    codebase_tracker=services['codebase_tracker'],
                    max_active_servers=config.joern.max_active_servers,
                    redis_url=redis_url,
                )
                logger.info(f"Docker container '{container_name}' is running")
                logger.info(
                    "JoernServerManager built: worker_mode=%r docker_network=%r "
                    "(pool mode needs a non-empty docker_network when the MCP is containerized)",
                    joern_server_manager.worker_mode, joern_server_manager.docker_network,
                )
            except Exception as e:
                container_issue = f"Failed to initialize Joern server manager: {e}"
                services['startup_issues'].append(container_issue)
                logger.warning(container_issue)
        else:
            if container_issue:
                services['startup_issues'].append(container_issue)
                logger.warning(
                    f"{container_issue}. Joern-backed tools will be unavailable until Docker is ready."
                )

        services['joern_server_manager'] = joern_server_manager
        # Use the server manager's port_manager so health stats reflect actual allocations.
        # Fall back to a fresh instance only when the container is unavailable.
        services['port_manager'] = (
            joern_server_manager.port_manager
            if joern_server_manager
            else PortManager(port_min=config.joern.port_min, port_max=config.joern.port_max)
        )

        # Cross-process coordinator. Redis-backed so the per-CPG query lock holds
        # across multiple API worker processes. An unreachable Redis makes
        # make_coordinator raise → fail-fast boot.
        from src.services.coordination import make_coordinator
        try:
            qt = int(getattr(config.query, "timeout", 300))
        except (TypeError, ValueError):
            qt = 300
        query_lock_timeout = max(qt, 300) + 60
        try:
            coordinator = make_coordinator(redis_url, lock_timeout=query_lock_timeout)
        except Exception as e:
            logger.error(
                f"Cannot reach Redis at {redis_url.split('@')[-1]}: {e}. "
                f"Start it with `docker compose up -d` or set REDIS_URL."
            )
            raise
        services['coordinator'] = coordinator
        logger.info(f"Coordinator backend: {coordinator.backend}")

        services['query_executor'] = QueryExecutor(
            joern_server_manager,
            config=config.query,
            codebase_tracker=services['codebase_tracker'],
            coordinator=coordinator,
        )

        services['code_browsing_service'] = CodeBrowsingService(
            services['codebase_tracker'],
            services['query_executor'],
            services['db_manager']
        )

        # Start CPG generation queue. Cap pending jobs to 4× the worker count so a
        # runaway client can't fill disk by queueing unlimited generation requests.
        # "durable" backs the queue with the DB jobs table so a large batch
        # survives restarts and is never silently dropped; "memory" is the
        # in-process queue.
        queue_backend = getattr(config.cpg, "queue_backend", "memory")
        # Pending-job depth is independent of build concurrency: only build_workers
        # builds run at once (memory stays capped), this just sizes the waiting
        # room so a high-concurrency client isn't rejected with queue_full. <=0
        # falls back to the old build_workers*4 heuristic.
        queue_maxsize = getattr(config.cpg, "queue_maxsize", 0) or config.cpg.build_workers * 4
        if queue_backend == "durable":
            # db_manager (Postgres) provides the job-queue methods via
            # FOR UPDATE SKIP LOCKED, so it doubles as the job store.
            cpg_queue = DurableCPGQueue(
                db_manager, services,
                workers=config.cpg.build_workers,
                maxsize=queue_maxsize,
            )
            logger.info("Durable CPG queue using postgres job store")
        else:
            cpg_queue = CPGGenerationQueue(
                workers=config.cpg.build_workers,
                maxsize=queue_maxsize,
            )
        await cpg_queue.start()
        services['cpg_queue'] = cpg_queue
        logger.info(
            f"CPG generation queue started ({queue_backend} backend, "
            f"{config.cpg.build_workers} workers)"
        )

        register_tools(server, services)

        # Wire watchdog → shared restart registry BEFORE starting the watchdog so
        # every dead-server detection goes through _schedule_restart_server_task
        # and can't race a user-triggered restart on the same codebase.
        if joern_server_manager:
            joern_server_manager.set_restart_callback(
                lambda h, p: _schedule_restart_server_task(h, p, services)
            )
            joern_server_manager.start_watchdog()
            logger.info("Joern server watchdog started")
            joern_server_manager.start_reaper()

        interval = int(os.getenv("STATUS_LOG_INTERVAL_SECS", "60"))
        services['status_log_task'] = asyncio.create_task(_periodic_status_log(interval))

        # Cold-CPG GC: release allocations of CPGs gone cold (cpg.bin kept on disk;
        # reloads on next query). Disk deletion is opt-in (CPG_GC_DELETE_COLD).
        if config.cpg.gc_enabled:
            services['cpg_gc_task'] = asyncio.create_task(_cpg_gc_loop(services, config))

        logger.info("All services initialized")
        _log_effective_config(config)
        logger.info("CodeBadger Server is ready")

        yield services

    except Exception as e:
        logger.error(f"Error during server lifecycle: {e}", exc_info=True)
        raise
    finally:
        await _graceful_shutdown()
        logger.info("CodeBadger Server shutdown complete")


class ConcurrencyLimitMiddleware(BaseHTTPMiddleware):
    """Return 503 when too many MCP connections are active (B2)."""

    def __init__(self, app, max_concurrent: int = 8):
        super().__init__(app)
        self._sem = asyncio.Semaphore(max_concurrent)

    async def dispatch(self, request: Request, call_next):
        if self._sem.locked():
            return PlainTextResponse(
                "Server busy - too many concurrent requests",
                status_code=503,
                headers={"Retry-After": "5"},
            )
        async with self._sem:
            return await call_next(request)


_max_mcp = int(os.getenv("MAX_MCP_CONNECTIONS", str(defaults.MAX_MCP_CONNECTIONS)))
mcp = FastMCP(
    "CodeBadger Server",
    lifespan=app_lifespan,
)
# Tools are registered inside the lifespan (app_lifespan), not here.


def _uptime_seconds() -> float:
    return round(time.monotonic() - _server_start_time, 1) if _server_start_time else 0.0


def _get_cpg_cache_mb() -> float:
    try:
        project_root = os.path.dirname(os.path.abspath(__file__))
        cpgs_dir = os.path.join(project_root, "playground", "cpgs")
        total = 0
        for dirpath, _, filenames in os.walk(cpgs_dir):
            for f in filenames:
                try:
                    total += os.path.getsize(os.path.join(dirpath, f))
                except OSError:
                    pass
        return round(total / (1024 ** 2), 2)
    except Exception:
        return -1.0


def _get_codebase_list(include_sensitive: bool = False) -> list:
    try:
        tracker = services.get("codebase_tracker")
        joern_mgr = services.get("joern_server_manager")
        if not tracker:
            return []
        # One bulk query for all codebases, and ONE snapshot of running servers,
        # instead of a per-codebase DB query + port lookup. Under Postgres the old
        # per-codebase loop opened one connection per codebase on the event loop
        # (seconds of blocking at 1000s of codebases), stalling the whole server.
        infos = tracker.list_codebases_full()
        ports = {}
        if joern_mgr:
            try:
                ports = joern_mgr.get_running_servers()
            except Exception:
                ports = {}
        result = []
        for info in infos:
            result.append({
                "hash": info.codebase_hash,
                "language": info.language,
                "status": info.metadata.get("status", "unknown"),
                "joern_port": ports.get(info.codebase_hash),
                "source_type": info.source_type,
                "source": _format_codebase_source(
                    info.source_type,
                    info.source_path,
                    include_sensitive=include_sensitive,
                ),
            })
        return result
    except Exception:
        return []


async def _build_health(include_sensitive: bool = False) -> dict:
    """Collect dependency-aware health and return the structured response.

    Probes Postgres, Redis, Docker and the Joern pool concurrently with bounded
    timeouts, then rolls them into an up/partial/down status plus a
    `dependencies` map for the devops admin. DB-backed detail (codebase catalog,
    cache size) is only queried when Postgres is up, so a dead Postgres can't
    hang the endpoint.
    """
    joern_mgr = services.get("joern_server_manager")
    db_manager = services.get("db_manager")
    coordinator = services.get("coordinator")
    config = services.get("config")
    cpq = services.get("cpg_queue")
    project_root = os.path.dirname(os.path.abspath(__file__))
    database_url = resolve_database_url()
    redis_url = resolve_redis_url()

    # Probe the backing services concurrently and time-bounded so one hung
    # dependency can't stall the whole endpoint.
    pg_probe, redis_probe, container_info, memory_info = await asyncio.gather(
        _run_probe(db_manager.ping) if db_manager else _const({"ok": False, "error": "db_manager not initialized"}),
        _run_probe(coordinator.ping) if coordinator else _const({"ok": False, "error": "coordinator not initialized"}),
        _run_probe(lambda: _check_joern_container_status(services.get("joern_container_name"), joern_mgr)),
        _run_probe(joern_mgr.get_memory_stats) if joern_mgr else _const({}),
    )
    if not isinstance(memory_info, dict):
        memory_info = {}

    # --- Per-dependency status ---
    postgres_status = "up" if pg_probe.get("ok") else "down"
    redis_status = "up" if redis_probe.get("ok") else "down"

    # Docker is down only when the daemon itself is unreachable; not_found/exited
    # still mean the daemon answered (that's a Joern problem, not a Docker one).
    cstatus = container_info.get("status")
    docker_status = "down" if (container_info.get("ok") is False
                               or cstatus in ("docker_unavailable", "error")) else "up"

    port_usage = _get_port_utilization()
    port_info = {
        "allocated": port_usage.get("allocated_count", 0),
        "available": port_usage.get("available_count", 0),
    }
    mem_util = memory_info.get("utilization_pct")
    container_running = bool(container_info.get("running"))
    if joern_mgr is None or not container_running:
        joern_status = "down"
    elif port_info["available"] <= 0 or (isinstance(mem_util, (int, float)) and mem_util >= 95):
        joern_status = "partial"
    else:
        joern_status = "up"

    queue_info = {
        "depth": cpq.depth if cpq else 0,
        "in_flight": cpq.in_flight if cpq else 0,
        "maxsize": cpq.maxsize if cpq else 0,
        "full": cpq.is_full if cpq else False,
        "workers": config.cpg.build_workers if config else 0,
        "backend": getattr(config.cpg, "queue_backend", "memory") if config else "memory",
    }
    if cpq is None:
        cpg_queue_status = "down"
    elif queue_info["full"]:
        cpg_queue_status = "partial"
    else:
        cpg_queue_status = "up"

    dependencies = {
        "joern": joern_status,
        "postgres": postgres_status,
        "redis": redis_status,
        "docker": docker_status,
        "cpg_queue": cpg_queue_status,
    }
    overall = _aggregate_status(dependencies)

    # --- DB-backed detail (only when Postgres is up, so a dead DB can't hang) ---
    active_servers_info = _get_active_servers()
    active_servers = active_servers_info.get("servers", {})
    sleeping = 0
    codebases: list = []
    by_status: dict = {}
    cpg_cache_mb = -1.0
    if postgres_status == "up":
        codebases = _get_codebase_list(include_sensitive=include_sensitive)
        for cb in codebases:
            s = cb["status"]
            by_status[s] = by_status.get(s, 0) + 1
            if s == "sleeping":
                sleeping += 1
        cpg_cache_mb = _get_cache_size().get("size_mb", -1.0)

    can_accept_query = joern_status != "down" and postgres_status == "up" and redis_status == "up"
    can_accept_generation = can_accept_query and not queue_info["full"]

    # --- Operator-facing issues (human-readable supplements to the status) ---
    issues = list(services.get("startup_issues", []))
    container_issue = _describe_joern_container_issue(container_info)
    if container_issue and container_issue not in issues:
        issues.append(container_issue)
    if postgres_status == "down":
        issues.append(f"Postgres unreachable at {database_url.split('@')[-1]}: {pg_probe.get('error', 'unknown')}")
    if redis_status == "down":
        issues.append(f"Redis unreachable at {redis_url.split('@')[-1]}: {redis_probe.get('error', 'unknown')}")
    if _get_system_memory_available_gb() < 1.0:
        issues.append("System memory critically low (<1 GB available)")
    if isinstance(mem_util, (int, float)) and mem_util >= 95:
        issues.append(f"Joern memory budget nearly exhausted ({mem_util}% reserved)")
    if port_info["available"] <= 0 and joern_mgr is not None:
        issues.append("Joern port pool exhausted")
    if queue_info["full"]:
        issues.append("CPG generation queue is full — new generate_cpg calls will be rejected")

    uptime = _uptime_seconds()
    health = {
        "status": overall,
        "mcp": "codebadger",
        "version": VERSION,
        "uptime": {
            "seconds": uptime,
            "human": _format_uptime(uptime),
        },
        "dependencies": dependencies,
        "capacity": {
            "accept_query": can_accept_query,
            "accept_generation": can_accept_generation,
        },
        "checks": {
            "joern": {
                "status": joern_status,
                "container": container_info,
                "servers": {
                    "worker_mode": joern_mgr.worker_mode if joern_mgr else "shared",
                    "admission": memory_info.get("mode", "count"),
                    "active": len(active_servers),
                    "sleeping": sleeping,
                    "count_cap": joern_mgr._max_active if joern_mgr else 0,
                    "lru_evictions": joern_mgr._lru_eviction_count if joern_mgr else 0,
                    "port_pool": port_info,
                },
                "memory": memory_info,
            },
            "postgres": {
                "status": postgres_status,
                "target": database_url.split("@")[-1],
                **{k: v for k, v in pg_probe.items() if k in ("latency_ms", "error")},
            },
            "redis": {
                "status": redis_status,
                "target": redis_url.split("@")[-1],
                "backend": getattr(coordinator, "backend", "unknown") if coordinator else "none",
                **{k: v for k, v in redis_probe.items() if k in ("latency_ms", "error")},
            },
            "docker": {
                "status": docker_status,
                "container_name": container_info.get("container_name"),
                "container_status": cstatus,
            },
            "cpg_queue": {"status": cpg_queue_status, **queue_info},
        },
        "codebases": {
            "total": len(codebases),
            "by_status": by_status,
        },
        "resources": {
            "process_memory_mb": _get_process_memory_mb(),
            "system_memory_available_gb": _get_system_memory_available_gb(),
            "disk": _get_disk_usage(project_root),
            "cpg_cache_mb": cpg_cache_mb,
        },
        "issues": issues,
    }
    if include_sensitive:
        health["codebases"]["list"] = codebases
    return health


async def _periodic_status_log(interval_secs: int) -> None:
    """Log a compact server status block every interval_secs seconds."""
    while True:
        await asyncio.sleep(interval_secs)
        try:
            h = await _build_health(include_sensitive=True)
            joern = h['checks']['joern']
            srv = joern['servers']
            mem = joern['memory']
            q = h['checks']['cpg_queue']
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            sep = "=" * 60
            deps = "  ".join(f"{k}={v}" for k, v in h['dependencies'].items())
            lines = [
                sep,
                f"CodeBadger Status  [{now}]  uptime {h['uptime']['human']}",
                sep,
                f"Status : {h['status'].upper()}" + (f"  issues={h['issues']}" if h['issues'] else ""),
                f"Deps   : {deps}",
                f"Memory : process={h['resources']['process_memory_mb']} MB  "
                f"system_avail={h['resources']['system_memory_available_gb']} GB",
                f"Joern  : mode={srv['worker_mode']}  "
                f"active={srv['active']}  "
                f"sleeping={srv['sleeping']}  "
                f"count_cap={srv['count_cap']}  "
                f"evictions={srv['lru_evictions']}  "
                f"ports={srv['port_pool']['available']} free",
                f"Budget : {mem.get('reserved_mb', 0)}/"
                f"{mem.get('budget_mb', 0)} MB reserved"
                + (f" ({mem.get('utilization_pct')}%)"
                   if mem.get('utilization_pct') is not None else "")
                + f"  rss={mem.get('container_rss_mb', '?')} MB",
                f"Queue  : depth={q['depth']}  "
                f"in_flight={q['in_flight']}  "
                f"max={q['maxsize']}  "
                f"workers={q['workers']}",
                f"CPGs   : {h['codebases']['total']} registered  "
                + "  ".join(f"{k}={v}" for k, v in h['codebases']['by_status'].items()),
            ]
            # Only list ACTIVE servers (those with a port) — listing every
            # registered codebase floods the log with thousands of lines per tick.
            active = [cb for cb in h['codebases'].get('list', []) if cb['joern_port']]
            for cb in active:
                src = cb['source']
                if len(src) > 40:
                    src = "..." + src[-37:]
                lines.append(
                    f"  {cb['hash']:<12}  {cb['language']:<10}  {cb['status']:<10}  :{cb['joern_port']:<6}  {src}"
                )
            if not active:
                lines.append("  (no active Joern servers)")
            lines.append(sep)
            for line in lines:
                logger.info(line)
        except Exception as e:
            logger.warning(f"Periodic status log failed: {e}")


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    """Dependency-aware health check. status ∈ {up, partial, down}.

    HTTP 200 for up/partial (the server is still serving), 503 for down so an
    orchestrator/load-balancer takes the instance out of rotation.
    """
    try:
        h = await _build_health()
        status_code = 503 if h["status"] == "down" else 200
        return JSONResponse(h, status_code=status_code)
    except Exception as e:
        logger.error(f"Error in health check: {e}", exc_info=True)
        return JSONResponse({
            "status": "down",
            "mcp": "codebadger",
            "version": VERSION,
            "error": str(e),
        }, status_code=500)


@mcp.custom_route("/", methods=["GET"])
async def root(request):
    """Root endpoint providing basic server information"""
    return JSONResponse({
        "service": "codebadger",
        "description": "CodeBadger for static code analysis using Code Property Graph technology",
        "version": VERSION,
        "endpoints": {
            "health": "/health",
            "mcp": "/mcp"
        }
    })


if __name__ == "__main__":
    config_data = load_config("config.yaml")
    host = config_data.server.host
    port = config_data.server.port

    logger.info(f"Starting CodeBadger Server with HTTP transport on {host}:{port}")

    _http_middleware = [Middleware(ConcurrencyLimitMiddleware, max_concurrent=_max_mcp)]
    asyncio.run(mcp.run_http_async(host=host, port=port, middleware=_http_middleware))