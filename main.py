#!/usr/bin/env python3
"""
CodeBadger Server - Main entry point using FastMCP

This is the main entry point for the CodeBadger Server that provides static code analysis
capabilities through the Model Context Protocol (MCP) using Joern's Code Property Graph.
"""

import asyncio
import logging
import os
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
from src.tools.core_tools import CPGGenerationQueue
from src.services import (
    CodebaseTracker,
    GitManager,
    CPGGenerator,
    JoernServerManager,
    PortManager,
    QueryExecutor,
    CodeBrowsingService
)
from src.utils import DBManager, setup_logging
from src.tools import register_tools

# Version information - bump this when releasing new versions
VERSION = "0.3.4-beta"

# Global service instances
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


async def _graceful_shutdown():
    """Gracefully shutdown all services"""
    logger.info("Performing graceful shutdown...")

    try:
        status_log_task = services.get('status_log_task')
        if status_log_task:
            status_log_task.cancel()
            with suppress(asyncio.CancelledError):
                await status_log_task

        # Terminate all Joern servers
        joern_server_manager = services.get('joern_server_manager')
        if joern_server_manager:
            watchdog_task = getattr(joern_server_manager, '_watchdog_task', None)
            if watchdog_task:
                watchdog_task.cancel()
                with suppress(asyncio.CancelledError):
                    await watchdog_task

            logger.info("Terminating all Joern servers...")
            joern_server_manager.terminate_all_servers()
            logger.info("All Joern servers terminated")

        # Release all ports
        if 'port_manager' in services:
            logger.info("Releasing allocated ports...")
            try:
                services['port_manager'].release_all_ports()
            except Exception as e:
                logger.warning(f"Error releasing ports: {e}")

        # Stop CPG generation queue
        if 'cpg_queue' in services:
            await services['cpg_queue'].stop()

        restart_tasks = services.get('restart_tasks', {})
        for task in restart_tasks.values():
            task.cancel()
        for task in restart_tasks.values():
            with suppress(asyncio.CancelledError):
                await task

        # Flush database and caches
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


def _describe_joern_container_issue(container_info: dict) -> str | None:
    """Return a user-facing issue string for the current Joern container state."""
    status = container_info.get("status")
    container_name = container_info.get("container_name", "codebadger-joern-server")

    if status == "running":
        return None
    if status == "not_found":
        return f"Joern Docker container '{container_name}' not found"
    if status == "docker_unavailable":
        return f"Cannot connect to Docker daemon: {container_info.get('error', 'Docker unavailable')}"
    if status == "error":
        return f"Failed to inspect Joern Docker container '{container_name}': {container_info.get('error', 'unknown error')}"
    return f"Joern Docker container '{container_name}' is not running"


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


@lifespan
async def app_lifespan(server: FastMCP):
    """Startup and shutdown logic for the FastMCP server"""
    global _server_start_time
    services.clear()
    _server_start_time = time.monotonic()

    # Load configuration
    config = load_config("config.yaml")
    setup_logging(config.server.log_level)
    logger.info("Starting CodeBadger Server")

    # Setup OpenTelemetry (must happen before tool invocations)
    _setup_telemetry(config)

    # Ensure required directories exist
    os.makedirs(config.storage.workspace_root, exist_ok=True)

    # Create playground directory relative to project root
    project_root = os.path.dirname(os.path.abspath(__file__))
    playground_dir = os.path.join(project_root, "playground")
    cpgs_dir = os.path.join(playground_dir, "cpgs")
    codebases_dir = os.path.join(playground_dir, "codebases")

    os.makedirs(cpgs_dir, exist_ok=True)
    os.makedirs(codebases_dir, exist_ok=True)
    logger.info("Created required directories")

    try:
        # Initialize DB Manager
        db_manager = DBManager(os.path.join(project_root, "codebadger.db"))

        logger.info("DB Manager initialized")

        # Initialize services
        services['config'] = config
        services['db_manager'] = db_manager
        services['startup_issues'] = []
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
                )
                logger.info(f"Docker container '{container_name}' is running")
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

        # Initialize CPG generator (runs Joern CLI directly in container)
        services['cpg_generator'] = CPGGenerator(config=config, joern_server_manager=joern_server_manager)
        # Skip initialize() - no Docker needed

        # Initialize query executor with Joern server manager
        services['query_executor'] = QueryExecutor(
            joern_server_manager,
            config=config.query,
            codebase_tracker=services['codebase_tracker'],
        )

        # Initialize Code Browsing Service
        services['code_browsing_service'] = CodeBrowsingService(
            services['codebase_tracker'],
            services['query_executor'],
            services['db_manager']
        )

        # Start CPG generation queue (B3). Cap pending jobs to 4× the worker count
        # so a runaway client can't fill disk by queueing unlimited generation requests.
        cpg_queue = CPGGenerationQueue(
            workers=config.cpg.build_workers,
            maxsize=config.cpg.build_workers * 4,
        )
        await cpg_queue.start()
        services['cpg_queue'] = cpg_queue
        logger.info(f"CPG generation queue started with {config.cpg.build_workers} workers")

        # Register MCP tools now that services are initialized
        register_tools(server, services)

        # Start Joern watchdog (C1) — must run after tools are registered
        if joern_server_manager:
            joern_server_manager.start_watchdog()
            logger.info("Joern server watchdog started")

        # Periodic status logger
        interval = int(os.getenv("STATUS_LOG_INTERVAL_SECS", "60"))
        services['status_log_task'] = asyncio.create_task(_periodic_status_log(interval))

        logger.info("All services initialized")
        logger.info("CodeBadger Server is ready")

        yield services

    except Exception as e:
        logger.error(f"Error during server lifecycle: {e}", exc_info=True)
        raise
    finally:
        await _graceful_shutdown()
        logger.info("CodeBadger Server shutdown complete")


def _apply_transforms(server) -> None:
    """Apply CodeMode transform after all tools are registered.

    CodeMode replaces the full 34-tool catalog with three lightweight
    discovery tools + one execute tool, so the LLM only loads schemas
    for the tools it actually needs:

        ListTools   — enumerate every available tool by name (one-shot)
        Search      — natural-language search across tool descriptions
        GetSchemas  — fetch full parameter schemas for selected tools
        execute     — run a Python script that chains call_tool() calls
                      in a sandbox, eliminating sequential round-trips
    """
    from fastmcp.experimental.transforms.code_mode import (
        CodeMode, ListTools, Search, GetSchemas,
    )
    server.add_transform(CodeMode(
        discovery_tools=[ListTools(), Search(), GetSchemas()],
    ))
    logger.info("Transform: CodeMode enabled (ListTools + Search + GetSchemas)")


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


# Initialize FastMCP server
_max_mcp = int(os.getenv("MAX_MCP_CONNECTIONS", str(defaults.MAX_MCP_CONNECTIONS)))
mcp = FastMCP(
    "CodeBadger Server",
    lifespan=app_lifespan,
)
# Note: Tools are registered inside the lifespan function
# register_tools(mcp, services)
# TODO: _apply_transforms is experimental — call it manually to enable CodeMode


def _uptime_seconds() -> float:
    return round(time.monotonic() - _server_start_time, 1) if _server_start_time else 0.0


def _format_uptime(seconds: float) -> str:
    s = int(seconds)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    minutes, s = divmod(s, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def _get_process_memory_mb() -> float:
    try:
        import psutil
        return round(psutil.Process().memory_info().rss / (1024 ** 2), 1)
    except ImportError:
        pass
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    kb = int(line.split()[1])
                    return round(kb / 1024, 1)
    except Exception:
        pass
    return -1.0


def _get_system_memory_available_gb() -> float:
    try:
        import psutil
        return round(psutil.virtual_memory().available / (1024 ** 3), 2)
    except ImportError:
        pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    return round(kb / (1024 ** 2), 2)
    except Exception:
        pass
    return -1.0


def _get_disk_usage(path: str) -> dict:
    try:
        stat = shutil.disk_usage(path)
        return {
            "total_gb": round(stat.total / (1024 ** 3), 2),
            "used_gb": round(stat.used / (1024 ** 3), 2),
            "free_gb": round(stat.free / (1024 ** 3), 2),
            "percent_used": round((stat.used / stat.total) * 100, 1) if stat.total > 0 else 0,
        }
    except Exception as e:
        return {"error": str(e)}


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


def _format_codebase_source(source_type: str, source_path: str, include_sensitive: bool = False) -> str:
    """Format a codebase source for operator output.

    Health responses default to redacted values so repository locations are not
    exposed. Internal status logs can opt into the original source path.
    """
    if include_sensitive:
        return source_path
    return f"<redacted:{source_type or 'unknown'}>"


def _get_codebase_list(include_sensitive: bool = False) -> list:
    try:
        tracker = services.get("codebase_tracker")
        joern_mgr = services.get("joern_server_manager")
        if not tracker:
            return []
        result = []
        for h in tracker.list_codebases():
            info = tracker.get_codebase(h)
            if not info:
                continue
            status = info.metadata.get("status", "unknown")
            port = joern_mgr.get_server_port(h) if joern_mgr else None
            result.append({
                "hash": h,
                "language": info.language,
                "status": status,
                "joern_port": port,
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


def _build_health(include_sensitive: bool = False) -> dict:
    """Collect all health metrics and return a structured dict."""
    joern_mgr = services.get("joern_server_manager")
    project_root = os.path.dirname(os.path.abspath(__file__))

    # Joern container
    container_info = _check_joern_container_status(services.get("joern_container_name"), joern_mgr)

    # Joern server pool
    active_servers_info = _get_active_servers()
    active_servers = active_servers_info.get("servers", {})

    # Sleeping count
    sleeping = 0
    codebases = _get_codebase_list(include_sensitive=include_sensitive)
    by_status: dict = {}
    for cb in codebases:
        s = cb["status"]
        by_status[s] = by_status.get(s, 0) + 1
        if s == "sleeping":
            sleeping += 1

    # Port pool
    port_usage = _get_port_utilization()
    port_info = {
        "allocated": port_usage.get("allocated_count", 0),
        "available": port_usage.get("available_count", 0),
    }

    # CPG queue
    cpq = services.get("cpg_queue")
    config = services.get("config")
    cache_info = _get_cache_size()

    issues = list(services.get("startup_issues", []))
    container_issue = _describe_joern_container_issue(container_info)
    if container_issue and container_issue not in issues:
        issues.append(container_issue)
    if _get_system_memory_available_gb() < 1.0:
        issues.append("System memory critically low (<1 GB available)")

    uptime = _uptime_seconds()
    return {
        "status": "unhealthy" if container_issue else ("degraded" if issues else "healthy"),
        "issues": issues,
        "service": "codebadger",
        "version": VERSION,
        "uptime": {
            "seconds": uptime,
            "human": _format_uptime(uptime),
        },
        "joern": {
            "container": container_info,
            "servers": {
                "active": len(active_servers),
                "sleeping": sleeping,
                "max_allowed": joern_mgr._max_active if joern_mgr else 0,
                "lru_evictions": joern_mgr._lru_eviction_count if joern_mgr else 0,
                "port_pool": port_info,
            },
        },
        "cpg_queue": {
            "depth": cpq.depth if cpq else 0,
            "workers": config.cpg.build_workers if config else 0,
        },
        "codebases": {
            "total": len(codebases),
            "by_status": by_status,
            "list": codebases,
        },
        "resources": {
            "process_memory_mb": _get_process_memory_mb(),
            "system_memory_available_gb": _get_system_memory_available_gb(),
            "disk": _get_disk_usage(project_root),
            "cpg_cache_mb": cache_info.get("size_mb", -1.0),
        },
    }


async def _periodic_status_log(interval_secs: int) -> None:
    """Log a compact server status block every interval_secs seconds."""
    while True:
        await asyncio.sleep(interval_secs)
        try:
            h = _build_health(include_sensitive=True)
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            sep = "=" * 60
            lines = [
                sep,
                f"CodeBadger Status  [{now}]  uptime {h['uptime']['human']}",
                sep,
                f"Status : {h['status'].upper()}" + (f"  issues={h['issues']}" if h['issues'] else ""),
                f"Memory : process={h['resources']['process_memory_mb']} MB  "
                f"system_avail={h['resources']['system_memory_available_gb']} GB",
                f"Joern  : active={h['joern']['servers']['active']}  "
                f"sleeping={h['joern']['servers']['sleeping']}  "
                f"max={h['joern']['servers']['max_allowed']}  "
                f"evictions={h['joern']['servers']['lru_evictions']}",
                f"Queue  : depth={h['cpg_queue']['depth']}  "
                f"workers={h['cpg_queue']['workers']}",
                f"CPGs   : {h['codebases']['total']} registered  "
                + "  ".join(f"{k}={v}" for k, v in h['codebases']['by_status'].items()),
            ]
            for cb in h['codebases']['list']:
                port_str = f":{cb['joern_port']}" if cb['joern_port'] else "      "
                src = cb['source']
                if len(src) > 40:
                    src = "..." + src[-37:]
                lines.append(
                    f"  {cb['hash']:<12}  {cb['language']:<10}  {cb['status']:<10}  {port_str:<7}  {src}"
                )
            lines.append(sep)
            for line in lines:
                logger.info(line)
        except Exception as e:
            logger.warning(f"Periodic status log failed: {e}")


# Health check endpoint
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    """Health check endpoint"""
    try:
        h = _build_health()
        status_code = 200 if h["status"] != "unhealthy" else 503
        return JSONResponse(h, status_code=status_code)
    except Exception as e:
        logger.error(f"Error in health check: {e}", exc_info=True)
        return JSONResponse({
            "status": "unhealthy",
            "service": "codebadger",
            "version": VERSION,
            "error": str(e),
        }, status_code=500)


# Root endpoint
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