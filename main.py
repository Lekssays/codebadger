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
from datetime import datetime, timezone
from fastmcp import FastMCP
from fastmcp.server.lifespan import lifespan
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

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
        # Terminate all Joern servers
        if 'joern_server_manager' in services:
            logger.info("Terminating all Joern servers...")
            services['joern_server_manager'].terminate_all_servers()
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


@lifespan
async def app_lifespan(server: FastMCP):
    """Startup and shutdown logic for the FastMCP server"""
    global _server_start_time
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
        services['codebase_tracker'] = CodebaseTracker(db_manager)
        services['git_manager'] = GitManager(config.storage.workspace_root)

        # Initialize port manager for Joern servers
        services['port_manager'] = PortManager(
            port_min=config.joern.port_min,
            port_max=config.joern.port_max
        )

        # Initialize Joern server manager (runs servers inside Docker container)
        container_name = os.getenv("JOERN_CONTAINER_NAME", "codebadger-joern-server")
        services['joern_server_manager'] = JoernServerManager(
            joern_binary_path=config.joern.binary_path,
            container_name=container_name,
            config=config,
            codebase_tracker=services['codebase_tracker'],
            max_active_servers=config.joern.max_active_servers,
        )

        # Verify the Docker container is running before proceeding
        try:
            import docker
            docker_client = docker.from_env()
            container = docker_client.containers.get(container_name)
            if container.status != "running":
                logger.error(
                    f"Docker container '{container_name}' exists but is not running "
                    f"(status: {container.status}). Please start it with: docker compose up -d"
                )
                raise RuntimeError(
                    f"Docker container '{container_name}' is not running. "
                    f"Run 'docker compose up -d' first."
                )
            logger.info(f"Docker container '{container_name}' is running")
        except docker.errors.NotFound:
            logger.error(
                f"Docker container '{container_name}' not found. "
                f"Please start it with: docker compose up -d"
            )
            raise RuntimeError(
                f"Docker container '{container_name}' not found. "
                f"Run 'docker compose up -d' first."
            )
        except docker.errors.DockerException as e:
            logger.error(f"Cannot connect to Docker daemon: {e}")
            raise RuntimeError(
                f"Cannot connect to Docker daemon. Is Docker running? Error: {e}"
            )

        # Initialize CPG generator (runs Joern CLI directly in container)
        services['cpg_generator'] = CPGGenerator(config=config, joern_server_manager=services['joern_server_manager'])
        # Skip initialize() - no Docker needed

        # Initialize query executor with Joern server manager
        services['query_executor'] = QueryExecutor(
            services['joern_server_manager'],
            config=config.query,
            codebase_tracker=services['codebase_tracker'],
        )

        # Initialize Code Browsing Service
        services['code_browsing_service'] = CodeBrowsingService(
            services['codebase_tracker'],
            services['query_executor'],
            services['db_manager']
        )

        # Start CPG generation queue (B3)
        cpg_queue = CPGGenerationQueue(workers=config.cpg.build_workers)
        await cpg_queue.start()
        services['cpg_queue'] = cpg_queue
        logger.info(f"CPG generation queue started with {config.cpg.build_workers} workers")

        # Register MCP tools now that services are initialized
        register_tools(server, services)

        # Start Joern watchdog (C1) — must run after tools are registered
        services['joern_server_manager'].start_watchdog()
        logger.info("Joern server watchdog started")

        # Periodic status logger
        interval = int(os.getenv("STATUS_LOG_INTERVAL_SECS", "60"))
        asyncio.create_task(_periodic_status_log(interval))

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
        if self._sem._value == 0:
            return Response(
                "Server busy — too many concurrent requests",
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
# _apply_transforms is called only in __main__ so tests use direct tool access


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


def _get_codebase_list() -> list:
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
                "source": info.source_path,
            })
        return result
    except Exception:
        return []


def _build_health() -> dict:
    """Collect all health metrics and return a structured dict."""
    joern_mgr = services.get("joern_server_manager")
    project_root = os.path.dirname(os.path.abspath(__file__))

    # Joern container
    container_info: dict = {}
    try:
        if joern_mgr:
            container = joern_mgr.docker_client.containers.get(joern_mgr.container_name)
            container_info = {"running": container.status == "running", "status": container.status}
        else:
            container_info = {"running": False, "status": "no_manager"}
    except Exception as e:
        container_info = {"running": False, "status": "not_found", "error": str(e)}

    # Joern server pool
    active_servers: dict = {}
    if joern_mgr:
        for h, p in joern_mgr.get_running_servers().items():
            active_servers[h] = p

    # Sleeping count
    sleeping = 0
    codebases = _get_codebase_list()
    by_status: dict = {}
    for cb in codebases:
        s = cb["status"]
        by_status[s] = by_status.get(s, 0) + 1
        if s == "sleeping":
            sleeping += 1

    # Port pool
    port_info: dict = {}
    if "port_manager" in services:
        pm = services["port_manager"]
        alloc = len(pm.get_all_allocations())
        avail = pm.available_count()
        port_info = {"allocated": alloc, "available": avail}

    # CPG queue
    cpq = services.get("cpg_queue")
    config = services.get("config")

    issues = []
    if not container_info.get("running"):
        issues.append("Joern Docker container is not running")
    if _get_system_memory_available_gb() < 1.0:
        issues.append("System memory critically low (<1 GB available)")

    uptime = _uptime_seconds()
    return {
        "status": "unhealthy" if any("not running" in i for i in issues) else ("degraded" if issues else "healthy"),
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
            "cpg_cache_mb": _get_cpg_cache_mb(),
        },
    }


async def _periodic_status_log(interval_secs: int) -> None:
    """Log a compact server status block every interval_secs seconds."""
    while True:
        await asyncio.sleep(interval_secs)
        try:
            h = _build_health()
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

    _apply_transforms(mcp)
    _http_middleware = [Middleware(ConcurrencyLimitMiddleware, max_concurrent=_max_mcp)]
    asyncio.run(mcp.run_http_async(host=host, port=port, middleware=_http_middleware))