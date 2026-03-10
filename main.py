#!/usr/bin/env python3
"""
CodeBadger Server - Main entry point using FastMCP

This is the main entry point for the CodeBadger Server that provides static code analysis
capabilities through the Model Context Protocol (MCP) using Joern's Code Property Graph.
"""

import asyncio
import logging
import os
import signal
import shutil
import socket
from fastmcp import FastMCP
from fastmcp.server.lifespan import lifespan
from starlette.responses import JSONResponse

from src.config import load_config
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
shutdown_event = asyncio.Event()

logger = logging.getLogger(__name__)


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


def _setup_signal_handlers(mcp: FastMCP):
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        asyncio.create_task(_graceful_shutdown())

    # Register handlers for SIGTERM and SIGINT
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    logger.debug("Signal handlers registered for SIGTERM and SIGINT")


@lifespan
async def app_lifespan(server: FastMCP):
    """Startup and shutdown logic for the FastMCP server"""
    # Load configuration
    config = load_config("config.yaml")
    setup_logging(config.server.log_level)
    logger.info("Starting CodeBadger Server")

    # Setup signal handlers for graceful shutdown
    _setup_signal_handlers(server)

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
        services['joern_server_manager'] = JoernServerManager(
            joern_binary_path=config.joern.binary_path,
            container_name=os.getenv("JOERN_CONTAINER_NAME", "codebadger-joern-server"),
            config=config
        )

        # Initialize CPG generator (runs Joern CLI directly in container)
        services['cpg_generator'] = CPGGenerator(config=config, joern_server_manager=services['joern_server_manager'])
        # Skip initialize() - no Docker needed

        # Initialize query executor with Joern server manager
        services['query_executor'] = QueryExecutor(services['joern_server_manager'], config=config.query)

        # Initialize Code Browsing Service
        services['code_browsing_service'] = CodeBrowsingService(
            services['codebase_tracker'],
            services['query_executor'],
            services['db_manager']
        )

        # Register MCP tools now that services are initialized
        register_tools(server, services)

        logger.info("All services initialized")
        logger.info("CodeBadger Server is ready")

        yield services

    except Exception as e:
        logger.error(f"Error during server lifecycle: {e}", exc_info=True)
        raise
    finally:
        await _graceful_shutdown()
        logger.info("CodeBadger Server shutdown complete")


# Initialize FastMCP server
mcp = FastMCP(
    "CodeBadger Server",
    lifespan=app_lifespan
)

# Note: Tools are registered inside the lifespan function
# register_tools(mcp, services)


def _get_disk_usage(path: str) -> dict:
    """Get disk usage information for a path"""
    try:
        stat = shutil.disk_usage(path)
        return {
            "total_gb": round(stat.total / (1024**3), 2),
            "used_gb": round(stat.used / (1024**3), 2),
            "free_gb": round(stat.free / (1024**3), 2),
            "percent_used": round((stat.used / stat.total) * 100, 2) if stat.total > 0 else 0
        }
    except Exception as e:
        logger.debug(f"Error getting disk usage for {path}: {e}")
        return {"error": str(e)}


def _get_cache_size() -> dict:
    """Get cache directory size"""
    try:
        project_root = os.path.dirname(os.path.abspath(__file__))
        cpgs_dir = os.path.join(project_root, "playground", "cpgs")

        total_size = 0
        if os.path.exists(cpgs_dir):
            for dirpath, dirnames, filenames in os.walk(cpgs_dir):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except Exception as e:
                        logger.debug(f"Error getting size of {filepath}: {e}")

        return {
            "cache_path": cpgs_dir,
            "size_mb": round(total_size / (1024**2), 2),
            "exists": os.path.exists(cpgs_dir)
        }
    except Exception as e:
        logger.debug(f"Error calculating cache size: {e}")
        return {"error": str(e)}


def _check_joern_container_status() -> dict:
    """Check Joern Docker container status"""
    try:
        if 'joern_server_manager' not in services:
            return {"error": "Joern server manager not initialized"}

        joern_mgr = services['joern_server_manager']
        try:
            container = joern_mgr.docker_client.containers.get(joern_mgr.container_name)
            return {
                "container_name": joern_mgr.container_name,
                "status": container.status,
                "running": container.status == "running"
            }
        except Exception as e:
            logger.debug(f"Error checking container status: {e}")
            return {
                "container_name": joern_mgr.container_name,
                "status": "not_found",
                "running": False,
                "error": str(e)
            }
    except Exception as e:
        logger.debug(f"Error in Joern container status check: {e}")
        return {"error": str(e)}


def _get_active_servers() -> dict:
    """Get information about active Joern servers"""
    try:
        if 'joern_server_manager' not in services:
            return {"error": "Joern server manager not initialized", "count": 0}

        joern_mgr = services['joern_server_manager']
        running_servers = joern_mgr.get_running_servers()

        servers = {}
        for codebase_hash, port in running_servers.items():
            # Check port connectivity
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                sock.close()
                is_accessible = result == 0
            except Exception:
                is_accessible = False

            servers[codebase_hash] = {
                "port": port,
                "accessible": is_accessible
            }

        return {
            "count": len(servers),
            "servers": servers
        }
    except Exception as e:
        logger.debug(f"Error getting active servers: {e}")
        return {"error": str(e), "count": 0}


def _get_port_utilization() -> dict:
    """Get port manager utilization information"""
    try:
        if 'port_manager' not in services:
            return {"error": "Port manager not initialized"}

        port_mgr = services['port_manager']
        allocations = port_mgr.get_all_allocations()
        allocated_count = len(allocations)
        available_count = port_mgr.available_count()

        return {
            "allocated_count": allocated_count,
            "available_count": available_count,
            "total_pool_size": allocated_count + available_count,
            "utilization_percent": round((allocated_count / (allocated_count + available_count) * 100)) if (allocated_count + available_count) > 0 else 0
        }
    except Exception as e:
        logger.debug(f"Error getting port utilization: {e}")
        return {"error": str(e)}


# Health check endpoint
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    """Health check endpoint for monitoring server status"""
    try:
        project_root = os.path.dirname(os.path.abspath(__file__))

        health_status = {
            "status": "healthy",
            "service": "codebadger",
            "version": VERSION,
            "joern_container": _check_joern_container_status(),
            "active_servers": _get_active_servers(),
            "port_utilization": _get_port_utilization(),
            "disk_usage": _get_disk_usage(project_root),
            "cache_info": _get_cache_size()
        }

        # Determine overall health status
        container_status = health_status["joern_container"]
        if "error" in container_status or not container_status.get("running", False):
            health_status["status"] = "degraded"

        return JSONResponse(health_status)
    except Exception as e:
        logger.error(f"Error in health check: {e}", exc_info=True)
        return JSONResponse({
            "status": "unhealthy",
            "service": "codebadger",
            "version": VERSION,
            "error": str(e)
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
    # Run the server with HTTP transport (Streamable HTTP)
    # Get configuration
    config_data = load_config("config.yaml")
    host = config_data.server.host
    port = config_data.server.port
    
    logger.info(f"Starting CodeBadger Server with HTTP transport on {host}:{port}")
    
    # Use HTTP transport (Streamable HTTP) for production deployment
    # This enables network accessibility, multiple concurrent clients,
    # and integration with web infrastructure
    mcp.run(transport="http", host=host, port=port)