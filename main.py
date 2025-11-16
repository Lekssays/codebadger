#!/usr/bin/env python3
"""
CodeBadger Toolkit Server - Main entry point using FastMCP

This is the main entry point for the CodeBadger Toolkit Server that provides static code analysis
capabilities through the Model Context Protocol (MCP) using Joern's Code Property Graph.
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastmcp import FastMCP
from starlette.responses import JSONResponse

from src.config import load_config
from src.services import (
    CodebaseTracker,
    GitManager,
    CPGGenerator,
    JoernServerClient,
    JoernServerManager,
    PortManager,
    QueryExecutor
)
from src.utils import RedisClient, SyncRedisClient, setup_logging
from src.tools import register_tools

# Version information - bump this when releasing new versions
VERSION = "0.3.0-beta"

# Global service instances
services = {}

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(mcp: FastMCP):
    """Startup and shutdown logic for the FastMCP server"""
    # Load configuration
    config = load_config("config.yaml")
    setup_logging(config.server.log_level)
    logger.info("Starting CodeBadger Toolkit Server")
    
    # Ensure required directories exist
    import os
    os.makedirs(config.storage.workspace_root, exist_ok=True)
    os.makedirs("playground/cpgs", exist_ok=True)
    logger.info("Created required directories")
    
    try:
        # Initialize Redis clients
        redis_client = RedisClient(config.redis)
        await redis_client.connect()
        
        sync_redis_client = SyncRedisClient(config.redis)
        sync_redis_client.connect()
        
        logger.info("Redis clients connected")
        
        # Initialize services
        services['config'] = config
        services['redis'] = redis_client
        services['sync_redis'] = sync_redis_client
        services['codebase_tracker'] = CodebaseTracker(sync_redis_client)
        services['git_manager'] = GitManager(config.storage.workspace_root)
        
        # Initialize port manager for Joern servers
        services['port_manager'] = PortManager()
        
        # Initialize Joern server manager
        services['joern_server_manager'] = JoernServerManager(
            joern_binary_path=config.joern.binary_path
        )
        
        # Initialize CPG generator (runs Joern CLI directly in container)
        services['cpg_generator'] = CPGGenerator(config=config, joern_server_manager=services['joern_server_manager'])
        # Skip initialize() - no Docker needed
        
        # Initialize query executor with Joern server manager
        services['query_executor'] = QueryExecutor(services['joern_server_manager'], config=config.query)
        
        # Register MCP tools now that services are initialized
        register_tools(mcp, services)
        
        logger.info("All services initialized")
        logger.info("CodeBadger Toolkit Server is ready")
        
        yield
        
        # Shutdown
        logger.info("Shutting down CodeBadger Toolkit Server")
        
        # Close connections
        await redis_client.close()
        sync_redis_client.close()
        
        logger.info("CodeBadger Toolkit Server shutdown complete")
        
    except Exception as e:
        logger.error(f"Error during server lifecycle: {e}", exc_info=True)
        raise


# Initialize FastMCP server
mcp = FastMCP(
    "CodeBadger Toolkit Server",
    lifespan=lifespan
)

# Note: Tools are registered inside the lifespan function
# register_tools(mcp, services)


# Health check endpoint
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    """Health check endpoint for monitoring server status"""
    return JSONResponse({
        "status": "healthy",
        "service": "codebadger-toolkit",
        "version": VERSION
    })


# Root endpoint
@mcp.custom_route("/", methods=["GET"])
async def root(request):
    """Root endpoint providing basic server information"""
    return JSONResponse({
        "service": "codebadger-toolkit",
        "description": "CodeBadger Toolkit for static code analysis using Code Property Graph technology",
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
    
    logger.info(f"Starting CodeBadger Toolkit Server with HTTP transport on {host}:{port}")
    
    # Use HTTP transport (Streamable HTTP) for production deployment
    # This enables network accessibility, multiple concurrent clients,
    # and integration with web infrastructure
    mcp.run(transport="http", host=host, port=port)