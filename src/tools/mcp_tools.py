"""
MCP Tool Definitions for CodeBadger Server

Main entry point that registers all tools from separate modules.
Custom tools are loaded last from custom_tools.py.
"""

import logging

from .core_tools import register_core_tools
from .code_browsing_tools import register_code_browsing_tools
from .taint_analysis_tools import register_taint_analysis_tools

logger = logging.getLogger(__name__)


def register_tools(mcp, services: dict):
    """Register all MCP tools with the FastMCP server"""

    register_core_tools(mcp, services)
    register_code_browsing_tools(mcp, services)
    register_taint_analysis_tools(mcp, services)

    try:
        from .custom_tools import register_custom_tools
        register_custom_tools(mcp, services)
        logger.info("Custom tools registered from custom_tools.py")
    except ImportError:
        logger.debug("custom_tools.py not found — skipping custom tool registration")
    except Exception as e:
        logger.error(f"Failed to register custom tools: {e}", exc_info=True)
