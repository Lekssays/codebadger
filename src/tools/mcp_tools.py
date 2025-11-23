"""
MCP Tool Definitions for CodeBadger Server

Main entry point that registers all tools from separate modules
"""

from .core_tools import register_core_tools
from .code_browsing_tools import register_code_browsing_tools
from .taint_analysis_tools import register_taint_analysis_tools


def register_tools(mcp, services: dict):
    """Register all MCP tools with the FastMCP server"""

    # Register core tools (hash-based CPG generation and status)
    register_core_tools(mcp, services)

    # Register code browsing tools (refactored to use codebase_hash)
    register_code_browsing_tools(mcp, services)

    # Register taint analysis tools (refactored to use codebase_hash)
    register_taint_analysis_tools(mcp, services)
