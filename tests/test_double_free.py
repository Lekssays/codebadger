"""Tests for the Double-Free detection tool."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock
import uuid

import pytest

from src.models import Config, CPGConfig, QueryResult, CodebaseInfo
from src.tools.mcp_tools import register_tools

from fastmcp import FastMCP, Client


@pytest.fixture
def double_free_services():
    """Create mock services for double-free testing."""
    codebase_tracker = MagicMock()
    codebase_hash = str(uuid.uuid4()).replace('-', '')[:16]
    codebase_info = CodebaseInfo(
        codebase_hash=codebase_hash,
        source_type="local",
        source_path="/tmp/test_project",
        language="c",
        cpg_path="/tmp/test.cpg",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    codebase_tracker.get_codebase.return_value = codebase_info

    query_executor = MagicMock()
    query_executor.last_query = None

    def execute_query_with_tracking(*args, **kwargs):
        if 'query' in kwargs:
            query_executor.last_query = kwargs['query']
        elif len(args) > 2:
            query_executor.last_query = args[2]
        
        # Default double-free text output with [file:line] format
        return QueryResult(
            success=True,
            data=[
                """Double-Free Detection Analysis
============================================================

Found 20 free() call site(s). Analyzing for double-free...

Found 3 potential Double-Free issue(s):

--- Issue 1 ---
Pointer: ptr
Location: main.c in process_data()

First Free:  [main.c:42] free(ptr)
Second Free: [main.c:55] free(ptr)

--- Issue 2 ---
Pointer: str
Location: parser.c in parse_input()

First Free:  [parser.c:100] xmlFree(str)
Second Free: [parser.c:120] xmlFree(str)

--- Issue 3 ---
Pointer: buf
Location: utils.c in cleanup()

First Free:  [utils.c:30] free(buf)
Second Free: [utils.c:45] free(alias_buf)
Flow Type:  [alias(alias_buf=buf)]

Total: 3 potential Double-Free issue(s) found
"""
            ],
            row_count=1,
        )

    query_executor.execute_query = execute_query_with_tracking

    cpg = CPGConfig()
    cfg = Config(cpg=cpg)

    services = {
        "codebase_tracker": codebase_tracker,
        "query_executor": query_executor,
        "config": cfg,
        "codebase_hash": codebase_hash,
    }

    return services


@pytest.mark.asyncio
async def test_find_double_free_success(double_free_services):
    """Test basic double-free detection returns expected output format."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, double_free_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_double_free",
            {"codebase_hash": double_free_services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check output format
        assert "Double-Free Detection" in result
        assert "First Free:" in result
        assert "Second Free:" in result
        assert "Pointer:" in result


@pytest.mark.asyncio
async def test_find_double_free_with_filename_filter(double_free_services):
    """Test double-free detection with filename filter."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, double_free_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_double_free",
            {
                "codebase_hash": double_free_services["codebase_hash"],
                "filename": "parser.c",
                "limit": 50,
            }
        )
        result = res.content[0].text

        # Check that query was called
        assert double_free_services["query_executor"].last_query is not None
        # Check the query contains the filename filter
        assert "parser.c" in double_free_services["query_executor"].last_query


@pytest.mark.asyncio
async def test_find_double_free_with_limit(double_free_services):
    """Test double-free detection respects limit parameter."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, double_free_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_double_free",
            {
                "codebase_hash": double_free_services["codebase_hash"],
                "limit": 25,
            }
        )

        # Check that query was executed with limit
        assert double_free_services["query_executor"].last_query is not None
        assert "25" in double_free_services["query_executor"].last_query


@pytest.mark.asyncio
async def test_find_double_free_detects_aliases(double_free_services):
    """Test that double-free detection identifies aliased pointers."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, double_free_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_double_free",
            {"codebase_hash": double_free_services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check that alias flows are in output
        assert "alias" in result


@pytest.mark.asyncio
async def test_find_double_free_invalid_hash(double_free_services):
    """Test error handling for invalid codebase hash."""
    services = double_free_services
    services["codebase_tracker"].get_codebase.return_value = None

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_double_free",
            {"codebase_hash": "invalid_hash_12345"}
        )
        result = res.content[0].text

        # Should return validation error
        assert "Error" in result or "not found" in result.lower()


@pytest.mark.asyncio
async def test_find_double_free_no_issues_found(double_free_services):
    """Test output when no double-free issues are detected."""
    services = double_free_services

    # Mock empty result
    no_issues_result = QueryResult(
        success=True,
        data=[
            """Double-Free Detection Analysis
============================================================

Found 5 free() call site(s). Analyzing for double-free...

No potential Double-Free issues detected.

Note: This analysis checks for:
  - Multiple free() on the same pointer in the same function
  - Pointer aliasing (p2 = ptr; free(ptr); free(p2))
  - Interprocedural double-free via function calls
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=no_issues_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_double_free",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        assert "No potential Double-Free issues detected" in result


@pytest.mark.asyncio
async def test_find_double_free_no_free_calls(double_free_services):
    """Test output when no free() calls exist in codebase."""
    services = double_free_services

    no_free_result = QueryResult(
        success=True,
        data=[
            """Double-Free Detection Analysis
============================================================

No free() calls found in the codebase.
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=no_free_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_double_free",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        assert "No free() calls found" in result


@pytest.mark.asyncio
async def test_find_double_free_query_error(double_free_services):
    """Test error handling when query execution fails."""
    services = double_free_services

    error_result = QueryResult(
        success=False,
        data=[],
        row_count=0,
        error="Query timeout after 120 seconds"
    )
    services["query_executor"].execute_query = MagicMock(return_value=error_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_double_free",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        assert "Error" in result
        assert "timeout" in result.lower()


@pytest.mark.asyncio
async def test_find_double_free_detects_free_variants(double_free_services):
    """Test that various free() variants are detected."""
    services = double_free_services

    variants_result = QueryResult(
        success=True,
        data=[
            """Double-Free Detection Analysis
============================================================

Found 10 free() call site(s). Analyzing for double-free...

Found 2 potential Double-Free issue(s):

--- Issue 1 ---
Pointer: ptr
Location: main.c in cleanup()

First Free:  [main.c:10] free(ptr)
Second Free: [main.c:20] free(ptr)

--- Issue 2 ---
Pointer: xmlStr
Location: parser.c in parse()

First Free:  [parser.c:30] xmlFree(xmlStr)
Second Free: [parser.c:40] xmlFree(xmlStr)

Total: 2 potential Double-Free issue(s) found
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=variants_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_double_free",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check that various free variants are in output
        assert "free(ptr)" in result
        assert "xmlFree(xmlStr)" in result
