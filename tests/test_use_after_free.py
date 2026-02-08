"""Tests for the Use-After-Free detection tool."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock
import uuid

import pytest

from src.models import Config, CPGConfig, QueryResult, CodebaseInfo
from src.tools.mcp_tools import register_tools

from fastmcp import FastMCP, Client


@pytest.fixture
def uaf_services():
    """Create mock services for UAF testing."""
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
        
        # Default UAF text output
        return QueryResult(
            success=True,
            data=[
                """Use-After-Free Analysis (Deep Interprocedural)
============================================================

Found 10 free() call site(s). Analyzing with deep interprocedural flow...

Found 2 potential UAF issue(s):

--- Issue 1 ---
Free Site: free(ptr)
  Location: main.c:42 in process_data()
  Freed Pointer: ptr

Post-Free Usage(s):
  [L50] print_data(ptr)
  [L55] ptr->value [DEEP]
           in helper() at utils.c

--- Issue 2 ---
Free Site: xmlFree(str)
  Location: parser.c:100 in parse_input()
  Freed Pointer: str

Post-Free Usage(s):
  [L110] strlen(str)
  [L115] str [via: parse_input -> validate -> check_str] [DEEP]
           in check_str() at validator.c

Total: 2 potential UAF issue(s) found

Flow Types:
  - direct: Same-function usage of freed pointer
  - alias(X): Usage of pointer alias X after original freed
  - [CROSS-FUNC]: Usage in directly called function
  - [DEEP]: Usage across multiple function call levels
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
async def test_find_use_after_free_success(uaf_services):
    """Test basic UAF detection returns expected output format."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, uaf_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_use_after_free",
            {"codebase_hash": uaf_services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check output format
        assert "Use-After-Free Analysis" in result
        assert "Deep Interprocedural" in result
        assert "Free Site:" in result
        assert "Freed Pointer:" in result
        assert "Post-Free Usage(s):" in result


@pytest.mark.asyncio
async def test_find_use_after_free_with_filename_filter(uaf_services):
    """Test UAF detection with filename filter."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, uaf_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_use_after_free",
            {
                "codebase_hash": uaf_services["codebase_hash"],
                "filename": "main.c",
                "limit": 50,
            }
        )
        result = res.content[0].text

        # Check that query was called
        assert uaf_services["query_executor"].last_query is not None
        # Check the query contains the filename filter
        assert "main.c" in uaf_services["query_executor"].last_query


@pytest.mark.asyncio
async def test_find_use_after_free_with_limit(uaf_services):
    """Test UAF detection respects limit parameter."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, uaf_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_use_after_free",
            {
                "codebase_hash": uaf_services["codebase_hash"],
                "limit": 10,
            }
        )

        # Check that query was executed with limit
        assert uaf_services["query_executor"].last_query is not None
        # The limit should be templated into the query
        assert "10" in uaf_services["query_executor"].last_query


@pytest.mark.asyncio
async def test_find_use_after_free_detects_flow_types(uaf_services):
    """Test that UAF detection identifies different flow types."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, uaf_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_use_after_free",
            {"codebase_hash": uaf_services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check flow types are documented
        assert "Flow Types:" in result
        assert "direct" in result
        assert "alias" in result
        assert "[DEEP]" in result


@pytest.mark.asyncio
async def test_find_use_after_free_shows_call_path(uaf_services):
    """Test that deep interprocedural flows show call path."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, uaf_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_use_after_free",
            {"codebase_hash": uaf_services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check that call paths are shown for deep flows
        assert "via:" in result
        assert "->" in result  # Arrow notation in call path


@pytest.mark.asyncio
async def test_find_use_after_free_invalid_hash(uaf_services):
    """Test error handling for invalid codebase hash."""
    services = uaf_services
    services["codebase_tracker"].get_codebase.return_value = None

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_use_after_free",
            {"codebase_hash": "invalid_hash_12345"}
        )
        result = res.content[0].text

        # Should return validation error
        assert "Error" in result or "not found" in result.lower()


@pytest.mark.asyncio
async def test_find_use_after_free_no_issues_found(uaf_services):
    """Test output when no UAF issues are detected."""
    services = uaf_services

    # Mock empty result
    no_uaf_result = QueryResult(
        success=True,
        data=[
            """Use-After-Free Analysis (Deep Interprocedural)
============================================================

Found 5 free() call site(s). Analyzing with deep interprocedural flow...

No potential Use-After-Free issues detected.

Note: This analysis includes:
  - Intraprocedural usages (same function)
  - Pointer aliasing (p2 = ptr; free(ptr); use(p2))
  - Deep interprocedural flow (multi-level call chains)
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=no_uaf_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_use_after_free",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        assert "No potential Use-After-Free issues detected" in result
        assert "Intraprocedural" in result
        assert "Pointer aliasing" in result
        assert "Deep interprocedural" in result


@pytest.mark.asyncio
async def test_find_use_after_free_no_free_calls(uaf_services):
    """Test output when no free() calls exist in codebase."""
    services = uaf_services

    # Mock result with no free calls
    no_free_result = QueryResult(
        success=True,
        data=[
            """Use-After-Free Analysis (Deep Interprocedural)
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
            "find_use_after_free",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        assert "No free() calls found" in result


@pytest.mark.asyncio
async def test_find_use_after_free_query_error(uaf_services):
    """Test error handling when query execution fails."""
    services = uaf_services

    # Mock query failure
    error_result = QueryResult(
        success=False,
        data=[],
        row_count=0,
        error="Query timeout after 180 seconds"
    )
    services["query_executor"].execute_query = MagicMock(return_value=error_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_use_after_free",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        assert "Error" in result
        assert "timeout" in result.lower()


@pytest.mark.asyncio
async def test_find_use_after_free_detects_free_variants(uaf_services):
    """Test that various free() variants are detected."""
    services = uaf_services

    # Mock result showing various free variants
    variants_result = QueryResult(
        success=True,
        data=[
            """Use-After-Free Analysis (Deep Interprocedural)
============================================================

Found 4 free() call site(s). Analyzing with deep interprocedural flow...

Found 3 potential UAF issue(s):

--- Issue 1 ---
Free Site: free(ptr)
  Location: main.c:10 in main()
  Freed Pointer: ptr

Post-Free Usage(s):
  [L15] ptr->value

--- Issue 2 ---
Free Site: xmlFree(xmlStr)
  Location: parser.c:20 in parse()
  Freed Pointer: xmlStr

Post-Free Usage(s):
  [L25] strlen(xmlStr)

--- Issue 3 ---
Free Site: g_free(gptr)
  Location: glib_utils.c:30 in cleanup()
  Freed Pointer: gptr

Post-Free Usage(s):
  [L35] gptr[0]

Total: 3 potential UAF issue(s) found
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=variants_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_use_after_free",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check that various free variants are in output
        assert "free(ptr)" in result
        assert "xmlFree(xmlStr)" in result
        assert "g_free(gptr)" in result
