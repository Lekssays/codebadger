"""Tests for the Null Pointer Dereference detection tool."""

from datetime import datetime, timezone
from unittest.mock import MagicMock
import uuid

import pytest

from src.models import Config, CPGConfig, QueryResult, CodebaseInfo
from src.tools.mcp_tools import register_tools

from fastmcp import FastMCP, Client


@pytest.fixture
def npd_services():
    """Create mock services for null pointer deref testing."""
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

        # Default null pointer deref text output
        return QueryResult(
            success=True,
            data=[
                """Null Pointer Dereference Analysis (Deep Interprocedural)
============================================================

Found 15 allocation site(s). Analyzing with deep interprocedural flow...

Found 2 potential null pointer dereference issue(s):

--- Issue 1 ---
Allocation Site: malloc(size)
  Location: main.c:42 in process_data()
  Assigned To: ptr

Unchecked Dereference(s):
  [main.c:50] ptr->field = value
  [main.c:55] *ptr = 0 [DEREF]

--- Issue 2 ---
Allocation Site: fopen(filename, "r")
  Location: parser.c:100 in read_config()
  Assigned To: fp

Unchecked Dereference(s):
  [parser.c:105] fread(buf, 1, size, fp) [FUNC-ARG]

Total: 2 potential null pointer dereference issue(s) found

Dereference Types:
  - (no tag): Member access via ->
  - [DEREF]: Explicit pointer dereference via *
  - [INDEX]: Array-style access via []
  - [FUNC-ARG]: Pointer passed to function (potential dereference inside)
  - [CROSS-FUNC]: Dereference in directly called function
  - [DEEP]: Dereference across multiple function call levels

CWE: CWE-476 (NULL Pointer Dereference)
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
async def test_find_null_pointer_deref_success(npd_services):
    """Test basic null pointer deref detection returns expected output format."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, npd_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {"codebase_hash": npd_services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check output format
        assert "Null Pointer Dereference Analysis (Deep Interprocedural)" in result
        assert "Allocation Site:" in result
        assert "Assigned To:" in result
        assert "Unchecked Dereference(s):" in result


@pytest.mark.asyncio
async def test_find_null_pointer_deref_with_filename_filter(npd_services):
    """Test null pointer deref detection with filename filter."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, npd_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {
                "codebase_hash": npd_services["codebase_hash"],
                "filename": "main.c",
                "limit": 50,
            }
        )
        result = res.content[0].text

        # Check that query was called
        assert npd_services["query_executor"].last_query is not None
        # Check the query contains the filename filter
        assert "main.c" in npd_services["query_executor"].last_query


@pytest.mark.asyncio
async def test_find_null_pointer_deref_with_limit(npd_services):
    """Test null pointer deref detection respects limit parameter."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, npd_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {
                "codebase_hash": npd_services["codebase_hash"],
                "limit": 10,
            }
        )

        # Check that query was executed with limit
        assert npd_services["query_executor"].last_query is not None
        # The limit should be templated into the query
        assert "10" in npd_services["query_executor"].last_query


@pytest.mark.asyncio
async def test_find_null_pointer_deref_detects_deref_types(npd_services):
    """Test that null pointer deref detection identifies different dereference types."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, npd_services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {"codebase_hash": npd_services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check dereference types are documented
        assert "Dereference Types:" in result
        assert "[DEREF]" in result
        assert "[FUNC-ARG]" in result


@pytest.mark.asyncio
async def test_find_null_pointer_deref_invalid_hash(npd_services):
    """Test error handling for invalid codebase hash."""
    services = npd_services
    services["codebase_tracker"].get_codebase.return_value = None

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {"codebase_hash": "invalid_hash_12345"}
        )
        result = res.content[0].text

        # Should return validation error
        assert "Error" in result or "not found" in result.lower()


@pytest.mark.asyncio
async def test_find_null_pointer_deref_no_issues_found(npd_services):
    """Test output when no null pointer deref issues are detected."""
    services = npd_services

    # Mock empty result
    no_npd_result = QueryResult(
        success=True,
        data=[
            """Null Pointer Dereference Analysis (Deep Interprocedural)
============================================================

Found 10 allocation site(s). Analyzing with deep interprocedural flow...

No potential Null Pointer Dereference issues detected.

Note: This analysis includes:
  - Intraprocedural unchecked allocation return values
  - Unchecked fopen/strdup/mmap return values
  - Dereferences without prior NULL checks
  - Deep interprocedural flow (multi-level call chains)

Filtered out:
  - Dereferences guarded by if(ptr != NULL) checks
  - Dereferences after early return/exit on NULL
  - Pointer reassignments between allocation and use
  - Safe wrapper allocators (xmalloc, g_malloc, etc.)
  - Cross-function dereferences with NULL checks in callee
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=no_npd_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        assert "No potential Null Pointer Dereference issues detected" in result
        assert "Intraprocedural unchecked allocation" in result
        assert "Filtered out:" in result


@pytest.mark.asyncio
async def test_find_null_pointer_deref_no_alloc_calls(npd_services):
    """Test output when no allocation calls exist in codebase."""
    services = npd_services

    # Mock result with no allocation calls
    no_alloc_result = QueryResult(
        success=True,
        data=[
            """Null Pointer Dereference Analysis (Deep Interprocedural)
============================================================

No allocation calls found in the codebase.
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=no_alloc_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        assert "No allocation calls found" in result


@pytest.mark.asyncio
async def test_find_null_pointer_deref_query_error(npd_services):
    """Test error handling when query execution fails."""
    services = npd_services

    # Mock query failure
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
            "find_null_pointer_deref",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        assert "Error" in result
        assert "timeout" in result.lower()


@pytest.mark.asyncio
async def test_find_null_pointer_deref_detects_alloc_variants(npd_services):
    """Test that various allocation function variants are detected."""
    services = npd_services

    # Mock result showing various allocation variants
    variants_result = QueryResult(
        success=True,
        data=[
            """Null Pointer Dereference Analysis (Deep Interprocedural)
============================================================

Found 8 allocation site(s). Analyzing with deep interprocedural flow...

Found 3 potential null pointer dereference issue(s):

--- Issue 1 ---
Allocation Site: malloc(sizeof(struct node))
  Location: main.c:10 in create_node()
  Assigned To: node

Unchecked Dereference(s):
  [main.c:12] node->value = 42

--- Issue 2 ---
Allocation Site: fopen(path, "r")
  Location: io.c:20 in read_file()
  Assigned To: fp

Unchecked Dereference(s):
  [io.c:22] fgets(buf, sizeof(buf), fp) [FUNC-ARG]

--- Issue 3 ---
Allocation Site: strdup(input)
  Location: utils.c:30 in copy_string()
  Assigned To: copy

Unchecked Dereference(s):
  [utils.c:32] copy[0] = toupper(copy[0]) [INDEX]

Total: 3 potential null pointer dereference issue(s) found
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=variants_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check that various allocation variants are in output
        assert "malloc(" in result
        assert "fopen(" in result
        assert "strdup(" in result


@pytest.mark.asyncio
async def test_find_null_pointer_deref_cross_function(npd_services):
    """Test that interprocedural null pointer deref detection works correctly."""
    services = npd_services

    # Mock result showing cross-function dereferences
    cross_func_result = QueryResult(
        success=True,
        data=[
            """Null Pointer Dereference Analysis (Deep Interprocedural)
============================================================

Found 12 allocation site(s). Analyzing with deep interprocedural flow...

Found 2 potential null pointer dereference issue(s):

--- Issue 1 ---
Allocation Site: malloc(sizeof(struct node))
  Location: main.c:42 in create_node()
  Assigned To: node

Unchecked Dereference(s):
  [main.c:50] node->value = 42
  [utils.c:15] data->next = NULL [CROSS-FUNC]
           in process_node()

--- Issue 2 ---
Allocation Site: malloc(size)
  Location: parser.c:100 in parse_input()
  Assigned To: buf

Unchecked Dereference(s):
  [parser.c:110] buf[0] = header [INDEX]
  [transform.c:55] ptr->len = 0 [via: parse_input -> transform -> set_len] [DEEP]
           in set_len()

Total: 2 potential null pointer dereference issue(s) found

Dereference Types:
  - (no tag): Member access via ->
  - [DEREF]: Explicit pointer dereference via *
  - [INDEX]: Array-style access via []
  - [FUNC-ARG]: Pointer passed to function (potential dereference inside)
  - [CROSS-FUNC]: Dereference in directly called function
  - [DEEP]: Dereference across multiple function call levels

CWE: CWE-476 (NULL Pointer Dereference)
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=cross_func_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check interprocedural output format
        assert "Deep Interprocedural" in result
        assert "[CROSS-FUNC]" in result
        assert "[DEEP]" in result
        assert "via:" in result
        assert "->" in result
        assert "CWE-476" in result


@pytest.mark.asyncio
async def test_find_null_pointer_deref_shows_callee_method(npd_services):
    """Test that cross-function dereferences show the callee method name."""
    services = npd_services

    cross_func_result = QueryResult(
        success=True,
        data=[
            """Null Pointer Dereference Analysis (Deep Interprocedural)
============================================================

Found 5 allocation site(s). Analyzing with deep interprocedural flow...

Found 1 potential null pointer dereference issue(s):

--- Issue 1 ---
Allocation Site: malloc(len)
  Location: main.c:20 in init()
  Assigned To: ptr

Unchecked Dereference(s):
  [helper.c:10] param->field = 1 [via: init -> helper_func] [CROSS-FUNC]
           in helper_func()

Total: 1 potential null pointer dereference issue(s) found

Dereference Types:
  - (no tag): Member access via ->
  - [DEREF]: Explicit pointer dereference via *
  - [INDEX]: Array-style access via []
  - [FUNC-ARG]: Pointer passed to function (potential dereference inside)
  - [CROSS-FUNC]: Dereference in directly called function
  - [DEEP]: Dereference across multiple function call levels

CWE: CWE-476 (NULL Pointer Dereference)
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=cross_func_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        # Check that callee method is shown
        assert "in helper_func()" in result
        assert "helper.c:10" in result


@pytest.mark.asyncio
async def test_find_null_pointer_deref_no_issues_interproc(npd_services):
    """Test output when no issues found includes interprocedural note."""
    services = npd_services

    no_issues_result = QueryResult(
        success=True,
        data=[
            """Null Pointer Dereference Analysis (Deep Interprocedural)
============================================================

Found 10 allocation site(s). Analyzing with deep interprocedural flow...

No potential Null Pointer Dereference issues detected.

Note: This analysis includes:
  - Intraprocedural unchecked allocation return values
  - Unchecked fopen/strdup/mmap return values
  - Dereferences without prior NULL checks
  - Deep interprocedural flow (multi-level call chains)

Filtered out:
  - Dereferences guarded by if(ptr != NULL) checks
  - Dereferences after early return/exit on NULL
  - Pointer reassignments between allocation and use
  - Safe wrapper allocators (xmalloc, g_malloc, etc.)
  - Cross-function dereferences with NULL checks in callee
"""
        ],
        row_count=1,
    )
    services["query_executor"].execute_query = MagicMock(return_value=no_issues_result)

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res = await client.call_tool(
            "find_null_pointer_deref",
            {"codebase_hash": services["codebase_hash"]}
        )
        result = res.content[0].text

        assert "No potential Null Pointer Dereference issues detected" in result
        assert "Deep interprocedural flow" in result
        assert "Cross-function dereferences with NULL checks in callee" in result
