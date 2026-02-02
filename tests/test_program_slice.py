"""
Tests for the get_program_slice function with simplified input/output.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock
import uuid

import pytest

from src.models import Config, CPGConfig, QueryResult, CodebaseInfo
from src.tools.mcp_tools import register_tools
from fastmcp import FastMCP, Client


@pytest.fixture
def fake_services_slice():
    """Create mock services for program slice tests."""
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

        # Return realistic text output (backward slice)
        text_output = """Program Slice for memcpy at tree.c:195
============================================================
Code: memcpy(&ret[0], prefix, lenp)
Method: xmlBuildQName
Arguments: &ret[0], prefix, lenp

[BACKWARD SLICE] (3 data dependencies)

  Data Dependencies:
    [tree.c:189] ret: ret = xmlMalloc(lenn + lenp + 2)
      <- depends on: lenn, lenp
    [tree.c:184] lenp: lenp = strlen((char *) prefix)
      <- depends on: prefix

  Control Dependencies:
    [tree.c:174] IF: (ncname == NULL) || (len < 0)
    [tree.c:188] IF: (memory == NULL) || ((size_t) len < lenn + lenp + 2)

  Parameters: prefix (xmlChar*)
"""
        return QueryResult(
            success=True,
            data=[text_output],
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


@pytest.fixture
def fake_services_forward():
    """Create mock services returning forward slice data."""
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

        text_output = """Program Slice for read at xmlIO.c:797
============================================================
Code: read(fd, buffer, len)
Method: xmlFdRead
Arguments: fd, buffer, len

[FORWARD SLICE] (5 propagations)
  Result stored in: bytes

  Propagations:
    [xmlIO.c:798] usage (bytes): bytes < 0
    [xmlIO.c:809] propagation (bytes): ret += bytes
    [xmlIO.c:810] propagation (bytes): buffer += bytes

  Control Flow Affected:
    [xmlIO.c:798] IF: bytes < 0
    [xmlIO.c:807] IF: bytes == 0
"""
        return QueryResult(
            success=True,
            data=[text_output],
            row_count=1,
        )

    query_executor.execute_query = execute_query_with_tracking

    cpg = CPGConfig()
    cfg = Config(cpg=cpg)

    return {
        "codebase_tracker": codebase_tracker,
        "query_executor": query_executor,
        "config": cfg,
        "codebase_hash": codebase_hash,
    }


@pytest.mark.asyncio
async def test_get_program_slice_backward(fake_services_slice):
    """Test backward slicing mode."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward",
            "max_depth": 5
        })).content[0].text
        
        # Check text output contains key information
        assert "Program Slice for memcpy" in res_text
        assert "at tree.c:195" in res_text
        assert "[BACKWARD SLICE]" in res_text
        assert "Data Dependencies:" in res_text
        assert "ret =" in res_text
        assert "depends on: lenn, lenp" in res_text


@pytest.mark.asyncio
async def test_get_program_slice_forward(fake_services_forward):
    """Test forward slicing mode."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_forward)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_forward["codebase_hash"],
            "location": "xmlIO.c:797:read",
            "direction": "forward",
            "max_depth": 5
        })).content[0].text

        assert "Program Slice for read" in res_text
        assert "[FORWARD SLICE]" in res_text
        assert "Result stored in: bytes" in res_text
        assert "Propagations:" in res_text
        assert "bytes < 0" in res_text
        assert "Control Flow Affected:" in res_text


@pytest.mark.asyncio
async def test_get_program_slice_data_dependencies(fake_services_slice):
    """Test that data dependencies are correctly returned."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward"
        })).content[0].text

        assert "Data Dependencies:" in res_text
        assert "[tree.c:189] ret: ret = xmlMalloc" in res_text
        assert "[tree.c:184] lenp: lenp = strlen" in res_text


@pytest.mark.asyncio
async def test_get_program_slice_control_dependencies(fake_services_slice):
    """Test that control dependencies are correctly returned."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward"
        })).content[0].text

        assert "Control Dependencies:" in res_text
        assert "[tree.c:174] IF: (ncname == NULL) || (len < 0)" in res_text


@pytest.mark.asyncio
async def test_get_program_slice_depth_limiting(fake_services_slice):
    """Test that max_depth parameter is used in the query."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward",
            "max_depth": 3
        })
        
        # Verify the query contains the depth limit
        query = fake_services_slice["query_executor"].last_query
        assert "maxDepth = 3" in query


@pytest.mark.asyncio
async def test_get_program_slice_invalid_direction(fake_services_slice):
    """Test that invalid direction is rejected."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195",
            "direction": "both"
        })).content[0].text

        assert "Validation Error" in res_text
        assert "direction" in res_text


@pytest.mark.asyncio
async def test_get_program_slice_invalid_location_format(fake_services_slice):
    """Test that invalid location format is rejected."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_text = (await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "invalid_format",
            "direction": "backward"
        })).content[0].text

        assert "Validation Error" in res_text
        assert "location must be" in res_text

