import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
import uuid

import pytest

from src.models import Config, CPGConfig, QueryResult, CodebaseInfo
from src.tools.mcp_tools import register_tools


from fastmcp import FastMCP, Client


@pytest.fixture
def fake_services():
    # codebase tracker mock
    from src.services.codebase_tracker import CodebaseTracker
    codebase_tracker = MagicMock()
    codebase_hash = str(uuid.uuid4()).replace('-', '')[:16]
    codebase_info = CodebaseInfo(
        codebase_hash=codebase_hash,
        source_type="local",
        source_path="/tmp",
        language="c",
        cpg_path="/tmp/test.cpg",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    codebase_tracker.get_codebase.return_value = codebase_info

    # query executor mock
    query_executor = MagicMock()

    # Store the last query for test assertions
    query_executor.last_query = None

    def execute_query_with_tracking(*args, **kwargs):
        # Store the query parameter
        if 'query' in kwargs:
            query_executor.last_query = kwargs['query'] 
        elif len(args) > 2:
            query_executor.last_query = args[2]  # query is typically 3rd arg

        # Return the mock result
        return QueryResult(
            success=True,
            data=[
                { 
                    "_1": 123,
                    "_2": "getenv",
                    "_3": 'char *s = getenv("FOO")',
                    "_4": "core.c",
                    "_5": 10,
                    "_6": "main",
                }
            ],
            row_count=1,
        )

    query_executor.execute_query = execute_query_with_tracking

    # config with taint lists
    cpg = CPGConfig() 
    cpg.taint_sources = {"c": ["getenv", "fgets"]}
    cpg.taint_sinks = {"c": ["system", "popen"]}
    cfg = Config(cpg=cpg)

    services = {
        "codebase_tracker": codebase_tracker,
        "query_executor": query_executor,
        "config": cfg,
        "codebase_hash": codebase_hash,
    }

    return services


@pytest.mark.asyncio
async def test_find_taint_sources_success(fake_services):
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services)

    async with Client(mcp) as client:
        res_json = await client.call_tool("find_taint_sources", {"codebase_hash": fake_services["codebase_hash"], "language": "c", "limit": 10})
        import json
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert "sources" in res
        assert isinstance(res["sources"], list)
        assert res["total"] == 1


@pytest.mark.asyncio
async def test_find_taint_sources_with_filename_filter(fake_services):
    """Test find_taint_sources with filename parameter"""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services)

    async with Client(mcp) as client:
        # Call with filename filter
        res_json = await client.call_tool(
            "find_taint_sources",
            {
                "codebase_hash": fake_services["codebase_hash"],
                "language": "c",
                "filename": "shell.c",
                "limit": 10,
            }
        )
        import json
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert "sources" in res
        assert isinstance(res["sources"], list)
        
        # Verify the query executor was called with a query containing the file filter
        query_executor = fake_services["query_executor"]
        assert query_executor.last_query is not None
        assert "where(_.file.name" in query_executor.last_query
        assert "shell" in query_executor.last_query


@pytest.mark.asyncio
async def test_find_taint_sinks_success(fake_services):
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services)

    async with Client(mcp) as client:
        res_json = await client.call_tool("find_taint_sinks", {"codebase_hash": fake_services["codebase_hash"], "language": "c", "limit": 10})
        import json
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert "sinks" in res
        assert isinstance(res["sinks"], list)
        assert res["total"] == 1


@pytest.mark.asyncio
async def test_find_taint_sinks_with_filename_filter(fake_services):
    """Test find_taint_sinks with filename parameter"""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services)

    async with Client(mcp) as client:
        # Call with filename filter
        res_json = await client.call_tool(
            "find_taint_sinks",
            {
                "codebase_hash": fake_services["codebase_hash"],
                "language": "c",
                "filename": "main.c",
                "limit": 10,
            }
        )
        import json
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert "sinks" in res
        assert isinstance(res["sinks"], list)
        
        # Verify the query executor was called with a query containing the file filter
        query_executor = fake_services["query_executor"]
        assert query_executor.last_query is not None
        assert "where(_.file.name" in query_executor.last_query
        assert "main" in query_executor.last_query


@pytest.mark.asyncio
async def test_find_taint_flows_success(fake_services):
    # Setup mock for flow query with text output
    services = fake_services

    # The refactored API returns human-readable text
    flow_result = QueryResult(
        success=True,
        data=[
            """Taint Flow Analysis
============================================================
Sources: pattern 'getenv' (1 found)
Sinks: pattern 'system' (1 found)

Found 1 taint flow(s):

--- Flow 1 ---
Source: getenv("FOO")
  Location: core.c:10 in main()

Sink: system(cmd)
  Location: core.c:42 in main()

Path length: 2 nodes
"""
        ],
        row_count=1,
    )

    services["query_executor"].execute_query = MagicMock(return_value=flow_result)
    services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
        codebase_hash=services["codebase_hash"],
        source_type="local",
        source_path="/path",
        language="c",
        cpg_path="/tmp/test.cpg",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = await client.call_tool(
            "find_taint_flows",
            {
                "codebase_hash": services["codebase_hash"],
                "source_location": "core.c:10",
                "sink_location": "core.c:42",
                "timeout": 10,
            }
        )
        result = res_text.content[0].text

        # Check text output contains expected information
        assert "Taint Flow Analysis" in result
        assert "getenv" in result
        assert "system" in result
        assert "core.c" in result


@pytest.mark.asyncio
async def test_find_taint_flows_with_node_ids(fake_services):
    """Test that node_id based queries work"""
    services = fake_services

    # The refactored API returns human-readable text
    flow_result = QueryResult(
        success=True,
        data=[
            """Taint Flow Analysis
============================================================
Source: getenv("FOO")
  Location: core.c:10
  Node ID: 30064771934
Sink: system(cmd)
  Location: core.c:42
  Node ID: 30064780656

Found 1 taint flow(s):

--- Flow 1 ---
Source: getenv("FOO")
  Location: core.c:10 in main()

Sink: system(cmd)
  Location: core.c:42 in main()

Path length: 2 nodes
"""
        ],
        row_count=1,
    )

    services["query_executor"].execute_query = MagicMock(return_value=flow_result)
    services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
        codebase_hash=services["codebase_hash"],
        source_type="local",
        source_path="/path",
        language="c",
        cpg_path="/tmp/test.cpg",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_text = await client.call_tool(
            "find_taint_flows",
            {
                "codebase_hash": services["codebase_hash"],
                "source_node_id": 30064771934,
                "sink_node_id": 30064780656,
                "timeout": 10,
            }
        )
        result = res_text.content[0].text

        # Check text output contains expected information
        assert "Taint Flow Analysis" in result
        assert "getenv" in result
        assert "system" in result


@pytest.mark.asyncio
async def test_find_taint_flows_validation_error(fake_services):
    """Test that missing source returns validation error"""
    services = fake_services

    services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
        codebase_hash=services["codebase_hash"],
        source_type="local",
        source_path="/path",
        language="c",
        cpg_path="/tmp/test.cpg",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        # Test with only sink (missing source)
        res_text = await client.call_tool(
            "find_taint_flows",
            {
                "codebase_hash": services["codebase_hash"],
                "sink_location": "core.c:42",
                "timeout": 10,
            }
        )
        result = res_text.content[0].text

        # Should return validation error about missing source
        assert "Validation Error" in result
        assert "source" in result.lower()

