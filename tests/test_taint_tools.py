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
    # Setup mock for source, sink, and flow queries
    services = fake_services

    # Create side effect to return different results for 3 queries
    source_result = QueryResult(
        success=True,
        data=[
            {"_1": 1001, "_2": 'getenv("FOO")', "_3": "core.c", "_4": 10, "_5": "main"}
        ],
        row_count=1,
    )

    sink_result = QueryResult(
        success=True,
        data=[
            {"_1": 1002, "_2": "system(cmd)", "_3": "core.c", "_4": 42, "_5": "execute"}
        ],
        row_count=1,
    )

    flow_result = QueryResult(
        success=True,
        data=[
            {
                "_1": 0,
                "_2": 3,
                "_3": [
                    {"_1": 'getenv("FOO")', "_2": "core.c", "_3": 10, "_4": "CALL"},
                    {"_1": "cmd", "_2": "core.c", "_3": 25, "_4": "IDENTIFIER"},
                    {"_1": "system(cmd)", "_2": "core.c", "_3": 42, "_4": "CALL"},
                ],
            }
        ],
        row_count=1,
    )

    call_count = [0]

    def mock_execute(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return source_result 
        elif call_count[0] == 2:
            return sink_result
        else:
            return flow_result

    services["query_executor"].execute_query = MagicMock(side_effect=mock_execute)
    # Set codebase tracker to return a codebase info ready for queries
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
        await client.call_tool(
            "find_taint_flows",
            {
                "codebase_hash": services["codebase_hash"],
                "source_node_id": "1001",
                "sink_node_id": "1002",
                "timeout": 10,
            }
        )
        # We don't verify result structure much here as previous test, 
        # but just ensuring it runs without error via client call is good for now, 
        # or we could inspect result.

@pytest.mark.asyncio
async def test_find_taint_flows_source_only(fake_services):
    # Setup mock for source-only query (flows to any sink)
    services = fake_services

    # Create side effect to return different results for 2 queries
    source_result = QueryResult(
        success=True,
        data=[
            {"_1": 1001, "_2": 'getenv("FOO")', "_3": "core.c", "_4": 10, "_5": "main"}
        ],
        row_count=1,
    )

    flow_result = QueryResult(
        success=True,
        data=[
            {
                "_1": 0,
                "_2": 3,
                "_3": [
                    {"_1": 'getenv("FOO")', "_2": "core.c", "_3": 10, "_4": "CALL"},
                    {"_1": "cmd", "_2": "core.c", "_3": 25, "_4": "IDENTIFIER"},
                    {"_1": "system(cmd)", "_2": "core.c", "_3": 42, "_4": "CALL"},
                ],
            }
        ],
        row_count=1,
    )

    call_count = [0]

    def mock_execute(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return source_result 
        else:
            return flow_result

    services["query_executor"].execute_query = MagicMock(side_effect=mock_execute)
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
        res_json = await client.call_tool(
            "find_taint_flows",
            {
                "codebase_hash": services["codebase_hash"],
                "source_node_id": "1001",
                "timeout": 10,
            }
        )
        import json
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert res["source"]["node_id"] == 1001
        assert "flows" in res
        assert isinstance(res["flows"], list)
        assert res["total_flows"] == 1


@pytest.mark.asyncio
async def test_find_taint_flows_sink_only_error(fake_services):
    # Test that sink-only queries are rejected
    services = fake_services

    mcp = FastMCP("TestServer")
    register_tools(mcp, services)

    async with Client(mcp) as client:
        res_json = await client.call_tool(
            "find_taint_flows",
            {
                "codebase_hash": services["codebase_hash"],
                "sink_node_id": "1002",
                "timeout": 10,
            }
        )
        import json
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is False
        assert "error" in res
        assert "Either source_node_id or source_location must be provided" in res["error"]["message"]
