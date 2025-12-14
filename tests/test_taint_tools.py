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
    # Setup mock for point-to-point flow query
    services = fake_services

    # The new API uses source_location and sink_location (file:line format)
    # and executes a single unified query
    flow_result = QueryResult(
        success=True,
        data=[
            '[{"flow_found": true, "source": {"code": "getenv(\\"FOO\\")", "file": "core.c", "line": 10}, "sink": {"code": "system(cmd)", "file": "core.c", "line": 42}, "variable": "cmd"}]'
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
        res_json = await client.call_tool(
            "find_taint_flows",
            {
                "codebase_hash": services["codebase_hash"],
                "source_location": "core.c:10",
                "sink_location": "core.c:42",
                "timeout": 10,
            }
        )
        import json
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert res.get("mode") == "point_to_point"
        assert res.get("flow_found") is True
        assert res["source"]["code"] == 'getenv("FOO")'
        assert res["sink"]["code"] == "system(cmd)"
        assert res["variable"] == "cmd"

@pytest.mark.asyncio
async def test_find_taint_flows_source_only(fake_services):
    # Setup mock for forward flow query (source -> sinks)
    services = fake_services

    # The new API uses source_location (file:line format) for forward analysis
    flow_result = QueryResult(
        success=True,
        data=[
            '[{"source": {"code": "getenv(\\"FOO\\")", "file": "core.c", "line": 10}, "sink": {"code": "system(cmd)", "file": "core.c", "line": 42}, "variable": "cmd", "path_length": 2}]'
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
        res_json = await client.call_tool(
            "find_taint_flows",
            {
                "codebase_hash": services["codebase_hash"],
                "source_location": "core.c:10",
                "timeout": 10,
            }
        )
        import json
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert res.get("mode") == "forward"
        assert "flows" in res
        assert isinstance(res["flows"], list)
        assert res["total"] == 1

@pytest.mark.asyncio
async def test_find_taint_flows_sink_only_backward(fake_services):
    """Test that sink-only queries work for backward analysis"""
    services = fake_services

    # The new API uses sink_location (file:line format) for backward analysis
    flow_result = QueryResult(
        success=True,
        data=[
            '[{"source": {"code": "getenv(\\"FOO\\")", "file": "core.c", "line": 10}, "sink": {"code": "system(cmd)", "file": "core.c", "line": 42}, "variable": "cmd", "path_length": 2}]'
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
        res_json = await client.call_tool(
            "find_taint_flows",
            {
                "codebase_hash": services["codebase_hash"],
                "sink_location": "core.c:42",
                "timeout": 10,
            }
        )
        import json
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert res.get("mode") == "backward"
        assert "flows" in res
        assert isinstance(res["flows"], list)
        assert res["total"] == 1

