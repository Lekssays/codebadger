"""
Tests for the refactored get_program_slice function with bidirectional slicing support.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock
import uuid
import json

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

        # Return realistic bidirectional slice result
        return QueryResult(
            success=True,
            data=[json.dumps({
                "success": True,
                "target": {
                    "node_id": "12345678",
                    "name": "memcpy",
                    "code": "memcpy(&ret[0], prefix, lenp)",
                    "file": "tree.c",
                    "line": 195,
                    "method": "xmlBuildQName",
                    "arguments": ["&ret[0]", "prefix", "lenp"]
                },
                "backward_slice": {
                    "data_dependencies": [
                        {"variable": "ret", "line": 189, "code": "ret = xmlMalloc(lenn + lenp + 2)", "depends_on": ["lenn", "lenp"]},
                        {"variable": "lenp", "line": 184, "code": "lenp = strlen((char *) prefix)", "depends_on": ["prefix"]}
                    ],
                    "control_dependencies": [
                        {"line": 174, "type": "IF", "condition": "(ncname == NULL) || (len < 0)"},
                        {"line": 188, "type": "IF", "condition": "(memory == NULL) || ((size_t) len < lenn + lenp + 2)"}
                    ],
                    "parameters": [{"name": "prefix", "type": "xmlChar*", "position": 2}],
                    "locals": [{"name": "ret", "type": "xmlChar*", "line": 172}]
                },
                "forward_slice": {
                    "result_variable": "",
                    "propagations": [],
                    "control_affected": []
                },
                "summary": {
                    "direction": "both",
                    "max_depth": 5,
                    "backward_nodes": 4,
                    "forward_nodes": 0
                }
            })],
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

        return QueryResult(
            success=True,
            data=[json.dumps({
                "success": True,
                "target": {
                    "node_id": "87654321",
                    "name": "read",
                    "code": "read(fd, buffer, len)",
                    "file": "xmlIO.c",
                    "line": 797,
                    "method": "xmlFdRead",
                    "arguments": ["fd", "buffer", "len"]
                },
                "backward_slice": {},
                "forward_slice": {
                    "result_variable": "bytes",
                    "propagations": [
                        {"line": 798, "code": "bytes < 0", "type": "usage", "variable": "bytes"},
                        {"line": 809, "code": "ret += bytes", "type": "propagation", "variable": "bytes", "propagates_to": "ret"},
                        {"line": 810, "code": "buffer += bytes", "type": "propagation", "variable": "bytes", "propagates_to": "buffer"}
                    ],
                    "control_affected": [
                        {"line": 798, "type": "IF", "condition": "bytes < 0"},
                        {"line": 807, "type": "IF", "condition": "bytes == 0"}
                    ]
                },
                "summary": {
                    "direction": "forward",
                    "max_depth": 5,
                    "backward_nodes": 0,
                    "forward_nodes": 5
                }
            })],
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
        res_json = await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward",
            "max_depth": 5
        })
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert "target" in res
        assert res["target"]["name"] == "memcpy"
        assert res["target"]["line"] == 195
        assert "backward_slice" in res


@pytest.mark.asyncio
async def test_get_program_slice_forward(fake_services_forward):
    """Test forward slicing mode."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_forward)

    async with Client(mcp) as client:
        res_json = await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_forward["codebase_hash"],
            "location": "xmlIO.c:797:read",
            "direction": "forward",
            "max_depth": 5
        })
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert "target" in res
        assert res["target"]["name"] == "read"
        assert "forward_slice" in res
        assert res["forward_slice"]["result_variable"] == "bytes"
        assert len(res["forward_slice"]["propagations"]) > 0


@pytest.mark.asyncio
async def test_get_program_slice_bidirectional(fake_services_slice):
    """Test bidirectional (both) slicing mode."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_json = await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195",
            "direction": "both"
        })
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert "backward_slice" in res
        assert "forward_slice" in res
        assert "summary" in res
        assert res["summary"]["direction"] == "both"


@pytest.mark.asyncio
async def test_get_program_slice_with_node_id(fake_services_slice):
    """Test slicing using direct node ID."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_json = await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "node_id": "12345678",
            "direction": "backward"
        })
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        assert res["target"]["node_id"] == "12345678"


@pytest.mark.asyncio
async def test_get_program_slice_data_dependencies(fake_services_slice):
    """Test that data dependencies are correctly returned."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_json = await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward"
        })
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        deps = res["backward_slice"]["data_dependencies"]
        
        # Check we have dependencies
        assert len(deps) >= 2
        
        # Check dependency structure
        for dep in deps:
            assert "variable" in dep
            assert "line" in dep
            assert "code" in dep
            assert "depends_on" in dep


@pytest.mark.asyncio
async def test_get_program_slice_control_dependencies(fake_services_slice):
    """Test that control dependencies are correctly returned."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_json = await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "backward"
        })
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        ctrl_deps = res["backward_slice"]["control_dependencies"]
        
        # Should have control deps
        assert len(ctrl_deps) >= 1
        
        # Check structure
        for ctrl in ctrl_deps:
            assert "line" in ctrl
            assert "type" in ctrl
            assert "condition" in ctrl


@pytest.mark.asyncio
async def test_get_program_slice_depth_limiting(fake_services_slice):
    """Test that max_depth parameter is used in the query."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "both",
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
        res_json = await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195",
            "direction": "invalid"
        })
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is False
        assert "direction" in res["error"]["message"].lower()


@pytest.mark.asyncio
async def test_get_program_slice_missing_required_params(fake_services_slice):
    """Test that missing location and node_id is rejected."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_json = await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "direction": "both"
        })
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is False
        assert "node_id" in res["error"]["message"] or "location" in res["error"]["message"]


@pytest.mark.asyncio
async def test_get_program_slice_summary_counts(fake_services_slice):
    """Test that summary contains correct node counts."""
    mcp = FastMCP("TestServer")
    register_tools(mcp, fake_services_slice)

    async with Client(mcp) as client:
        res_json = await client.call_tool("get_program_slice", {
            "codebase_hash": fake_services_slice["codebase_hash"],
            "location": "tree.c:195:memcpy",
            "direction": "both"
        })
        res = json.loads(res_json.content[0].text)

        assert res.get("success") is True
        summary = res["summary"]
        
        assert "backward_nodes" in summary
        assert "forward_nodes" in summary
        assert "max_depth" in summary
        assert isinstance(summary["backward_nodes"], int)
        assert isinstance(summary["forward_nodes"], int)
