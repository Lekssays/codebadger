"""
Tests for MCP tools
"""

import asyncio
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from src.models import CodebaseInfo, Config, QueryResult
from src.services.codebase_tracker import CodebaseTracker
from src.services.cpg_generator import CPGGenerator
from src.services.git_manager import GitManager
from src.tools.mcp_tools import register_tools


from fastmcp import FastMCP, Client


@pytest.fixture
def mock_services():
    """Create mock services for testing"""
    # Mock git manager
    git_manager = MagicMock(spec=GitManager)

    # Mock CPG generator
    cpg_generator = MagicMock(spec=CPGGenerator)

    # Mock codebase tracker
    codebase_tracker = MagicMock(spec=CodebaseTracker)
    codebase_tracker.save_codebase.return_value = CodebaseInfo(
        codebase_hash="553642871dd4251d",
        source_type="github",
        source_path="https://github.com/test/repo",
        language="c",
        cpg_path="/tmp/test.cpg"
    )
    codebase_tracker.get_codebase.return_value = CodebaseInfo(
        codebase_hash="553642871dd4251d",
        source_type="github",
        source_path="https://github.com/test/repo",
        language="c",
        cpg_path="/tmp/test.cpg"
    )

    # Mock query executor
    query_executor = MagicMock()
    query_executor.execute_query.return_value = QueryResult(
        success=True,
        data=[{"_1": "main", "_2": "function", "_3": "void main()", "_4": "main.c", "_5": 1}],
        row_count=1
    )

    # Mock config
    config = Config()

    # Mock code browsing service
    code_browsing_service = MagicMock()
    code_browsing_service.list_methods.return_value = {"success": True, "methods": []}
    code_browsing_service.list_files.return_value = "test_codebase/"
    code_browsing_service.run_query.return_value = {"success": True, "data": [], "row_count": 0}

    # Mock joern server manager
    joern_server_manager = MagicMock()
    joern_server_manager.get_server_port.return_value = 8080

    return {
        "git_manager": git_manager,
        "cpg_generator": cpg_generator,
        "codebase_tracker": codebase_tracker,
        "query_executor": query_executor,
        "config": config,
        "code_browsing_service": code_browsing_service,
        "joern_server_manager": joern_server_manager,
    }


@pytest.fixture
def temp_workspace():
    """Create a temporary workspace directory"""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create playground structure
        playground = os.path.join(temp_dir, "playground")
        os.makedirs(os.path.join(playground, "cpgs", "test1234567890123456"))
        os.makedirs(os.path.join(playground, "codebases", "test1234567890123456"))

        # Create a fake CPG file
        cpg_path = os.path.join(playground, "cpgs", "test1234567890123456", "cpg.bin")
        with open(cpg_path, "w") as f:
            f.write("fake cpg")

        yield temp_dir


class TestMCPTools:
    """Test MCP tools functionality"""

    def test_code_browsing_service_escapes_list_methods_query(self, mock_services):
        """Structured code-browsing queries should escape Scala string literals."""
        from src.services.code_browsing_service import CodeBrowsingService

        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=True,
            data=[],
            row_count=0,
        )
        service = CodeBrowsingService(
            codebase_tracker=mock_services["codebase_tracker"],
            query_executor=mock_services["query_executor"],
        )

        service.list_methods(
            "553642871dd4251d",
            name_pattern='main"; cpg.call.l //',
        )

        rendered_query = mock_services["query_executor"].execute_query.call_args.kwargs["query"]
        assert 'cpg.method.isExternal(false).name("main\\"; cpg.call.l //")' in rendered_query

    @pytest.mark.asyncio
    async def test_generate_cpg_github_success(self, mock_services, temp_workspace):
        """Test successful CPG generation from GitHub"""
        # Import core_tools to register the tools
        from src.tools.core_tools import register_core_tools
        
        with patch("src.tools.core_tools.os.path.abspath", return_value=temp_workspace), \
             patch("src.tools.core_tools.os.path.dirname", return_value=temp_workspace), \
             patch("src.tools.core_tools.os.path.join", side_effect=os.path.join), \
             patch("src.tools.core_tools.os.makedirs"), \
             patch("src.tools.core_tools.shutil.copytree"), \
             patch("src.tools.core_tools.shutil.copy2"):

            mcp = FastMCP("TestServer")
            register_core_tools(mcp, mock_services)

            # Mock the git clone
            mock_services["git_manager"].clone_repository.return_value = None

            # Call the tool using Client
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "generate_cpg",
                    {
                        "source_type": "github",
                        "source_path": "https://github.com/test/repo",
                        "language": "c"
                    }
                )

                # extract data from CallToolResult
                data = result.content[0].text
                import json
                result_dict = json.loads(data)

                # Now it returns "generating" status immediately
                assert "codebase_hash" in result_dict
                assert result_dict["status"] == "generating"
                assert result_dict["source_type"] == "github"

    @pytest.mark.asyncio
    async def test_generate_cpg_cached(self, mock_services, temp_workspace):
        """Test CPG generation when CPG already exists"""
        from src.tools.core_tools import register_core_tools
        
        # Set up existing codebase in tracker
        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash="553642871dd4251d",
            source_type="github",
            source_path="https://github.com/test/repo",
            language="c",
            cpg_path=os.path.join(temp_workspace, "playground/cpgs/test/cpg.bin"),
            joern_port=2000,
            metadata={"status": "ready"}
        )
        
        with patch("src.tools.core_tools.os.path.abspath", return_value=temp_workspace), \
             patch("src.tools.core_tools.os.path.dirname", return_value=temp_workspace), \
             patch("src.tools.core_tools.os.path.join", side_effect=os.path.join), \
             patch("src.tools.core_tools.os.path.exists", return_value=True):

            mcp = FastMCP("TestServer")
            register_core_tools(mcp, mock_services)

            # Call the tool using Client
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "generate_cpg",
                    {
                        "source_type": "github",
                        "source_path": "https://github.com/test/repo",
                        "language": "c"
                    }
                )
                
                # import json
                # data = result.content[0].text
                # result_dict = json.loads(data)
                # The result object from FastMCP might be different if it handles JSON parsing automatically or wrapped
                # FastMCP Client.call_tool returns CallToolResult. 
                # Let's assume we need to parse content.
                
                import json
                result_dict = json.loads(result.content[0].text)

                assert result_dict["status"] == "ready"
                assert result_dict["cpg_path"] == "<redacted:host-path>"
                assert result_dict["joern_port"] == 2000

    @pytest.mark.asyncio
    async def test_generate_cpg_cached_loading_does_not_schedule_duplicate_restart(self, mock_services, temp_workspace):
        """A cached codebase already loading should not enqueue a second restart."""
        from src.tools.core_tools import register_core_tools

        codebase_hash = "553642871dd4251d"
        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash=codebase_hash,
            source_type="local",
            source_path="/Users/private/test-repo",
            language="c",
            cpg_path=os.path.join(temp_workspace, "playground/cpgs/test/cpg.bin"),
            joern_port=2000,
            metadata={
                "status": "loading",
                "container_cpg_path": f"/playground/cpgs/{codebase_hash}/cpg.bin",
            },
        )
        mock_services["joern_server_manager"].is_server_running.return_value = False
        pending_restart = asyncio.get_running_loop().create_future()
        mock_services["restart_tasks"] = {codebase_hash: pending_restart}

        with patch("src.tools.core_tools.os.path.abspath", return_value=temp_workspace), \
             patch("src.tools.core_tools.os.path.dirname", return_value=temp_workspace), \
             patch("src.tools.core_tools.os.path.join", side_effect=os.path.join), \
             patch("src.tools.core_tools.os.path.exists", return_value=True), \
               patch("src.tools.core_tools.get_cpg_cache_key", return_value=codebase_hash), \
               patch("src.tools.core_tools._schedule_restart_server_task") as schedule_restart:

            mcp = FastMCP("TestServer")
            register_core_tools(mcp, mock_services)

            async with Client(mcp) as client:
                result = await client.call_tool(
                    "generate_cpg",
                    {
                        "source_type": "local",
                        "source_path": "/Users/private/test-repo",
                        "language": "c"
                    }
                )

                import json
                result_dict = json.loads(result.content[0].text)

                assert result_dict["status"] == "loading"
                assert "already in progress" in result_dict["message"]
                schedule_restart.assert_not_called()

            pending_restart.cancel()

    @pytest.mark.asyncio
    async def test_generate_cpg_local_copy_error_redacts_host_path(self, mock_services, tmp_path):
        """Local copy failures should not echo host paths back to the client."""
        from src.tools.core_tools import register_core_tools

        source_dir = tmp_path / "private-repo"
        source_dir.mkdir()
        mock_services["codebase_tracker"].get_codebase.return_value = None

        with patch("src.tools.core_tools.resolve_host_path", return_value=str(source_dir)), \
             patch("src.tools.core_tools._get_git_commit_hash", return_value=None), \
             patch("src.tools.core_tools.os.path.abspath", return_value=str(tmp_path)), \
             patch("src.tools.core_tools.os.path.dirname", return_value=str(tmp_path)), \
             patch("src.tools.core_tools.os.path.join", side_effect=os.path.join), \
             patch("src.tools.core_tools.os.makedirs"), \
             patch("src.tools.core_tools.os.listdir", side_effect=OSError(f"permission denied: {source_dir}")):

            mcp = FastMCP("TestServer")
            register_core_tools(mcp, mock_services)

            async with Client(mcp) as client:
                result = await client.call_tool(
                    "generate_cpg",
                    {
                        "source_type": "local",
                        "source_path": str(source_dir),
                        "language": "c"
                    }
                )

                import json
                result_dict = json.loads(result.content[0].text)

                assert result_dict["success"] is False
                assert result_dict["error"] == "Failed to copy local source directory"
                assert str(source_dir) not in result_dict["error"]

    @pytest.mark.asyncio
    async def test_generate_cpg_rejects_playground_self_inclusion(self, mock_services):
        """A local source that contains the playground must be refused, not copied.

        Regression for the outage where a cell passed CodeBadger's own dir (which
        contains playground/) as source: the recursive copy + on-loop size walk hung
        the entire MCP. The guard must reject it before any copy.
        """
        import src.tools.core_tools as core_tools
        from src.tools.core_tools import register_core_tools
        import json

        mock_services["codebase_tracker"].get_codebase.return_value = None
        # The real playground dir the guard derives from __file__, and its parent
        # (an ancestor) — analyzing the parent would recursively include playground.
        playground = os.path.abspath(
            os.path.join(os.path.dirname(core_tools.__file__), "..", "..", "playground")
        )
        ancestor = os.path.dirname(playground)

        with patch("src.tools.core_tools.resolve_host_path", return_value=ancestor), \
             patch("src.tools.core_tools._get_git_commit_hash", return_value=None), \
             patch("src.tools.core_tools._scan_repo", return_value=(0, 0)), \
             patch("src.tools.core_tools._copy_local_source_tree") as copy_mock:

            mcp = FastMCP("TestServer")
            register_core_tools(mcp, mock_services)

            async with Client(mcp) as client:
                result = await client.call_tool(
                    "generate_cpg",
                    {"source_type": "local", "source_path": ancestor, "language": "c"},
                )
                result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is False
            assert "playground" in result_dict["error"].lower()
            # The bomb must never be staged.
            copy_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_generate_cpg_snippet_stages_pasted_code(self, mock_services, tmp_path):
        """A pasted snippet should be written into codebases/<hash> and queued."""
        from unittest.mock import AsyncMock
        from src.tools.core_tools import register_core_tools

        codebase_hash = "abc1234567890123"
        code = "int main() { int a[2]; a[5] = 1; return 0; }"
        mock_services["codebase_tracker"].get_codebase.return_value = None
        mock_services["cpg_queue"] = MagicMock()
        mock_services["cpg_queue"].submit = AsyncMock(return_value="queued")

        with patch("src.tools.core_tools.os.path.abspath", return_value=str(tmp_path)), \
             patch("src.tools.core_tools.os.path.dirname", return_value=str(tmp_path)), \
             patch("src.tools.core_tools.os.path.join", side_effect=os.path.join), \
             patch("src.tools.core_tools.get_cpg_cache_key", return_value=codebase_hash):

            mcp = FastMCP("TestServer")
            register_core_tools(mcp, mock_services)

            async with Client(mcp) as client:
                result = await client.call_tool(
                    "generate_cpg",
                    {
                        "source_type": "snippet",
                        "source_path": "",
                        "language": "c",
                        "code": code,
                    },
                )

            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["status"] == "generating"
            mock_services["cpg_queue"].submit.assert_awaited_once()

            # The snippet was staged with the language-derived filename.
            snippet_file = tmp_path / "codebases" / codebase_hash / "snippet.c"
            assert snippet_file.read_text() == code

            # Persisted as a snippet source.
            save_kwargs = mock_services["codebase_tracker"].save_codebase.call_args.kwargs
            assert save_kwargs["source_type"] == "snippet"

    @pytest.mark.asyncio
    async def test_generate_cpg_snippet_requires_code(self, mock_services, tmp_path):
        """source_type='snippet' without code returns a validation error, not a crash."""
        from src.tools.core_tools import register_core_tools

        mock_services["codebase_tracker"].get_codebase.return_value = None

        mcp = FastMCP("TestServer")
        register_core_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool(
                "generate_cpg",
                {"source_type": "snippet", "source_path": "", "language": "c"},
            )

        import json
        result_dict = json.loads(result.content[0].text)
        assert result_dict["success"] is False
        # Helpful, actionable message telling the LLM how to supply the code.
        err = result_dict["error"]
        assert "no snippet code" in err.lower() and "<code language=" in err

    @pytest.mark.asyncio
    async def test_generate_cpg_local_disabled_in_chat_deploy(self, mock_services, tmp_path):
        """When chat_deploy is on, source_type='local' is refused with guidance."""
        from src.tools.core_tools import register_core_tools

        mock_services["config"].server.chat_deploy = True
        mock_services["codebase_tracker"].get_codebase.return_value = None

        mcp = FastMCP("TestServer")
        register_core_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool(
                "generate_cpg",
                {"source_type": "local", "source_path": str(tmp_path), "language": "c"},
            )

        import json
        result_dict = json.loads(result.content[0].text)
        assert result_dict["success"] is False
        err = result_dict["error"]
        assert "disabled" in err.lower()
        # Steer the LLM to the allowed alternatives.
        assert "github" in err.lower() and "snippet" in err.lower()

    @pytest.mark.asyncio
    async def test_get_cpg_status_exists(self, mock_services):
        """Test getting CPG status when CPG exists"""
        from src.tools.core_tools import register_core_tools
        
        # Set up existing codebase with metadata
        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash="553642871dd4251d",
            source_type="local",
            source_path="/Users/private/test-repo",
            language="c",
            cpg_path="/tmp/test.cpg",
            joern_port=2000,
            metadata={
                "status": "ready",
                "container_codebase_path": "/playground/codebases/553642871dd4251d",
                "container_cpg_path": "/playground/cpgs/553642871dd4251d/cpg.bin"
            }
        )
        
        mcp = FastMCP("TestServer")
        register_core_tools(mcp, mock_services)

        with patch("os.path.exists", return_value=True):
            async with Client(mcp) as client:
                result = await client.call_tool("get_cpg_status", {"codebase_hash": "553642871dd4251d"})
                
                import json
                result_dict = json.loads(result.content[0].text)

                assert result_dict["codebase_hash"] == "553642871dd4251d"
                assert result_dict["status"] == "ready"
                assert result_dict["cpg_path"] == "<redacted:host-path>"
                assert result_dict["source_path"] == "<redacted:local-source>"
                assert result_dict["container_codebase_path"] == "<redacted:container-path>"
                assert result_dict["container_cpg_path"] == "<redacted:container-path>"

    @pytest.mark.asyncio
    async def test_get_cpg_status_not_found(self, mock_services):
        """Test getting CPG status when CPG doesn't exist (valid-format but unknown hash)"""
        from src.tools.core_tools import register_core_tools

        mock_services["codebase_tracker"].get_codebase.return_value = None
        unknown_hash = "0123456789abcdef"

        mcp = FastMCP("TestServer")
        register_core_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool("get_cpg_status", {"codebase_hash": unknown_hash})
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["codebase_hash"] == unknown_hash
            assert result_dict["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_get_cpg_status_rejects_malformed_hash(self, mock_services):
        """A malformed codebase_hash is rejected by validation, not treated as not_found."""
        from src.tools.core_tools import register_core_tools

        mcp = FastMCP("TestServer")
        register_core_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool("get_cpg_status", {"codebase_hash": "nonexistent"})
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is False
            assert "16-character hex" in result_dict["error"]

    @pytest.mark.asyncio
    async def test_remove_cpg_rejects_malformed_hash(self, mock_services):
        """remove_cpg validates the hash before any DB/filesystem action."""
        from src.tools.core_tools import register_core_tools

        mcp = FastMCP("TestServer")
        register_core_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool(
                "remove_cpg", {"codebase_hash": "../../etc", "delete_files": True}
            )
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is False
            assert "16-character hex" in result_dict["error"]
            mock_services["codebase_tracker"].get_codebase.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_methods_success(self, mock_services):
        """Test listing methods successfully"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool("list_methods", {"codebase_hash": "553642871dd4251d"})
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is True
            assert "methods" in result_dict
            assert isinstance(result_dict["methods"], list)

    @pytest.mark.asyncio
    async def test_run_cpgql_query_success(self, mock_services):
        """Test running CPGQL query successfully"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        # Patch the query_executor to return a structured QueryResult
        from src.models import QueryResult
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=True,
            data=["result"],
            row_count=1,
        )

        async with Client(mcp) as client:
            result = await client.call_tool("run_cpgql_query", {"codebase_hash": "553642871dd4251d", "query": "cpg.method"})
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is True
            assert result_dict["data"] == ["result"]

    @pytest.mark.asyncio
    async def test_run_cpgql_query_invalid(self, mock_services):
        """Test running invalid CPGQL query"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        from src.models import QueryResult
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=False,
            error="Invalid query syntax",
            data=[],
            row_count=0,
        )

        async with Client(mcp) as client:
            result = await client.call_tool("run_cpgql_query", {"codebase_hash": "553642871dd4251d", "query": "invalid query"})
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is False
            assert result_dict["error"] == "Invalid query syntax"

    @pytest.mark.asyncio
    async def test_run_cpgql_query_blocks_dangerous_query(self, mock_services):
        """The security blocklist is enforced on the raw-query path, before execution."""
        from src.tools.code_browsing_tools import register_code_browsing_tools

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool(
                "run_cpgql_query",
                {
                    "codebase_hash": "553642871dd4251d",
                    "query": 'scala.io.Source.fromFile("/etc/passwd").mkString',
                },
            )
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is False
            assert "dangerous operation" in result_dict["error"]
            # Blocked before ever reaching the executor.
            mock_services["query_executor"].execute_query.assert_not_called()

    @pytest.mark.asyncio
    async def test_run_cpgql_query_surfaces_truncation(self, mock_services):
        """A truncated QueryResult is flagged to the client."""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        from src.models import QueryResult

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=True, data=["x"], row_count=1, truncated=True
        )

        async with Client(mcp) as client:
            result = await client.call_tool(
                "run_cpgql_query",
                {"codebase_hash": "553642871dd4251d", "query": "cpg.method.name.l"},
            )
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is True
            assert result_dict["truncated"] is True
            assert "truncation_note" in result_dict

    @pytest.mark.asyncio
    async def test_get_codebase_summary_success(self, mock_services):
        """Test getting codebase summary successfully"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        # Mock the combined stats query result (single query now)
        # The implementation expects a JSON string or dict with these fields
        import json
        summary_data = {
            "success": True,
            "language": "c",
            "total_files": 5,
            "total_methods": 10,
            "user_defined_methods": 8,
            "total_calls": 15,
            "total_literals": 20
        }
        
        mock_result = QueryResult(
            success=True,
            data=[json.dumps(summary_data)],  # Return as JSON string like Joern would
            row_count=1
        )

        mock_services["query_executor"].execute_query.return_value = mock_result

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool("get_codebase_summary", {"codebase_hash": "553642871dd4251d"})
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is True
            assert "summary" in result_dict
            assert result_dict["summary"]["language"] == "c"
            assert result_dict["summary"]["total_files"] == 5
            assert result_dict["summary"]["total_methods"] == 10

    @pytest.mark.asyncio
    async def test_list_files_local_tree_default(self, mock_services, tmp_path):
        """Test listing files as a tree for a local codebase with pagination"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        from src.models import CodebaseInfo

        # Build a playground-like source tree under a temp dir
        source_dir = tmp_path / "test_codebase"
        source_dir.mkdir()

        # create a subdir with 25 files
        subdir = source_dir / "many_files"
        subdir.mkdir()
        for i in range(25):
            f = subdir / f"file_{i:02d}.txt"  # Use zero-padded names for consistent sorting
            f.write_text(f"content {i}")

        # Create nested directories
        nested_dir = subdir / "nested"
        nested_dir.mkdir()
        for i in range(3):
            f = nested_dir / f"nfile_{i}.txt"
            f.write_text(f"nested {i}")

        # Configure codebase tracker to return local source dir
        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash="553642871dd4251d",
            source_type="local",
            source_path=str(source_dir),
            language="python",
            cpg_path=None,
        )

        # Use a real CodeBrowsingService instance instead of MagicMock to test file system behavior
        from src.services.code_browsing_service import CodeBrowsingService
        real_cb_service = CodeBrowsingService(codebase_tracker=mock_services["codebase_tracker"], query_executor=mock_services["query_executor"])
        mock_services["code_browsing_service"] = real_cb_service

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool("list_files", {"codebase_hash": "553642871dd4251d"})
            # Result is now a plain text string, not JSON
            tree_text = result.content[0].text

            # Check that tree contains the directory
            assert "many_files/" in tree_text
            # Check that all files are present (25 files + 3 nested = 28 items, under 100 limit)
            assert "file_24.txt" in tree_text
            assert "nested/" in tree_text
            assert "nfile_2.txt" in tree_text
            # Check tree formatting characters are present
            assert "├──" in tree_text or "└──" in tree_text

    @pytest.mark.asyncio
    async def test_list_files_pagination(self, mock_services, tmp_path):
        """Test listing files with pagination for large directories"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        from src.models import CodebaseInfo

        # Build a source dir with 150 files (more than 100 limit)
        source_dir = tmp_path / "test_codebase_large"
        source_dir.mkdir()

        # Create 150 files directly in source_dir
        for i in range(150):
            f = source_dir / f"file_{i:03d}.txt"
            f.write_text(f"content {i}")

        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash="553642871dd4251f",
            source_type="local",
            source_path=str(source_dir),
            language="python",
            cpg_path=None,
        )

        from src.services.code_browsing_service import CodeBrowsingService
        real_cb_service = CodeBrowsingService(codebase_tracker=mock_services["codebase_tracker"], query_executor=mock_services["query_executor"])
        mock_services["code_browsing_service"] = real_cb_service

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        async with Client(mcp) as client:
            # Test page 1
            result = await client.call_tool("list_files", {"codebase_hash": "553642871dd4251f"})
            tree_text = result.content[0].text

            # Tree should start with the dir name
            assert tree_text.startswith("test_codebase_large/")
            # First 100 files should be present
            assert "file_000.txt" in tree_text
            assert "file_099.txt" in tree_text
            # File 100 should NOT be present on page 1
            assert "file_100.txt" not in tree_text
            # Pagination info should be shown
            assert "Page 1/2" in tree_text
            assert "Showing 100 of 150 items" in tree_text
            assert "Use page=2 to see more" in tree_text

            # Test page 2
            result2 = await client.call_tool("list_files", {"codebase_hash": "553642871dd4251f", "page": 2})
            tree_text2 = result2.content[0].text

            # File 100-149 should be present on page 2
            assert "file_100.txt" in tree_text2
            assert "file_149.txt" in tree_text2
            # Pagination info should show page 2
            assert "Page 2/2" in tree_text2
            assert "Showing 50 of 150 items" in tree_text2
            # No "Use page=3" since this is the last page
            assert "Use page=3" not in tree_text2

    @pytest.mark.asyncio
    async def test_list_files_rejects_sibling_escape(self, mock_services, tmp_path):
        """local_path must not escape to a sibling directory that shares the same prefix."""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        from src.models import CodebaseInfo
        from src.services.code_browsing_service import CodeBrowsingService

        source_dir = tmp_path / "test_codebase"
        source_dir.mkdir()
        (source_dir / "inside.txt").write_text("inside")

        sibling_dir = tmp_path / "test_codebase-escape"
        sibling_dir.mkdir()
        (sibling_dir / "outside.txt").write_text("outside")

        codebase_hash = "553642871dd4252a"
        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash=codebase_hash,
            source_type="local",
            source_path=str(source_dir),
            language="python",
            cpg_path=None,
        )

        mock_services["code_browsing_service"] = CodeBrowsingService(
            codebase_tracker=mock_services["codebase_tracker"],
            query_executor=mock_services["query_executor"],
        )

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool(
                "list_files",
                {
                    "codebase_hash": codebase_hash,
                    "local_path": "../test_codebase-escape",
                },
            )

            text_result = result.content[0].text
            assert text_result.startswith("Error: ")
            assert "Path traversal attempt detected" in text_result
            assert str(source_dir) not in text_result
            assert str(sibling_dir) not in text_result

    @pytest.mark.asyncio
    async def test_get_method_source_uses_sandbox_snapshot(self, mock_services, tmp_path):
        """Method source should be read from the sandbox snapshot, not the live checkout."""
        from src.tools.code_browsing_tools import register_code_browsing_tools

        codebase_hash = "553642871dd4252b"
        playground_dir = tmp_path / "playground"
        snapshot_dir = playground_dir / "codebases" / codebase_hash / "src"
        snapshot_dir.mkdir(parents=True)
        (snapshot_dir / "thing.c").write_text("int sandbox_version() { return 7; }\n")

        live_dir = tmp_path / "live-checkout" / "src"
        live_dir.mkdir(parents=True)
        (live_dir / "thing.c").write_text("int live_version() { return 9; }\n")

        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash=codebase_hash,
            source_type="local",
            source_path=str(live_dir.parent),
            language="c",
            cpg_path="/tmp/test.cpg",
        )
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=True,
            data=[{"_1": "sandbox_version", "_2": "src/thing.c", "_3": 1, "_4": 1}],
            row_count=1,
        )

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        with patch("src.tools.code_browsing_tools._get_playground_path", return_value=str(playground_dir)):
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "get_method_source",
                    {"codebase_hash": codebase_hash, "method_name": "sandbox_version"},
                )

        import json
        result_dict = json.loads(result.content[0].text)

        assert result_dict["success"] is True
        assert result_dict["methods"][0]["code"] == "int sandbox_version() { return 7; }\n"
        assert "live_version" not in result_dict["methods"][0]["code"]

    @pytest.mark.asyncio
    async def test_get_method_source_redacts_read_errors(self, mock_services, tmp_path):
        """Method source read failures should not expose raw filesystem errors."""
        from src.tools.code_browsing_tools import register_code_browsing_tools

        codebase_hash = "553642871dd4252d"
        playground_dir = tmp_path / "playground"
        snapshot_dir = playground_dir / "codebases" / codebase_hash / "src"
        snapshot_dir.mkdir(parents=True)
        target_file = snapshot_dir / "thing.c"
        target_file.write_text("int hidden() { return 0; }\n")

        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash=codebase_hash,
            source_type="local",
            source_path=str(tmp_path / "live-checkout"),
            language="c",
            cpg_path="/tmp/test.cpg",
        )
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=True,
            data=[{"_1": "hidden", "_2": "src/thing.c", "_3": 1, "_4": 1}],
            row_count=1,
        )

        real_open = open

        def failing_open(path, *args, **kwargs):
            if os.path.realpath(path) == os.path.realpath(target_file):
                raise OSError(f"permission denied: {target_file}")
            return real_open(path, *args, **kwargs)

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        with patch("src.tools.code_browsing_tools._get_playground_path", return_value=str(playground_dir)), \
             patch("builtins.open", side_effect=failing_open):
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "get_method_source",
                    {"codebase_hash": codebase_hash, "method_name": "hidden"},
                )

        import json
        result_dict = json.loads(result.content[0].text)

        assert result_dict["success"] is True
        assert result_dict["methods"][0]["code"] == "// Error reading source file"
        assert str(target_file) not in result_dict["methods"][0]["code"]

    @pytest.mark.asyncio
    async def test_get_code_snippet_uses_sandbox_snapshot(self, mock_services, tmp_path):
        """Code snippets should be read from the sandbox snapshot, not the live checkout."""
        from src.tools.code_browsing_tools import register_code_browsing_tools

        codebase_hash = "553642871dd4252c"
        playground_dir = tmp_path / "playground"
        snapshot_dir = playground_dir / "codebases" / codebase_hash / "src"
        snapshot_dir.mkdir(parents=True)
        (snapshot_dir / "main.c").write_text("int sandbox_main() { return 1; }\n")

        live_dir = tmp_path / "live-checkout" / "src"
        live_dir.mkdir(parents=True, exist_ok=True)
        (live_dir / "main.c").write_text("int live_main() { return 2; }\n")

        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash=codebase_hash,
            source_type="local",
            source_path=str(live_dir.parent),
            language="c",
            cpg_path="/tmp/test.cpg",
        )

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        with patch("src.tools.code_browsing_tools._get_playground_path", return_value=str(playground_dir)):
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "get_code_snippet",
                    {
                        "codebase_hash": codebase_hash,
                        "filename": "src/main.c",
                        "start_line": 1,
                        "end_line": 1,
                    },
                )

        import json
        result_dict = json.loads(result.content[0].text)

        assert result_dict["success"] is True
        assert result_dict["code"] == "int sandbox_main() { return 1; }\n"
        assert "live_main" not in result_dict["code"]

    @pytest.mark.asyncio
    async def test_get_code_snippet_redacts_read_errors(self, mock_services, tmp_path):
        """Code snippet read failures should not expose raw filesystem errors."""
        from src.tools.code_browsing_tools import register_code_browsing_tools

        codebase_hash = "553642871dd4252e"
        playground_dir = tmp_path / "playground"
        snapshot_dir = playground_dir / "codebases" / codebase_hash / "src"
        snapshot_dir.mkdir(parents=True)
        target_file = snapshot_dir / "main.c"
        target_file.write_text("int hidden_main() { return 0; }\n")

        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash=codebase_hash,
            source_type="local",
            source_path=str(tmp_path / "live-checkout"),
            language="c",
            cpg_path="/tmp/test.cpg",
        )

        real_open = open

        def failing_open(path, *args, **kwargs):
            if os.path.realpath(path) == os.path.realpath(target_file):
                raise OSError(f"permission denied: {target_file}")
            return real_open(path, *args, **kwargs)

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        with patch("src.tools.code_browsing_tools._get_playground_path", return_value=str(playground_dir)), \
             patch("builtins.open", side_effect=failing_open):
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "get_code_snippet",
                    {
                        "codebase_hash": codebase_hash,
                        "filename": "src/main.c",
                        "start_line": 1,
                        "end_line": 1,
                    },
                )

        import json
        result_dict = json.loads(result.content[0].text)

        assert result_dict["success"] is False
        assert result_dict["error"] == "Failed to read source file"
        assert str(target_file) not in result_dict["error"]

    @pytest.mark.asyncio
    async def test_get_cfg_success(self, mock_services):
        """Test getting CFG for a method successfully"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        # Mock query result with CFG as text
        expected_output = """Control Flow Graph for test_func
============================================================
Nodes:
  [1001] ControlStructure: if (x > 0)
  [1002] Return: return x

Edges:
  [1001] -> [1002] [Label: TRUE]
"""
        
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=True,
            data=[expected_output],
            row_count=1
        )

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool("get_cfg", {
                "codebase_hash": "553642871dd4251d",
                "method_name": "test_func"
            })
            
            # Result is now a plain text string
            text_result = result.content[0].text
            
            assert "Control Flow Graph for test_func" in text_result
            assert "Nodes:" in text_result
            assert "[1001] ControlStructure: if (x > 0)" in text_result
            assert "Edges:" in text_result
            assert "[1001] -> [1002] [Label: TRUE]" in text_result

    @pytest.mark.asyncio
    async def test_get_type_definition_success(self, mock_services):
        """Test getting type definition with members"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        # Mock query result with type info
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=True,
            data=[
                {
                    "_1": "Buffer",
                    "_2": "struct Buffer",
                    "_3": "buffer.h",
                    "_4": 10,
                    "_5": [
                        {"name": "data", "type": "char*"},
                        {"name": "size", "type": "int"},
                    ]
                }
            ],
            row_count=1
        )

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool("get_type_definition", {
                "codebase_hash": "553642871dd4251d",
                "type_name": "Buffer"
            })
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is True
            assert "types" in result_dict
            assert len(result_dict["types"]) == 1
            assert result_dict["types"][0]["name"] == "Buffer"
            assert len(result_dict["types"][0]["members"]) == 2

    @pytest.mark.asyncio
    async def test_get_macro_expansion_success(self, mock_services):
        """Test checking for macro expansions"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        # Mock query result with call info including dispatch types
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=True,
            data=[
                {
                    "_1": "MAX",
                    "_2": "MAX(a, b)",
                    "_3": 42,
                    "_4": "utils.c",
                    "_5": "INLINED"
                },
                {
                    "_1": "printf",
                    "_2": "printf(msg)",
                    "_3": 43,
                    "_4": "utils.c",
                    "_5": "STATIC_DISPATCH"
                }
            ],
            row_count=2
        )

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool("get_macro_expansion", {
                "codebase_hash": "553642871dd4251d",
                "filename": "utils.c"
            })
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["success"] is True
            assert "calls" in result_dict
            assert len(result_dict["calls"]) == 2
            # MAX should be detected as macro (INLINED)
            assert result_dict["calls"][0]["is_macro"] is True
            # printf should not be a macro
            assert result_dict["calls"][1]["is_macro"] is False

    @pytest.mark.asyncio
    async def test_discover_fixed_vulnerabilities_success(self, mock_services, tmp_path):
        """Test discovering vulnerability fixes from git history"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        from src.models import CodebaseInfo
        import subprocess

        # Create a temporary git repo with security-related commits
        playground_dir = tmp_path / "playground"
        repo_dir = playground_dir / "codebases" / "553642871dd4251d"
        repo_dir.mkdir(parents=True)

        # Initialize git repo
        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True, capture_output=True)

        # Create files and commit with security-related message
        (repo_dir / "parser.c").write_text("int parse() { return 0; }")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Fix buffer overflow in parser"], cwd=repo_dir, check=True, capture_output=True)

        # Another security commit
        (repo_dir / "auth.c").write_text("int auth() { return 1; }")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "CVE-2023-1234: Patch SQL injection"], cwd=repo_dir, check=True, capture_output=True)

        # Non-security commit
        (repo_dir / "README.md").write_text("# Test")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Update documentation"], cwd=repo_dir, check=True, capture_output=True)

        # Configure codebase tracker
        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash="553642871dd4251d",
            source_type="local",
            source_path=str(repo_dir),
            language="c",
            cpg_path="/tmp/test.cpg",
        )

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        with patch("src.tools.code_browsing_tools._get_playground_path", return_value=str(playground_dir)):
            async with Client(mcp) as client:
                result = await client.call_tool("discover_fixed_vulnerabilities", {
                    "codebase_hash": "553642871dd4251d",
                    "limit": 100
                })
                text_result = result.content[0].text

            # Should find security-related commits
            assert "Discovered Vulnerability Fixes" in text_result
            assert "buffer overflow" in text_result.lower()
            assert "CVE-2023-1234" in text_result
            # Should not include the documentation commit
            assert "Update documentation" not in text_result
            # Should show affected files
            assert "parser.c" in text_result or "auth.c" in text_result

    @pytest.mark.asyncio
    async def test_discover_fixed_vulnerabilities_no_matches(self, mock_services, tmp_path):
        """Test when no security commits are found"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        from src.models import CodebaseInfo
        import subprocess

        # Create a temporary git repo without security-related commits
        playground_dir = tmp_path / "playground"
        repo_dir = playground_dir / "codebases" / "553642871dd4251e"
        repo_dir.mkdir(parents=True)

        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True, capture_output=True)

        (repo_dir / "main.c").write_text("int main() { return 0; }")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)

        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash="553642871dd4251e",
            source_type="local",
            source_path=str(repo_dir),
            language="c",
            cpg_path="/tmp/test.cpg",
        )

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        with patch("src.tools.code_browsing_tools._get_playground_path", return_value=str(playground_dir)):
            async with Client(mcp) as client:
                result = await client.call_tool("discover_fixed_vulnerabilities", {
                    "codebase_hash": "553642871dd4251e"
                })
                text_result = result.content[0].text

            assert "No commits matching vulnerability patterns were found" in text_result
            assert "CPG-based tools for comprehensive security analysis" in text_result

    @pytest.mark.asyncio
    async def test_discover_fixed_vulnerabilities_no_git_repo(self, mock_services, tmp_path):
        """Test error handling when source is not a git repository"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        from src.models import CodebaseInfo

        # Create a directory without git
        playground_dir = tmp_path / "playground"
        source_dir = playground_dir / "codebases" / "553642871dd4251f"
        source_dir.mkdir(parents=True)
        (source_dir / "main.c").write_text("int main() { return 0; }")

        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash="553642871dd4251f",
            source_type="local",
            source_path=str(source_dir),
            language="c",
            cpg_path="/tmp/test.cpg",
        )

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        with patch("src.tools.code_browsing_tools._get_playground_path", return_value=str(playground_dir)):
            async with Client(mcp) as client:
                result = await client.call_tool("discover_fixed_vulnerabilities", {
                    "codebase_hash": "553642871dd4251f"
                })
                text_result = result.content[0].text

            assert "Error" in text_result
            assert "not a git repository" in text_result

    @pytest.mark.asyncio
    async def test_discover_fixed_vulnerabilities_uses_sandbox_snapshot(self, mock_services, tmp_path):
        """Git history analysis should use the sandbox snapshot instead of the original local path."""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        from src.models import CodebaseInfo
        import subprocess

        codebase_hash = "553642871dd4251a"
        playground_dir = tmp_path / "playground"
        repo_dir = playground_dir / "codebases" / codebase_hash
        repo_dir.mkdir(parents=True)

        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True, capture_output=True)

        (repo_dir / "parser.c").write_text("int parse() { return 0; }")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Fix buffer overflow in parser"], cwd=repo_dir, check=True, capture_output=True)

        original_source = tmp_path / "live-checkout"
        original_source.mkdir()
        (original_source / "main.c").write_text("int main() { return 0; }")

        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash=codebase_hash,
            source_type="local",
            source_path=str(original_source),
            language="c",
            cpg_path="/tmp/test.cpg",
        )

        mcp = FastMCP("TestServer")
        register_code_browsing_tools(mcp, mock_services)

        with patch("src.tools.code_browsing_tools._get_playground_path", return_value=str(playground_dir)):
            async with Client(mcp) as client:
                result = await client.call_tool("discover_fixed_vulnerabilities", {
                    "codebase_hash": codebase_hash,
                    "limit": 20
                })
                text_result = result.content[0].text

        assert "Discovered Vulnerability Fixes" in text_result
        assert "buffer overflow" in text_result.lower()


class TestCopyLocalSourceTree:
    """Unit tests for the off-loop local-source copy helper (path-race fix A)."""

    def test_copies_files_and_dirs(self, tmp_path):
        from src.tools.core_tools import _copy_local_source_tree
        src = tmp_path / "src"; (src / "sub").mkdir(parents=True)
        (src / "a.c").write_text("int a;")
        (src / "sub" / "b.c").write_text("int b;")
        dst = tmp_path / "dst"
        _copy_local_source_tree(str(src), str(dst))
        assert (dst / "a.c").read_text() == "int a;"
        assert (dst / "sub" / "b.c").read_text() == "int b;"

    def test_skips_symlink_escaping_source_root(self, tmp_path):
        import os
        from src.tools.core_tools import _copy_local_source_tree
        outside = tmp_path / "secret.txt"; outside.write_text("TOP SECRET")
        src = tmp_path / "src"; src.mkdir()
        (src / "ok.c").write_text("int ok;")
        os.symlink(str(outside), str(src / "leak"))   # escapes the source root
        dst = tmp_path / "dst"
        _copy_local_source_tree(str(src), str(dst))
        assert (dst / "ok.c").exists()
        assert not (dst / "leak").exists()            # escaping symlink not copied


class TestLargeProjectGuard:
    """generate_cpg large-project guard: configurable + toggleable (fix #2)."""

    @pytest.mark.asyncio
    async def test_warns_when_guard_on_and_over_threshold(self, mock_services, tmp_path):
        from src.tools.core_tools import register_core_tools
        mock_services["codebase_tracker"].get_codebase.return_value = None
        src = tmp_path / "src"; src.mkdir()
        # default config: guard on, thresholds 2000 MB / 2M LOC -> 3M LOC trips it
        with patch("src.tools.core_tools.resolve_host_path", return_value=str(src)), \
             patch("src.tools.core_tools._scan_repo", return_value=(3000, 3_000_000)):
            mcp = FastMCP("t"); register_core_tools(mcp, mock_services)
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "generate_cpg",
                    {"source_type": "local", "source_path": str(src), "language": "c"},
                )
            import json; d = json.loads(result.content[0].text)
            assert d["status"] == "large_project_warning"
            assert d["lines_of_code"] == 3_000_000

    @pytest.mark.asyncio
    async def test_guard_off_skips_warning_and_builds(self, mock_services, tmp_path):
        from unittest.mock import AsyncMock
        from src.tools.core_tools import register_core_tools
        mock_services["codebase_tracker"].get_codebase.return_value = None
        mock_services["config"].cpg.large_project_guard = False   # batch driver
        mock_services["cpg_queue"] = MagicMock()
        mock_services["cpg_queue"].submit = AsyncMock(return_value="queued")
        src = tmp_path / "src"; src.mkdir()
        with patch("src.tools.core_tools.resolve_host_path", return_value=str(src)), \
             patch("src.tools.core_tools._get_git_commit_hash", return_value=None), \
             patch("src.tools.core_tools._copy_local_source_tree"), \
             patch("src.tools.core_tools.os.path.abspath", return_value=str(tmp_path)), \
             patch("src.tools.core_tools.os.path.dirname", return_value=str(tmp_path)), \
             patch("src.tools.core_tools.os.path.join", side_effect=os.path.join):
            mcp = FastMCP("t"); register_core_tools(mcp, mock_services)
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "generate_cpg",
                    {"source_type": "local", "source_path": str(src), "language": "c"},
                )
            import json; d = json.loads(result.content[0].text)
            assert d["status"] == "generating"          # guard off -> built, not declined


class TestCpgBuildFailureLabeling:
    """Fix #4: failed CPG builds carry a labeled cause (OOM/TIMEOUT/BUILD_ERROR)."""

    def test_classifier_oom_by_exit_137(self):
        from src.tools.core_tools import _classify_cpg_build_failure
        code, msg = _classify_cpg_build_failure(137, "killed", 28)
        assert code == "OOM" and "-Xmx28G" in msg

    def test_classifier_oom_by_marker(self):
        from src.tools.core_tools import _classify_cpg_build_failure
        code, _ = _classify_cpg_build_failure(1, "x java.lang.OutOfMemoryError: Java heap space", 28)
        assert code == "OOM"

    def test_classifier_generic_build_error(self):
        from src.tools.core_tools import _classify_cpg_build_failure
        code, _ = _classify_cpg_build_failure(2, "parse error", 28)
        assert code == "BUILD_ERROR"

    def test_classifier_bounds_output(self):
        from src.tools.core_tools import _classify_cpg_build_failure
        _, msg = _classify_cpg_build_failure(1, "X" * 9000, 28)
        assert len(msg) < 2300   # frontend dump tail-bounded

    @pytest.mark.asyncio
    async def test_get_cpg_status_surfaces_failure_cause(self, mock_services):
        from src.tools.core_tools import register_core_tools
        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash="0123456789abcdef",
            source_type="local",
            source_path="/x",
            language="c",
            cpg_path=None,
            metadata={"status": "failed", "error_code": "OOM", "error": "ran out of memory"},
        )
        mcp = FastMCP("t"); register_core_tools(mcp, mock_services)
        async with Client(mcp) as client:
            result = await client.call_tool("get_cpg_status", {"codebase_hash": "0123456789abcdef"})
        import json; d = json.loads(result.content[0].text)
        assert d["status"] == "failed"
        assert d["error_code"] == "OOM"
        assert "memory" in d["error"]
