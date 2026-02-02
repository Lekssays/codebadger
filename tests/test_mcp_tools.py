"""
Tests for MCP tools
"""

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
                assert "cpg_path" in result_dict
                assert result_dict["joern_port"] == 2000

    @pytest.mark.asyncio
    async def test_get_cpg_status_exists(self, mock_services):
        """Test getting CPG status when CPG exists"""
        from src.tools.core_tools import register_core_tools
        
        # Set up existing codebase with metadata
        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash="553642871dd4251d",
            source_type="github",
            source_path="https://github.com/test/repo",
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
                assert "cpg_path" in result_dict
                assert result_dict["container_codebase_path"] == "/playground/codebases/553642871dd4251d"
                assert result_dict["container_cpg_path"] == "/playground/cpgs/553642871dd4251d/cpg.bin"

    @pytest.mark.asyncio
    async def test_get_cpg_status_not_found(self, mock_services):
        """Test getting CPG status when CPG doesn't exist"""
        from src.tools.core_tools import register_core_tools
        
        mock_services["codebase_tracker"].get_codebase.return_value = None

        mcp = FastMCP("TestServer")
        register_core_tools(mcp, mock_services)

        async with Client(mcp) as client:
            result = await client.call_tool("get_cpg_status", {"codebase_hash": "nonexistent"})
            import json
            result_dict = json.loads(result.content[0].text)

            assert result_dict["codebase_hash"] == "nonexistent"
            assert result_dict["status"] == "not_found"

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
