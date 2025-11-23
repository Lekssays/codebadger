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


class FakeMCP:
    """Fake MCP class for testing"""

    def __init__(self):
        self.registered = {}

    def tool(self):
        """Decorator to register tool functions"""
        def _decorator(func):
            self.registered[func.__name__] = func
            return func
        return _decorator


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
    code_browsing_service.list_files.return_value = {"success": True, "files": [], "total": 0}
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

            mcp = FakeMCP()
            register_core_tools(mcp, mock_services)

            func = mcp.registered.get("generate_cpg")
            assert func is not None

            # Mock the git clone
            mock_services["git_manager"].clone_repository.return_value = None

            # Call the tool (async now)
            result = await func(
                source_type="github",
                source_path="https://github.com/test/repo",
                language="c"
            )

            # Now it returns "generating" status immediately
            assert "codebase_hash" in result
            assert result["status"] == "generating"
            assert result["source_type"] == "github"

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

            mcp = FakeMCP()
            register_core_tools(mcp, mock_services)

            func = mcp.registered.get("generate_cpg")
            assert func is not None

            # Call the tool (async now)
            result = await func(
                source_type="github",
                source_path="https://github.com/test/repo",
                language="c"
            )

            assert result["status"] == "ready"
            assert "cpg_path" in result
            assert result["joern_port"] == 2000

    def test_get_cpg_status_exists(self, mock_services):
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
        
        mcp = FakeMCP()
        register_core_tools(mcp, mock_services)

        func = mcp.registered.get("get_cpg_status")
        assert func is not None

        with patch("os.path.exists", return_value=True):
            result = func(codebase_hash="553642871dd4251d")

        assert result["codebase_hash"] == "553642871dd4251d"
        assert result["status"] == "ready"
        assert "cpg_path" in result
        assert result["container_codebase_path"] == "/playground/codebases/553642871dd4251d"
        assert result["container_cpg_path"] == "/playground/cpgs/553642871dd4251d/cpg.bin"

    def test_get_cpg_status_not_found(self, mock_services):
        """Test getting CPG status when CPG doesn't exist"""
        from src.tools.core_tools import register_core_tools
        
        mock_services["codebase_tracker"].get_codebase.return_value = None

        mcp = FakeMCP()
        register_core_tools(mcp, mock_services)

        func = mcp.registered.get("get_cpg_status")
        assert func is not None

        result = func(codebase_hash="nonexistent")

        assert result["codebase_hash"] == "nonexistent"
        assert result["status"] == "not_found"

    def test_list_methods_success(self, mock_services):
        """Test listing methods successfully"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        mcp = FakeMCP()
        register_code_browsing_tools(mcp, mock_services)

        func = mcp.registered.get("list_methods")
        assert func is not None

        result = func(codebase_hash="553642871dd4251d")

        assert result["success"] is True
        assert "methods" in result
        assert isinstance(result["methods"], list)

    def test_run_cpgql_query_success(self, mock_services):
        """Test running CPGQL query successfully"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        mcp = FakeMCP()
        register_code_browsing_tools(mcp, mock_services)

        func = mcp.registered.get("run_cpgql_query")
        assert func is not None

        # Patch the query_executor to return a structured QueryResult
        from src.models import QueryResult
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=True,
            data=["result"],
            row_count=1,
        )

        result = func(codebase_hash="553642871dd4251d", query="cpg.method")

        assert result["success"] is True
        assert result["data"] == ["result"]

    def test_run_cpgql_query_invalid(self, mock_services):
        """Test running invalid CPGQL query"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        mcp = FakeMCP()
        register_code_browsing_tools(mcp, mock_services)

        func = mcp.registered.get("run_cpgql_query")
        assert func is not None

        from src.models import QueryResult
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=False,
            error="Invalid query syntax",
            data=[],
            row_count=0,
        )

        result = func(codebase_hash="553642871dd4251d", query="invalid query")

        assert result["success"] is False
        assert result["error"] == "Invalid query syntax"

    def test_get_codebase_summary_success(self, mock_services):
        """Test getting codebase summary successfully"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        
        # Mock the metadata query
        meta_result = QueryResult(
            success=True,
            data=[{"_1": "c", "_2": "1.0"}],
            row_count=1
        )

        # Mock the stats query
        stats_result = QueryResult(
            success=True,
            data=[{"_1": 5, "_2": 10, "_3": 8, "_4": 15, "_5": 20}],
            row_count=1
        )

        # Configure mock to return different results for different queries
        call_count = 0
        def mock_execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            query = kwargs.get('query', '')
            if 'm.language' in query:
                return meta_result
            else:
                return stats_result

        mock_services["query_executor"].execute_query.side_effect = mock_execute

        mcp = FakeMCP()
        register_code_browsing_tools(mcp, mock_services)

        func = mcp.registered.get("get_codebase_summary")
        assert func is not None

        result = func(codebase_hash="553642871dd4251d")

        assert result["success"] is True
        assert "summary" in result
        assert result["summary"]["language"] == "c"
        assert result["summary"]["total_files"] == 5
        assert result["summary"]["total_methods"] == 10

    def test_list_files_local_tree_default(self, mock_services, tmp_path):
        """Test listing files as a tree for a local codebase, default per-dir limit 20"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        from src.models import CodebaseInfo

        # Build a playground-like source tree under a temp dir
        source_dir = tmp_path / "test_codebase"
        source_dir.mkdir()

        # create a subdir with 25 files to check per-dir limit (20)
        subdir = source_dir / "many_files"
        subdir.mkdir()
        for i in range(25):
            f = subdir / f"file_{i}.txt"
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

        mcp = FakeMCP()
        register_code_browsing_tools(mcp, mock_services)

        func = mcp.registered.get("list_files")
        assert func is not None

        result = func(codebase_hash="553642871dd4251d")
        assert result["success"] is True
        assert "files" in result
        # root should include at least the many_files dir; check its children per-dir limit
        root_children = result["files"]
        found = False
        for node in root_children:
            if node["name"] == "many_files":
                found = True
                assert node["type"] == "dir"
                # children of many_files should be limited to 20
                assert len(node["children"]) == 20
        assert found

    def test_list_files_local_path_limit(self, mock_services, tmp_path):
        """Test listing files for a specific local_path with per-dir limit 50"""
        from src.tools.code_browsing_tools import register_code_browsing_tools
        from src.models import CodebaseInfo

        # Build a source dir
        source_dir = tmp_path / "test_codebase2"
        source_dir.mkdir()

        # Create a directory with 60 files
        big_dir = source_dir / "big_dir"
        big_dir.mkdir()
        for i in range(60):
            f = big_dir / f"file_{i}.txt"
            f.write_text(f"content {i}")

        mock_services["codebase_tracker"].get_codebase.return_value = CodebaseInfo(
            codebase_hash="553642871dd4251e",
            source_type="local",
            source_path=str(source_dir),
            language="python",
            cpg_path=None,
        )

        from src.services.code_browsing_service import CodeBrowsingService
        real_cb_service = CodeBrowsingService(codebase_tracker=mock_services["codebase_tracker"], query_executor=mock_services["query_executor"])
        mock_services["code_browsing_service"] = real_cb_service

        mcp = FakeMCP()
        register_code_browsing_tools(mcp, mock_services)

        func = mcp.registered.get("list_files")
        assert func is not None

        # Request only big_dir contents
        result = func(codebase_hash="553642871dd4251e", local_path="big_dir")
        assert result["success"] is True
        assert "files" in result
        root_children = result["files"]
        # should be the children of big_dir, limited to 50
        assert len(root_children) == 50
