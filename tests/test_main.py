"""
Tests for main module
"""

import main
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import main module

lifespan = main.lifespan


class TestLifespan:
    """Test FastMCP lifespan management"""

    @pytest.mark.asyncio
    async def test_lifespan_success(self):
        """Test successful lifespan startup and shutdown"""
        class DummyMCP:
            def __init__(self):
                self.registered = {}

            def tool(self):
                def decorator(func):
                    self.registered[func.__name__] = func
                    return func

                return decorator

        mock_mcp = DummyMCP()

        # Mock all the services and dependencies
        with patch("main.load_config") as mock_load_config, patch(
            "main.CodebaseTracker"
        ) as mock_codebase_tracker_class, patch(
            "main.GitManager"
        ) as mock_git_manager_class, patch(
            "main.CPGGenerator"
        ) as mock_cpg_generator_class, patch(
            "main.setup_logging"
        ) as mock_setup_logging, patch(
            "main.logger"
        ) as mock_logger, patch(
            "os.makedirs"
        ) as mock_makedirs:

            # Setup mocks
            mock_config = AsyncMock()
            mock_config.server.log_level = "INFO"
            mock_config.storage.workspace_root = "/tmp/workspace"
            mock_config.cpg = AsyncMock()
            mock_config.query = AsyncMock()
            mock_config.joern = AsyncMock()

            mock_load_config.return_value = mock_config

            mock_codebase_tracker = AsyncMock()
            mock_codebase_tracker_class.return_value = mock_codebase_tracker

            mock_git_manager = AsyncMock()
            mock_git_manager_class.return_value = mock_git_manager

            mock_cpg_generator = AsyncMock()
            mock_cpg_generator_class.return_value = mock_cpg_generator

            # Test lifespan context manager
            async with lifespan(mock_mcp):
                # Verify initialization calls
                mock_load_config.assert_called_with("config.yaml")
                mock_setup_logging.assert_called_with("INFO")
                mock_makedirs.assert_called()

            # Verify shutdown calls
            # No specific shutdown calls to verify for now

    @pytest.mark.asyncio
    async def test_lifespan_initialization_failure(self):
        """Test lifespan with initialization failure"""
        class DummyMCP:
            def __init__(self):
                self.registered = {}

            def tool(self):
                def decorator(func):
                    self.registered[func.__name__] = func
                    return func

                return decorator

        mock_mcp = DummyMCP()

        with patch(
            "main.load_config", side_effect=Exception("Config load failed")
        ), patch("main.logger") as mock_logger:

            with pytest.raises(Exception, match="Config load failed"):
                async with lifespan(mock_mcp):
                    pass




class TestEndpoints:
    """Test custom HTTP endpoints"""

    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        """Test the /health endpoint returns correct response"""
        from main import health_check, VERSION
        from starlette.requests import Request
        from starlette.responses import JSONResponse

        # Mock request
        mock_request = AsyncMock(spec=Request)

        # Call the health endpoint
        response = await health_check(mock_request)

        # Verify response
        assert isinstance(response, JSONResponse)
        response_data = response.body
        # JSONResponse.body is bytes, so we need to decode it
        import json
        response_dict = json.loads(response_data.decode('utf-8'))

        assert response_dict["status"] == "healthy"
        assert response_dict["service"] == "codebadger"
        assert response_dict["version"] == VERSION

    @pytest.mark.asyncio
    async def test_root_endpoint(self):
        """Test the / root endpoint returns correct response"""
        from main import root, VERSION
        from starlette.requests import Request
        from starlette.responses import JSONResponse

        # Mock request
        mock_request = AsyncMock(spec=Request)

        # Call the root endpoint
        response = await root(mock_request)

        # Verify response
        assert isinstance(response, JSONResponse)
        response_data = response.body
        # JSONResponse.body is bytes, so we need to decode it
        import json
        response_dict = json.loads(response_data.decode('utf-8'))

        assert response_dict["service"] == "codebadger"
        assert "description" in response_dict
        assert response_dict["version"] == VERSION
        assert "endpoints" in response_dict
        assert response_dict["endpoints"]["health"] == "/health"
        assert response_dict["endpoints"]["mcp"] == "/mcp"
