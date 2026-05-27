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


@pytest.fixture(autouse=True)
def reset_main_services():
    """Isolate tests from global state held in main.services."""
    main.services.clear()
    yield
    main.services.clear()


class TestLifespan:
    """Test FastMCP lifespan management"""

    @pytest.mark.asyncio
    async def test_lifespan_success(self):
        """Test successful lifespan startup and shutdown"""
        mock_mcp = MagicMock()

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
        ) as mock_makedirs, patch(
            "main._setup_telemetry"
        ), patch(
            "main._graceful_shutdown", new_callable=AsyncMock
        ), patch(
            "main.register_tools"
        ), patch(
            "main.DBManager"
        ), patch(
            "main.PortManager"
        ), patch(
            "main.JoernServerManager"
        ), patch(
            "main.QueryExecutor"
        ), patch(
            "main.CodeBrowsingService"
        ):

            # Setup mocks
            mock_config = MagicMock()
            mock_config.server.log_level = "INFO"
            mock_config.storage.workspace_root = "/tmp/workspace"
            mock_config.cpg = MagicMock()
            mock_config.query = MagicMock()
            mock_config.joern = MagicMock()
            mock_config.joern.port_min = 13371
            mock_config.joern.port_max = 13870
            mock_config.joern.binary_path = "joern"
            mock_config.telemetry = MagicMock()
            mock_config.telemetry.enabled = False

            mock_load_config.return_value = mock_config

            mock_codebase_tracker = MagicMock()
            mock_codebase_tracker_class.return_value = mock_codebase_tracker

            mock_git_manager = MagicMock()
            mock_git_manager_class.return_value = mock_git_manager

            mock_cpg_generator = MagicMock()
            mock_cpg_generator_class.return_value = mock_cpg_generator

            # Lifespan.__call__ returns an async context manager
            async with main.app_lifespan(mock_mcp) as ctx:
                # Verify initialization calls
                mock_load_config.assert_called_with("config.yaml")
                mock_setup_logging.assert_called_with("INFO")
                mock_makedirs.assert_called()

    @pytest.mark.asyncio
    async def test_lifespan_initialization_failure(self):
        """Test lifespan with initialization failure"""
        mock_mcp = MagicMock()

        with patch(
            "main.load_config", side_effect=Exception("Config load failed")
        ), patch("main.logger") as mock_logger, patch(
            "main._graceful_shutdown", new_callable=AsyncMock
        ):

            with pytest.raises(Exception, match="Config load failed"):
                async with main.app_lifespan(mock_mcp) as ctx:
                    pass

    @pytest.mark.asyncio
    async def test_lifespan_degrades_when_docker_unavailable(self):
        """Startup should succeed even when Docker/Joern is unavailable."""
        mock_mcp = MagicMock()

        with patch("main.load_config") as mock_load_config, patch(
            "main.CodebaseTracker"
        ), patch(
            "main.GitManager"
        ), patch(
            "main.CPGGenerator"
        ), patch(
            "main.setup_logging"
        ), patch(
            "main.logger"
        ), patch(
            "os.makedirs"
        ), patch(
            "main._setup_telemetry"
        ), patch(
            "main._graceful_shutdown", new_callable=AsyncMock
        ), patch(
            "main.register_tools"
        ), patch(
            "main.DBManager"
        ), patch(
            "main.PortManager"
        ), patch(
            "main.JoernServerManager"
        ) as mock_joern_manager_class, patch(
            "main.QueryExecutor"
        ), patch(
            "main.CodeBrowsingService"
        ), patch(
            "main._check_joern_container_status",
            return_value={"running": False, "status": "docker_unavailable", "error": "daemon down"},
        ):
            mock_config = MagicMock()
            mock_config.server.log_level = "INFO"
            mock_config.storage.workspace_root = "/tmp/workspace"
            mock_config.cpg = MagicMock()
            mock_config.cpg.build_workers = 1
            mock_config.query = MagicMock()
            mock_config.joern = MagicMock()
            mock_config.joern.port_min = 13371
            mock_config.joern.port_max = 13870
            mock_config.joern.binary_path = "joern"
            mock_config.joern.max_active_servers = 2
            mock_config.telemetry = MagicMock()
            mock_config.telemetry.enabled = False

            mock_load_config.return_value = mock_config

            async with main.app_lifespan(mock_mcp) as ctx:
                assert ctx["joern_server_manager"] is None
                assert ctx["startup_issues"]

            mock_joern_manager_class.assert_not_called()




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

        # Patch helpers that access the global services dict
        with patch("main._check_joern_container_status", return_value={"status": "running", "running": True}), \
             patch("main._get_active_servers", return_value={"count": 0, "servers": {}}), \
             patch("main._get_port_utilization", return_value={"allocated_count": 0, "available_count": 29}), \
             patch("main._get_disk_usage", return_value={"total_gb": 100, "used_gb": 50, "free_gb": 50}), \
             patch("main._get_cache_size", return_value={"cache_path": "/tmp", "size_mb": 0, "exists": True}):

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


class TestMiddleware:
    """Test middleware behavior."""

    @pytest.mark.asyncio
    async def test_concurrency_limit_returns_503_when_saturated(self):
        """The concurrency middleware should return a valid 503 response when full."""
        from starlette.requests import Request

        middleware = main.ConcurrencyLimitMiddleware(MagicMock(), max_concurrent=1)
        await middleware._sem.acquire()

        mock_request = AsyncMock(spec=Request)
        mock_call_next = AsyncMock()

        response = await middleware.dispatch(mock_request, mock_call_next)

        assert response.status_code == 503
        assert response.headers["Retry-After"] == "5"
        assert response.body == b"Server busy - too many concurrent requests"
        mock_call_next.assert_not_called()
