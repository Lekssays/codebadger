"""
Tests for main module
"""

import asyncio
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
            "main.PostgresDBManager"
        ), patch(
            "main.PortManager"
        ), patch(
            "main.JoernServerManager"
        ), patch(
            "main.QueryExecutor"
        ), patch(
            "main.CodeBrowsingService"
        ), patch(
            "src.services.coordination.make_coordinator",
            return_value=MagicMock(backend="redis"),
        ):

            # Setup mocks
            mock_config = MagicMock()
            mock_config.server.log_level = "INFO"
            mock_config.storage.workspace_root = "/tmp/workspace"
            mock_config.cpg = MagicMock()
            # Read during startup for DB-pool sizing — must be a real int.
            mock_config.cpg.build_workers = 2
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

            # Lifespan.__call__ returns an async context manager
            async with main.app_lifespan(mock_mcp) as ctx:
                # Verify initialization calls
                mock_load_config.assert_called_with("config.yaml")
                # setup_logging now also receives file-logging kwargs; assert the
                # level positional without pinning the exact kwarg set.
                mock_setup_logging.assert_called_once()
                assert mock_setup_logging.call_args[0][0] == "INFO"
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
            "main.PostgresDBManager"
        ), patch(
            "main.PortManager"
        ), patch(
            "main.JoernServerManager"
        ) as mock_joern_manager_class, patch(
            "main.QueryExecutor"
        ), patch(
            "main.CodeBrowsingService"
        ), patch(
            "src.services.coordination.make_coordinator",
            return_value=MagicMock(backend="redis"),
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

    @staticmethod
    def _install_healthy_services():
        """Populate main.services with mocks so /health reports status=up."""
        db = MagicMock()
        db.ping.return_value = {"ok": True, "latency_ms": 1.0}
        coord = MagicMock(backend="redis")
        coord.ping.return_value = {"ok": True, "latency_ms": 0.4, "backend": "redis"}
        joern = MagicMock()
        joern.worker_mode = "pool"
        joern._max_active = 8
        joern._lru_eviction_count = 0
        joern.get_memory_stats.return_value = {
            "mode": "memory", "reserved_mb": 0, "budget_mb": 24000,
            "utilization_pct": 0.0, "container_rss_mb": 10.0,
        }
        joern.get_running_servers.return_value = {}
        cpq = MagicMock(depth=0, in_flight=0, maxsize=8, is_full=False)
        cfg = MagicMock()
        cfg.cpg.build_workers = 2
        cfg.cpg.queue_backend = "durable"
        main.services.update({
            "db_manager": db, "coordinator": coord, "joern_server_manager": joern,
            "cpg_queue": cpq, "config": cfg,
            "joern_container_name": "codebadger-joern-server", "startup_issues": [],
        })

    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        """/health returns up + mcp + a dependencies map when everything is healthy."""
        from main import health_check, VERSION
        from starlette.responses import JSONResponse
        import json

        self._install_healthy_services()
        mock_request = AsyncMock()

        with patch("main._check_joern_container_status",
                   return_value={"status": "running", "running": True,
                                 "container_name": "codebadger-joern-server"}), \
             patch("main._get_port_utilization", return_value={"allocated_count": 0, "available_count": 29}), \
             patch("main._get_disk_usage", return_value={"total_gb": 100, "used_gb": 50, "free_gb": 50}), \
             patch("main._get_codebase_list", return_value=[]), \
             patch("main._get_cache_size", return_value={"cache_path": "/tmp", "size_mb": 0, "exists": True}):
            response = await health_check(mock_request)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 200
        body = json.loads(response.body.decode("utf-8"))

        assert body["status"] == "up"
        assert body["mcp"] == "codebadger"
        assert body["version"] == VERSION
        assert body["dependencies"] == {
            "joern": "up", "postgres": "up", "redis": "up",
            "docker": "up", "cpg_queue": "up",
        }

    @pytest.mark.asyncio
    async def test_health_endpoint_down_when_postgres_unreachable(self):
        """A failing Postgres ping makes the overall status down (HTTP 503)."""
        from main import health_check
        import json

        self._install_healthy_services()
        main.services["db_manager"].ping.return_value = {"ok": False, "error": "connection refused"}
        mock_request = AsyncMock()

        with patch("main._check_joern_container_status",
                   return_value={"status": "running", "running": True}), \
             patch("main._get_port_utilization", return_value={"allocated_count": 0, "available_count": 29}), \
             patch("main._get_disk_usage", return_value={"total_gb": 100, "used_gb": 50, "free_gb": 50}), \
             patch("main._get_cache_size", return_value={"size_mb": 0}):
            response = await health_check(mock_request)

        assert response.status_code == 503
        body = json.loads(response.body.decode("utf-8"))
        assert body["status"] == "down"
        assert body["dependencies"]["postgres"] == "down"

    @pytest.mark.asyncio
    async def test_health_endpoint_does_not_expose_codebase_sources(self):
        """The public /health response must not include the codebase list/sources."""
        from main import health_check
        import json

        self._install_healthy_services()
        mock_request = AsyncMock()

        with patch("main._check_joern_container_status",
                   return_value={"status": "running", "running": True}), \
             patch("main._get_port_utilization", return_value={"allocated_count": 0, "available_count": 29}), \
             patch("main._get_disk_usage", return_value={"total_gb": 100, "used_gb": 50, "free_gb": 50}), \
             patch("main._get_codebase_list",
                   return_value=[{"hash": "h", "language": "python", "status": "ready",
                                  "joern_port": None, "source_type": "local",
                                  "source": "/Users/example/private-repo"}]), \
             patch("main._get_cache_size", return_value={"size_mb": 0}):
            response = await health_check(mock_request)

        raw = response.body.decode("utf-8")
        body = json.loads(raw)
        # Public health exposes counts only — never the per-codebase list or paths.
        assert "list" not in body["codebases"]
        assert "/Users/example/private-repo" not in raw


class TestHealthHelpers:
    """Test health helper behavior."""

    def test_get_codebase_list_can_include_sensitive_sources(self):
        """Internal status paths can still request full source locations."""
        from src.models import CodebaseInfo

        tracker = MagicMock()
        tracker.list_codebases_full.return_value = [CodebaseInfo(
            codebase_hash="553642871dd4251d",
            source_type="github",
            source_path="https://github.com/acme/private-repo",
            language="python",
            cpg_path="/tmp/test.cpg",
            metadata={"status": "ready"},
        )]
        main.services["codebase_tracker"] = tracker
        main.services["joern_server_manager"] = None

        redacted = main._get_codebase_list()
        detailed = main._get_codebase_list(include_sensitive=True)

        assert redacted[0]["source"] == "<redacted:github>"
        assert detailed[0]["source"] == "https://github.com/acme/private-repo"


class TestEffectiveConfigSelfCheck:
    """The startup self-check logs resolved config and flags env-vs-effective drift."""

    def _config(self, worker_mode="shared", queue_backend="memory"):
        cfg = MagicMock()
        cfg.joern.worker_mode = worker_mode
        cfg.joern.memory_budget_mb = 8192
        cfg.cpg.queue_backend = queue_backend
        cfg.cpg.build_heap_gb = 6
        cfg.cpg.build_workers = 4
        return cfg

    def test_logs_effective_config_without_drift(self):
        coordinator = MagicMock()
        coordinator.backend = "redis"
        main.services["coordinator"] = coordinator
        main.services["cpg_queue"] = MagicMock()
        main.services["joern_server_manager"] = None

        with patch("main.logger") as mock_logger, patch.dict(
            "os.environ", {}, clear=True
        ):
            main._log_effective_config(self._config())

        infos = " ".join(str(c.args[0]) for c in mock_logger.info.call_args_list)
        assert "Effective runtime configuration" in infos
        mock_logger.warning.assert_not_called()

    def test_flags_queue_backend_env_drift(self):
        """CPG_QUEUE_BACKEND=durable but effective memory → a warning."""
        coordinator = MagicMock()
        coordinator.backend = "redis"
        main.services["coordinator"] = coordinator
        main.services["cpg_queue"] = MagicMock()
        main.services["joern_server_manager"] = None

        with patch("main.logger") as mock_logger, patch.dict(
            "os.environ", {"CPG_QUEUE_BACKEND": "durable"}, clear=True
        ):
            main._log_effective_config(self._config(queue_backend="memory"))

        warnings = " ".join(str(c.args[0]) for c in mock_logger.warning.call_args_list)
        assert "CPG_QUEUE_BACKEND=durable" in warnings
        assert "queue_backend=memory" in warnings

class TestShutdown:
    """Test graceful shutdown behavior."""

    @pytest.mark.asyncio
    async def test_graceful_shutdown_cancels_restart_tasks(self):
        """Graceful shutdown should cancel tracked restart tasks before clearing services."""
        status_log_task = asyncio.get_running_loop().create_future()
        restart_task = asyncio.get_running_loop().create_future()

        joern_server_manager = MagicMock()
        joern_server_manager._watchdog_task = None
        joern_server_manager._reaper_task = None
        port_manager = MagicMock()
        cpg_queue = MagicMock()
        cpg_queue.stop = AsyncMock()
        db_manager = MagicMock()

        main.services.update(
            {
                "status_log_task": status_log_task,
                "restart_tasks": {"codebase": restart_task},
                "joern_server_manager": joern_server_manager,
                "port_manager": port_manager,
                "cpg_queue": cpg_queue,
                "db_manager": db_manager,
            }
        )

        await main._graceful_shutdown()

        assert status_log_task.cancelled()
        assert restart_task.cancelled()
        joern_server_manager.terminate_all_servers.assert_called_once()
        port_manager.release_all_ports.assert_called_once()
        cpg_queue.stop.assert_awaited_once()
        db_manager.close.assert_called_once()
        assert main.services == {}


class TestRootEndpoint:
    """Test root endpoint behavior."""

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


class TestExposureCheck:
    """_check_exposure flags fail-open network exposure (item 17)."""

    def _cfg(self, host, chat_deploy):
        import types
        return types.SimpleNamespace(server=types.SimpleNamespace(host=host, chat_deploy=chat_deploy))

    def test_unsafe_combination_flagged(self, monkeypatch):
        monkeypatch.delenv("ALLOWED_SOURCE_ROOTS", raising=False)
        issues = main._check_exposure(self._cfg("0.0.0.0", False))
        assert any("INSECURE EXPOSURE" in i for i in issues)

    def test_loopback_is_safe(self, monkeypatch):
        monkeypatch.delenv("ALLOWED_SOURCE_ROOTS", raising=False)
        assert main._check_exposure(self._cfg("127.0.0.1", False)) == []

    def test_chat_deploy_suppresses_local_risk(self, monkeypatch):
        monkeypatch.delenv("ALLOWED_SOURCE_ROOTS", raising=False)
        issues = main._check_exposure(self._cfg("0.0.0.0", True))
        # still warns about all-interfaces+no-auth, but not the local-path read risk
        assert not any("INSECURE EXPOSURE" in i for i in issues)
        assert any("no built-in" in i for i in issues)

    def test_allowed_roots_suppresses_local_risk(self, monkeypatch):
        monkeypatch.setenv("ALLOWED_SOURCE_ROOTS", "/srv/code")
        issues = main._check_exposure(self._cfg("0.0.0.0", False))
        assert not any("INSECURE EXPOSURE" in i for i in issues)
