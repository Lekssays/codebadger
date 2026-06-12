"""
HTTP client for communicating with Joern server API
"""

import json
import logging
import re
import time
from typing import Dict, Optional, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..utils.query_rendering import escape_scala_string

logger = logging.getLogger(__name__)

# Joern prints this when a query runs but no project is open — i.e. importCpg
# did not register/open a project (stale collision, or import silently failed).
_NO_PROJECT_MARKER = "No projects loaded"
# Pull the integer out of a Joern REPL result line like "val res0: Int = 42".
_RESULT_INT_RE = re.compile(r"=\s*(\d+)")
# Number of times to re-poll the verify query before giving up — importCpg can
# return before the project is fully registered/overlays settle, so a one-shot
# verify spuriously sees "No projects loaded". A short poll absorbs that race.
_VERIFY_POLL_ATTEMPTS = 5
_VERIFY_POLL_INTERVAL_S = 2.0


def _safe_project_name(raw: str) -> str:
    """Derive a collision-free Joern project name from a hash/path.

    Every CPG file is named ``cpg.bin``; if we let importCpg derive the project
    name from the filename, a worker that imports a second CPG (or reuses a
    workspace) collides on the name ``cpg.bin`` and importCpg leaves NO project
    open -> "No projects loaded". A name unique to the codebase avoids that.
    """
    base = raw.rsplit("/", 1)[-1]
    base = base[:-4] if base.endswith(".bin") else base
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", base).strip("_")
    return cleaned or "cpg"


class JoernServerClient:
    """Client for Joern server HTTP API with connection pooling"""

    def __init__(self, host: str = "localhost", port: int = 8080, username: Optional[str] = None, password: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Joern server client with connection pooling

        Args:
            host: Server hostname
            port: Server port
            username: Optional authentication username
            password: Optional authentication password
            config: Optional configuration dict with HTTP settings
        """
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.auth = (username, password) if username and password else None
        self.config = config or {}

        # Initialize session with connection pooling
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests Session with connection pooling configuration"""
        session = requests.Session()

        # Get HTTP configuration from config dict (with sensible defaults)
        pool_connections = self.config.get("http_pool_connections", 10)
        pool_maxsize = self.config.get("http_pool_maxsize", 10)
        max_retries = self.config.get("http_max_retries", 3)
        backoff_factor = self.config.get("http_backoff_factor", 0.3)

        # Create retry strategy
        retry_strategy = Retry(
            total=max_retries,
            read=0,  # Do NOT retry on read timeouts
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )

        # Create HTTP adapter with connection pooling
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy
        )

        # Mount adapters for both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set authentication if provided
        if self.auth:
            session.auth = self.auth

        logger.debug(f"Created session with connection pooling: pools={pool_connections}, maxsize={pool_maxsize}, retries={max_retries}")
        return session

    def close(self):
        """Close the session and cleanup connections"""
        if hasattr(self, 'session') and self.session:
            self.session.close()
            logger.debug(f"Closed session for {self.host}:{self.port}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup session"""
        self.close()
        return False

    # Legacy async submission methods removed: use execute_query() for synchronous API

    def check_health(self, timeout: int = 5) -> bool:
        """
        Quick health check to verify the Joern server is responsive.
        
        Args:
            timeout: Maximum time to wait for response (seconds)
            
        Returns:
            True if server is responding, False otherwise
        """
        try:
            response = self.session.get(self.base_url, timeout=timeout)
            return response.status_code in [200, 404]
        except Exception:
            return False

    def execute_query(
        self,
        query: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Execute a query synchronously using the /query-sync endpoint

        Args:
            query: The CPGQL query to execute
            timeout: Maximum time to wait for result (seconds)

        Returns:
            Dictionary with keys: success (bool), stdout (str), stderr (str)
        """
        try:
            url = f"{self.base_url}/query-sync"
            payload = {"query": query}

            logger.debug(f"Executing query synchronously at {url}: {query[:100]}...")

            response = self.session.post(url, json=payload, timeout=timeout)
            
            if response.status_code != 200:
                error_text = response.text
                logger.error(f"Query execution failed: {response.status_code} - {error_text}")
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"HTTP {response.status_code}: {error_text}"
                }
            
            result = response.json()
            
            # The response should have success, stdout, stderr keys
            success = result.get("success", False)
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            
            logger.debug(f"Query executed: success={success}")
            if not success:
                logger.error(f"Query failed: {stderr}")
            
            return {
                "success": success,
                "stdout": stdout,
                "stderr": stderr
            }
            
        except requests.Timeout:
            logger.error(f"Query timeout after {timeout}s: {query[:100]}...")
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Query timeout after {timeout}s. The Joern server may be overloaded. "
                         f"Consider filtering by filename or increasing the timeout."
            }
        except requests.RequestException as e:
            error_str = str(e)
            if "ReadTimeoutError" in error_str or "Read timed out" in error_str:
                logger.error(f"Read timeout after {timeout}s for query: {query[:100]}...")
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Query read timeout after {timeout}s. Large codebase queries (taint analysis, dataflow) "
                             f"may need more time. Try increasing the timeout parameter or filtering by filename."
                }
            logger.error(f"HTTP error executing query: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": f"HTTP error: {str(e)}"
            }
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Error: {str(e)}"
            }

    # Outcome of a verify poll: a project is open and we read a method count.
    _VERIFY_OK = "ok"
    # A project is open but the CPG has 0 user-defined methods — the build
    # parsed nothing. This is a broken/empty build, not a load race; no retry
    # will help, so the caller should fail it with a distinct reason.
    _VERIFY_EMPTY = "empty"
    # No project is open ("No projects loaded") — import didn't register. This
    # is the race/collision case worth re-importing once.
    _VERIFY_NO_PROJECT = "no_project"
    # Could not run the verify query at all (server/network).
    _VERIFY_ERROR = "error"

    def _import_query(self, cpg_path: str, project_name: str) -> str:
        """Build the import statement: reset stale state, import under an
        explicit unique name, then open it (open is idempotent if importCpg
        already opened it, and surfaces a clear error if it didn't)."""
        path_lit = escape_scala_string(cpg_path)
        proj_lit = escape_scala_string(project_name)
        return (
            f'workspace.reset; '
            f'importCpg("{path_lit}", "{proj_lit}"); '
            f'open("{proj_lit}")'
        )

    def _verify_loaded(self, deadline: Optional[float] = None) -> tuple:
        """Poll until a project is open and report (outcome, method_count).

        Re-polls so a project that is still being registered after importCpg
        returns isn't mistaken for a permanent failure. Each probe uses the
        configured ``verify_timeout`` (default 60s, formerly a hard-coded 15s
        that condemned valid CPGs under load); the whole poll is bounded by
        ``deadline`` (the load_cpg budget) so it can never outlive the load.
        """
        verify_timeout = max(1, int(self.config.get("verify_timeout", 60)))
        last_stdout = ""
        # Two independent bounds: a small attempt cap (a registration race or a
        # genuinely-absent project resolves in a few fast polls — don't burn the
        # whole load budget on a hopeless one) AND, when load_cpg passes one, a
        # deadline so the poll can never outlive the load.
        for attempt in range(_VERIFY_POLL_ATTEMPTS):
            if deadline is not None and time.monotonic() >= deadline:
                break
            # A single probe waits up to verify_timeout, but never past the deadline.
            probe_timeout = verify_timeout
            if deadline is not None:
                probe_timeout = max(1, min(verify_timeout, int(deadline - time.monotonic())))
            verify_result = self.execute_query(
                "cpg.method.isExternal(false).l.size", timeout=probe_timeout
            )
            if not verify_result.get("success"):
                # Treat a connection/server error as retryable within the poll.
                last_stdout = verify_result.get("stderr", "") or ""
                time.sleep(_VERIFY_POLL_INTERVAL_S)
                continue

            stdout = verify_result.get("stdout", "") or ""
            last_stdout = stdout

            if _NO_PROJECT_MARKER in stdout:
                # Import hasn't registered a project (yet). Keep polling.
                time.sleep(_VERIFY_POLL_INTERVAL_S)
                continue

            match = _RESULT_INT_RE.search(stdout)
            if match:
                count = int(match.group(1))
                if count > 0:
                    return (self._VERIFY_OK, count)
                # Project is open but empty — settle briefly in case overlays
                # are still populating, then accept the (empty) verdict.
                if attempt < _VERIFY_POLL_ATTEMPTS - 1:
                    time.sleep(_VERIFY_POLL_INTERVAL_S)
                    continue
                return (self._VERIFY_EMPTY, 0)

            # Unparseable output that isn't the no-project marker — retry.
            time.sleep(_VERIFY_POLL_INTERVAL_S)

        if _NO_PROJECT_MARKER in last_stdout:
            return (self._VERIFY_NO_PROJECT, None)
        logger.error(f"Could not parse method count from: {last_stdout[:300]}")
        return (self._VERIFY_ERROR, None)

    def load_cpg(self, cpg_path: str, project_name: Optional[str] = None, timeout: int = 600) -> bool:
        """
        Load a CPG file into the Joern server.

        Imports the pre-built cpg.bin under an explicit, collision-free project
        name (every file is literally named ``cpg.bin``, so deriving the name
        from the filename collides and leaves "No projects loaded"), opens it,
        then verifies with a readiness poll. On a "No projects loaded" verdict
        we re-import once before giving up — that verdict is usually a
        registration race or a stale-workspace collision, not a dead CPG.

        Args:
            cpg_path: Path to the CPG file to load
            project_name: Name to assign to the project (defaults to a name
                derived from the file path)
            timeout: Maximum time to wait for the import (seconds)

        Returns:
            True if a non-empty CPG was loaded and verified, False otherwise.
        """
        proj = _safe_project_name(project_name or cpg_path)
        query = self._import_query(cpg_path, proj)
        # The readiness poll shares the load budget: it must verify within the
        # same window the import was given, never outlive it.
        verify_deadline = time.monotonic() + max(1, int(timeout))

        for attempt in range(2):  # initial import + one re-import on no_project
            label = "Loading" if attempt == 0 else "Re-importing"
            logger.info(f"{label} CPG from {cpg_path} as project '{proj}' (timeout={timeout}s)")
            try:
                result = self.execute_query(query, timeout=timeout)
            except Exception as e:
                logger.error(f"Error importing CPG from {cpg_path}: {e}")
                # The import statement itself blew up; a verify poll can still
                # confirm a prior successful load in rare connection-reset cases.
                outcome, count = self._verify_loaded(verify_deadline)
                if outcome == self._VERIFY_OK:
                    logger.info(f"CPG verified despite import exception: {count} methods")
                    return True
                return False

            if not result.get("success"):
                error_msg = result.get("stderr", "") or ""
                # A connection reset can fire after the import actually applied,
                # so fall through to the verify poll rather than failing blind.
                logger.warning(
                    f"importCpg returned unsuccessful for {cpg_path}: {error_msg[:300]} "
                    f"— verifying load state anyway"
                )

            outcome, count = self._verify_loaded(verify_deadline)
            if outcome == self._VERIFY_OK:
                logger.info(f"CPG verified: {count} methods found")
                return True
            if outcome == self._VERIFY_EMPTY:
                logger.error(
                    f"CPG loaded but is empty (0 user-defined methods) for {cpg_path} "
                    f"— treating as a failed/empty build"
                )
                return False
            if outcome == self._VERIFY_NO_PROJECT and attempt == 0:
                logger.warning(
                    f"No project open after import of {cpg_path} — re-importing once"
                )
                continue  # retry the import loop
            logger.error(
                f"Failed to load CPG from {cpg_path} (verify outcome: {outcome})"
            )
            return False

        return False


