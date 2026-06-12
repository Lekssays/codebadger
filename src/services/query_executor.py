import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

from ..models import QueryResult, SessionStatus
from ..exceptions import QueryExecutionError
from ..defaults import (
    MAX_QUERY_TIMEOUT_SECONDS,
    MAX_RESULT_ROWS,
    MAX_QUERY_OUTPUT_BYTES,
)
from ..utils.validators import sanitize_error_text
from .coordination import QueryLockTimeout
from ..telemetry import get_tracer
from .joern_server_manager import JoernServerManager

if TYPE_CHECKING:
    from .joern_client import JoernServerClient
    from ..services.codebase_tracker import CodebaseTracker

logger = logging.getLogger(__name__)
tracer = get_tracer()

# Dataflow queries (reachableByFlows) return huge result sets and run for minutes.
# Auto-cap their output and give them a higher default timeout.
_DATAFLOW_PATTERNS = (".reachableByFlows", "reachableByFlows")
_DATAFLOW_RESULT_LIMIT = 50
_DATAFLOW_DEFAULT_TIMEOUT = 120  # seconds


class QueryExecutor:
    """Service for executing CPGQL queries against CPGs using Joern HTTP server"""

    def __init__(
        self,
        joern_server_manager: Optional["JoernServerManager"] = None,
        config: Optional[Dict[str, Any]] = None,
        codebase_tracker: Optional["CodebaseTracker"] = None,
        coordinator=None,
    ):
        self.joern_server_manager = joern_server_manager
        self.config = config or {}
        self.codebase_tracker = codebase_tracker
        # Serialize queries per codebase so a runaway query on one JVM doesn't
        # cause a second request to pile on. The (Redis-backed) coordinator makes
        # this lock hold across processes.
        if coordinator is None:
            raise ValueError("QueryExecutor requires a coordinator")
        self.coordinator = coordinator

    def _is_loading(self, codebase_hash: str) -> bool:
        """True if the codebase is mid-load/build, so its JVM is legitimately
        busy (not runaway) and must not be terminated on a query timeout."""
        if not self.codebase_tracker:
            return False
        try:
            info = self.codebase_tracker.get_codebase(codebase_hash)
        except Exception:
            return False
        if not info:
            return False
        return info.metadata.get("status") in (
            SessionStatus.LOADING,
            SessionStatus.GENERATING,
        )

    def execute_query(
        self,
        codebase_hash: str,
        cpg_path: str,
        query: str,
        timeout: int = 30,
        limit: Optional[int] = None,
    ) -> QueryResult:
        """Execute a CPGQL query using the Joern server for the specific codebase"""
        with tracer.start_as_current_span("query.execute") as span:
            span.set_attribute("query.codebase_hash", codebase_hash)
            span.set_attribute("query.length", len(query))

            start_time = time.time()

            # Clamp a caller-supplied timeout so an LLM can't hold a JVM + the
            # per-codebase query lock for an unbounded period.
            try:
                timeout = max(1, min(int(timeout), MAX_QUERY_TIMEOUT_SECONDS))
            except (TypeError, ValueError):
                timeout = 30

            try:
                logger.debug(f"Executing query for codebase {codebase_hash}: {query[:100]}...")

                if not self.joern_server_manager:
                    return QueryResult(
                        success=False,
                        error="No Joern server manager configured",
                        error_code="SERVER_UNAVAILABLE",
                        execution_time=time.time() - start_time,
                    )

                # Serialize queries per codebase: one JVM handles one query at a
                # time. Cross-process when the coordinator is Redis-backed.
                with self.coordinator.codebase_query_lock(codebase_hash):
                    port = self.joern_server_manager.get_server_port(codebase_hash)
                    if not port:
                        info = (
                            self.codebase_tracker.get_codebase(codebase_hash)
                            if self.codebase_tracker else None
                        )
                        status = info.metadata.get("status") if info else None
                        # Don't dispatch a query into a build/load in progress: the
                        # server isn't ready, so the call would hit a dead/not-ready
                        # port and surface as "connection refused". Tell the caller
                        # to poll instead.
                        if status in (SessionStatus.LOADING, SessionStatus.GENERATING):
                            return QueryResult(
                                success=False,
                                error="CPG is still loading; try again shortly.",
                                error_code="SERVER_UNAVAILABLE",
                                execution_time=time.time() - start_time,
                            )
                        # SLEEPING (idle-reaped) or READY-but-server-gone (a zombie
                        # whose worker was reaped/evicted): reactivate from the CPG
                        # on disk rather than failing. reload_with_retry absorbs a
                        # transient reactivation stall.
                        if info and info.cpg_path and status in (
                            SessionStatus.SLEEPING, SessionStatus.READY,
                        ):
                            logger.info(
                                f"Reactivating {status} codebase {codebase_hash} (no live server)"
                            )
                            try:
                                port = self.joern_server_manager.reactivate(codebase_hash, info.cpg_path)
                            except Exception as e:
                                return QueryResult(
                                    success=False,
                                    error=f"Failed to reactivate codebase: {e}",
                                    error_code="SERVER_UNAVAILABLE",
                                    execution_time=time.time() - start_time,
                                )
                    if not port:
                        return QueryResult(
                            success=False,
                            error=f"No Joern server running for codebase {codebase_hash}",
                            error_code="SERVER_UNAVAILABLE",
                            execution_time=time.time() - start_time,
                        )

                    joern_client = self.joern_server_manager.get_or_create_client(codebase_hash)

                    # Single health check — no sleep. If the server was killed due to a
                    # previous query timeout it will be absent; auto-wake handles restart
                    # on the next call.
                    if not joern_client.check_health(timeout=10):
                        logger.warning(f"Joern server on port {port} not responding")
                        return QueryResult(
                            success=False,
                            error=(
                                f"Joern server not responding (port {port}). "
                                f"It may be restarting after a previous timeout. Try again shortly."
                            ),
                            error_code="SERVER_UNAVAILABLE",
                            execution_time=time.time() - start_time,
                        )

                    normalized_query = self._normalize_query(query, limit)
                    logger.debug(f"Normalized query for execution: {normalized_query}")

                    result = self._execute_via_client(joern_client, normalized_query, timeout)
                    result.execution_time = time.time() - start_time
                    span.set_attribute("query.execution_time_s", result.execution_time)
                    span.set_attribute("query.success", result.success)

                    # On timeout: kill the server so a runaway JVM doesn't peg CPU.
                    # Mark it sleeping so the next query auto-reactivates transparently.
                    # BUT never kill a server that is mid-load/build: a query that
                    # times out while a CPG is still importing means the JVM is busy,
                    # not runaway — terminating it aborts the load and permanently
                    # fails the codebase. Leave it to finish; the caller retries.
                    if result.error_code == "TIMEOUT":
                        if self._is_loading(codebase_hash):
                            logger.info(
                                f"Query timed out for {codebase_hash} while it is "
                                f"loading/generating — leaving the server to finish, "
                                f"not terminating"
                            )
                            return result
                        logger.warning(
                            f"Query timed out for {codebase_hash} — terminating server "
                            f"to stop runaway JVM (same pattern as load_cpg timeout)"
                        )
                        self.joern_server_manager.terminate_server(codebase_hash)
                        if self.codebase_tracker:
                            try:
                                self.codebase_tracker.update_codebase(
                                    codebase_hash,
                                    joern_port=None,
                                    metadata={"status": SessionStatus.SLEEPING},
                                )
                            except Exception as e:
                                logger.warning(f"Failed to mark codebase sleeping after timeout: {e}")

                    return result

            except QueryLockTimeout as e:
                logger.warning(f"Query lock busy for {codebase_hash}: {e}")
                return QueryResult(
                    success=False,
                    error="Server busy: another request is using this CPG. Try again shortly.",
                    error_code="SERVER_BUSY",
                    execution_time=time.time() - start_time,
                )
            except Exception as e:
                execution_time = time.time() - start_time
                logger.error(f"Error executing query: {e}", exc_info=True)
                return QueryResult(
                    success=False,
                    error=sanitize_error_text(str(e)),
                    execution_time=execution_time,
                )

    def _normalize_query(self, query: str, limit: Optional[int] = None) -> str:
        """Normalize query to ensure proper output format"""
        query = query.strip()

        # Block queries (start with { and end with }) may already produce their
        # own output; don't wrap those in another conversion.
        if query.startswith('{') and query.endswith('}'):
            if '.toJsonPretty' in query or '.toJson' in query:
                return query
            if '.toString()' in query[-50:]:
                return query

        # Remove existing output modifiers from the end
        if query.endswith('.toJsonPretty'):
            base_query = query[:-13]
        elif query.endswith('.toJson'):
            base_query = query[:-7]
        elif query.endswith('.l'):
            base_query = query[:-2]
        elif query.endswith('.toList'):
            base_query = query[:-7]
        else:
            base_query = query

        # Auto-cap dataflow queries that are not already limited — they fan out over the
        # entire identifier set and return enormous result sets if unconstrained.
        is_size_query = bool(re.search(r"\.size\s*$", base_query))
        if limit is None and any(p in base_query for p in _DATAFLOW_PATTERNS):
            limit = _DATAFLOW_RESULT_LIMIT
        # Cap any otherwise-unbounded query (e.g. a raw `cpg.method.l`) so it can't
        # stream the whole graph back. Clamp explicit limits to the same ceiling.
        if limit is None and not is_size_query:
            limit = MAX_RESULT_ROWS
        if limit is not None and limit > 0 and not is_size_query:
            limit = min(limit, MAX_RESULT_ROWS)
            base_query = f"{base_query}.take({limit})"

        if is_size_query:
            return f"{base_query}.toString"
        return f"{base_query}.toJsonPretty"

    def _execute_via_client(self, joern_client: 'JoernServerClient', query: str, timeout: int) -> QueryResult:
        """Execute query using Joern server client"""
        try:
            logger.debug(f"Executing query via Joern client: {query[:100]}...")

            result = joern_client.execute_query(query, timeout=timeout)

            if result.get("success"):
                stdout = result.get("stdout", "")
                # Bound the raw payload we parse/return so a single query can't
                # exhaust memory or flood the response channel.
                truncated = False
                if len(stdout) > MAX_QUERY_OUTPUT_BYTES:
                    stdout = stdout[:MAX_QUERY_OUTPUT_BYTES]
                    truncated = True
                data = self._parse_output(stdout)
                if isinstance(data, list) and len(data) > MAX_RESULT_ROWS:
                    data = data[:MAX_RESULT_ROWS]
                    truncated = True
                row_count = len(data) if isinstance(data, list) else 1
                return QueryResult(success=True, data=data, row_count=row_count, truncated=truncated)
            else:
                stderr = result.get("stderr", "")
                if "timeout" in stderr.lower() or "timed out" in stderr.lower():
                    error_msg = (
                        f"Query timed out after {timeout}s. "
                        f"Try: 1) filtering by filename, "
                        f"2) increasing the timeout parameter, "
                        f"3) using simpler queries before taint analysis."
                    )
                    logger.error(f"Query execution timed out after {timeout}s: {query[:100]}...")
                    return QueryResult(success=False, error=error_msg, error_code="TIMEOUT")
                logger.error(f"Query execution failed: {stderr}")
                # Joern stderr / stack traces embed host paths — redact before returning.
                return QueryResult(success=False, error=sanitize_error_text(stderr), error_code="QUERY_ERROR")

        except Exception as e:
            logger.error(f"Error executing query via Joern client: {e}")
            return QueryResult(success=False, error=sanitize_error_text(str(e)), error_code="QUERY_ERROR")

    def _parse_output(self, output: str) -> Union[list, int, float, str]:
        """Parse Joern query output"""
        if not output or not output.strip():
            return []

        # Remove ANSI color codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output = ansi_escape.sub('', output)

        # codebadger_result markers wrap text output from non-JSON queries
        marker_match = re.search(r'<codebadger_result>\s*(.*?)\s*</codebadger_result>', output, re.DOTALL)
        if marker_match:
            return [marker_match.group(1).strip()]

        # Extract JSON from Scala REPL output (wrapped in triple quotes)
        match = re.search(r'"""(\[.*?\]|\{.*?\})"""', output, re.DOTALL)
        if match:
            json_str = match.group(1)
            try:
                data = json.loads(json_str)
                if isinstance(data, dict):
                    return [data]
                elif isinstance(data, list):
                    return data
                else:
                    return [{"value": str(data)}]
            except json.JSONDecodeError:
                pass

        # Try direct JSON parsing
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                return [data]
            elif isinstance(data, list):
                return data
            else:
                return [{"value": str(data)}]
        except json.JSONDecodeError:
            # Not JSON: return a numeric primitive if it parses, else plain text.
            s = output.strip()
            try:
                return int(s)
            except Exception:
                pass
            try:
                return float(s)
            except Exception:
                pass
            return s
