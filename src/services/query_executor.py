import json
import logging
import time
from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

from ..models import QueryResult
from ..exceptions import QueryExecutionError
from ..telemetry import get_tracer
from .joern_server_manager import JoernServerManager

if TYPE_CHECKING:
    from .joern_client import JoernServerClient

logger = logging.getLogger(__name__)
tracer = get_tracer()


class QueryExecutor:
    """Service for executing CPGQL queries against CPGs using Joern HTTP server"""

    def __init__(self, joern_server_manager: Optional['JoernServerManager'] = None, config: Optional[Dict[str, Any]] = None):
        self.joern_server_manager = joern_server_manager
        self.config = config or {}

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

            try:
                logger.debug(f"Executing query for codebase {codebase_hash}: {query[:100]}...")

                # Get the Joern server port for this codebase
                if not self.joern_server_manager:
                    return QueryResult(
                        success=False,
                        error="No Joern server manager configured",
                        execution_time=time.time() - start_time,
                    )

                port = self.joern_server_manager.get_server_port(codebase_hash)
                if not port:
                    return QueryResult(
                        success=False,
                        error=f"No Joern server running for codebase {codebase_hash}",
                        execution_time=time.time() - start_time,
                    )

                # Get cached client with connection pooling instead of creating new one
                joern_client = self.joern_server_manager.get_or_create_client(codebase_hash)

                # Quick health check before submitting potentially expensive queries
                if not joern_client.check_health(timeout=5):
                    logger.warning(f"Joern server on port {port} is not responding, it may be overloaded or crashed")
                    return QueryResult(
                        success=False,
                        error=f"Joern server not responding (port {port}). The server may be overloaded from a previous heavy query. "
                              f"Try again in a few minutes, or restart the server.",
                        execution_time=time.time() - start_time,
                    )

                # Normalize query for JSON output
                normalized_query = self._normalize_query(query, limit)
                logger.debug(f"Normalized query for execution: {normalized_query}")

                # Execute query via HTTP API
                result = self._execute_via_client(joern_client, normalized_query, timeout)
                result.execution_time = time.time() - start_time
                span.set_attribute("query.execution_time_s", result.execution_time)
                span.set_attribute("query.success", result.success)

                return result

            except Exception as e:
                execution_time = time.time() - start_time
                logger.error(f"Error executing query: {e}", exc_info=True)
                return QueryResult(
                    success=False,
                    error=str(e),
                    execution_time=execution_time,
                )

    def _normalize_query(self, query: str, limit: Optional[int] = None) -> str:
        """Normalize query to ensure proper output format"""
        query = query.strip()

        # Check if this is a block query that already produces its own output
        # Block queries start with { and end with }
        if query.startswith('{') and query.endswith('}'):
            # Check if the block contains JSON output methods
            if '.toJsonPretty' in query or '.toJson' in query:
                # Block already produces JSON, don't modify
                return query
            # Check if the block returns a string (.toString() at the end)
            if '.toString()' in query[-50:]:
                # Block returns a string, don't add JSON conversion
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

        # Add limit if specified (only for queries that return collections)
        if limit is not None and limit > 0:
            # Don't add .take for queries that return a size/int (e.g., cpg.method.size)
            import re
            if not re.search(r"\.size\s*$", base_query):
                base_query = f"{base_query}.take({limit})"

        # Add JSON output or string conversion for size results
        import re
        if re.search(r"\.size\s*$", base_query):
            # Size returns Int, convert to string
            return f"{base_query}.toString"
        # Default: return JSON output for collections
        return f"{base_query}.toJsonPretty"

    def _execute_via_client(self, joern_client: 'JoernServerClient', query: str, timeout: int) -> QueryResult:
        """Execute query using Joern server client"""
        try:
            logger.debug(f"Executing query via Joern client: {query[:100]}...")
            
            result = joern_client.execute_query(query, timeout=timeout)
            
            if result.get("success"):
                # Parse the output
                stdout = result.get("stdout", "")
                data = self._parse_output(stdout)
                # Data may be a list (for collection outputs) or a primitive (for size/string outputs)
                if isinstance(data, list):
                    row_count = len(data)
                else:
                    row_count = 1
                return QueryResult(success=True, data=data, row_count=row_count)
            else:
                # Query failed - provide actionable error messages
                stderr = result.get("stderr", "")
                if "timeout" in stderr.lower() or "timed out" in stderr.lower():
                    error_msg = (
                        f"Query timed out after {timeout}s. "
                        f"For large codebases, try: 1) Filtering by filename to reduce scope, "
                        f"2) Increasing the timeout parameter, "
                        f"3) Using simpler queries before complex taint analysis."
                    )
                    logger.error(f"Query execution timed out after {timeout}s: {query[:100]}...")
                    return QueryResult(success=False, error=error_msg)
                logger.error(f"Query execution failed: {stderr}")
                return QueryResult(success=False, error=stderr)

        except Exception as e:
            logger.error(f"Error executing query via Joern client: {e}")
            return QueryResult(success=False, error=str(e))

    def _parse_output(self, output: str) -> Union[list, int, float, str]:
        """Parse Joern query output"""
        if not output or not output.strip():
            return []

        # Remove ANSI color codes
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output = ansi_escape.sub('', output)

        # First, check for codebadger_result markers (for text output queries)
        marker_match = re.search(r'<codebadger_result>\s*(.*?)\s*</codebadger_result>', output, re.DOTALL)
        if marker_match:
            # Return the extracted content as a string in a list
            return [marker_match.group(1).strip()]

        # Try to extract JSON from Scala REPL output
        # Look for JSON within triple quotes
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
            # Return as plain text
            # If output looks like a simple number, return as primitive
            s = output.strip()
            # Try int
            try:
                return int(s)
            except Exception:
                pass
            # Try float
            try:
                return float(s)
            except Exception:
                pass
            # If not numeric, return as string
            return s
