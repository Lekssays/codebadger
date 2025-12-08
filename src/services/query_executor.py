import json
import logging
import time
from typing import Dict, List, Optional, Any

from ..models import QueryResult
from ..exceptions import QueryExecutionError
from .joern_client import JoernServerClient
from .joern_server_manager import JoernServerManager

logger = logging.getLogger(__name__)


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

            # Create a client for this specific server
            joern_client = JoernServerClient(host="localhost", port=port)

            # Normalize query for JSON output
            normalized_query = self._normalize_query(query, limit)
            logger.debug(f"Normalized query for execution: {normalized_query}")

            # Execute query via HTTP API
            result = self._execute_via_client(joern_client, normalized_query, timeout)
            result.execution_time = time.time() - start_time

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
        """Normalize query to ensure JSON output"""
        query = query.strip()

        # Check if this is a block query that already produces JSON output
        # Block queries start with { and end with }
        if query.startswith('{') and query.endswith('}'):
            # Check if the block contains .toJsonPretty or .toJson inside
            if '.toJsonPretty' in query or '.toJson' in query:
                # Block already produces JSON, don't modify
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

    def _execute_via_client(self, joern_client: JoernServerClient, query: str, timeout: int) -> QueryResult:
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
                # Query failed
                stderr = result.get("stderr", "")
                logger.error(f"Query execution failed: {stderr}")
                return QueryResult(success=False, error=stderr)

        except Exception as e:
            logger.error(f"Error executing query via Joern client: {e}")
            return QueryResult(success=False, error=str(e))

    def _parse_output(self, output: str) -> list:
        """Parse Joern query output"""
        if not output or not output.strip():
            return []

        # Remove ANSI color codes
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output = ansi_escape.sub('', output)

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
