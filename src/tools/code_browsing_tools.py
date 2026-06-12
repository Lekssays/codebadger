"""
Code Browsing MCP Tools for CodeBadger Server
Tools for exploring and navigating codebase structure
"""

import logging
import os
from typing import Any, Dict, Optional, Annotated
from pydantic import Field

from ..exceptions import (
            ValidationError,
)
from ..utils.validators import (
    validate_codebase_hash,
    validate_cpgql_query,
)
from .queries import QueryLoader
from ._common import require_cpg, unwrap_result

logger = logging.getLogger(__name__)


def _get_playground_path() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "playground"))


def register_code_browsing_tools(mcp, services: dict):
    """Register code browsing MCP tools with the FastMCP server"""


    @mcp.tool(
        description="""List methods/functions in the codebase.

Discover all methods and functions defined in the analyzed code.

Args:
    codebase_hash: The codebase hash.
    name_pattern: Regex filter for method name.
    file_pattern: Regex filter for filename.
    callee_pattern: Regex filter for methods that call this specific function.
    include_external: Include external (library) methods (default False).
    limit: Max results.
    page: Page number.

Returns:
    {
        "success": true,
        "methods": [{"name": "main", "filename": "main.c", ...}],
        "total": 100,
        "page": 1,
        "total_pages": 5
    }

Notes:
    - Use name_pattern to find specific methods.
    - Use callee_pattern to find usages (e.g., who calls 'malloc').

Examples:
    list_methods(codebase_hash="abc", name_pattern=".*auth.*")
    list_methods(codebase_hash="abc", callee_pattern="memcpy")""",
    )
    def list_methods(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        name_pattern: Annotated[Optional[str], Field(description="Optional regex to filter method names (e.g., '.*authenticate.*')")] = None,
        file_pattern: Annotated[Optional[str], Field(description="Optional regex to filter by file path")] = None,
        callee_pattern: Annotated[Optional[str], Field(description="Optional regex to filter for methods that call a specific function (e.g., 'memcpy|free|malloc')")] = None,
        include_external: Annotated[bool, Field(description="Include external/library methods")] = False,
        limit: Annotated[int, Field(description="Maximum number of results to fetch for caching")] = 1000,
        page: Annotated[int, Field(description="Page number")] = 1,
        page_size: Annotated[int, Field(description="Number of results per page")] = 100,
    ) -> Dict[str, Any]:
        """Discover all methods and functions defined in the codebase."""
        try:
            code_browsing_service = services["code_browsing_service"]
            return code_browsing_service.list_methods(
                codebase_hash=codebase_hash,
                name_pattern=name_pattern,
                file_pattern=file_pattern,
                callee_pattern=callee_pattern,
                include_external=include_external,
                limit=limit,
                page=page,
                page_size=page_size,
            )
        except ValidationError as e:
            logger.error(f"Error listing methods: {e}")
            return {
                "success": False,
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }


    @mcp.tool(
        description="""List function/method calls in the codebase.

Discover call relationships between functions.

Args:
    codebase_hash: The codebase hash.
    caller_pattern: Regex for the calling method.
    callee_pattern: Regex for the called method.
    limit: Max results.
    page: Page number.

Returns:
    {
        "success": true,
        "calls": [
            {"caller": "main", "callee": "printf", "fileName": "main.c", "lineNumber": 10}
        ],
        "total": 1
    }

Notes:
    - Useful for finding where specific functions are used.

Examples:
    list_calls(codebase_hash="abc", callee_pattern="strcpy")
    list_calls(codebase_hash="abc", caller_pattern="main")""",
    )
    def list_calls(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        caller_pattern: Annotated[Optional[str], Field(description="Optional regex to filter caller method names")] = None,
        callee_pattern: Annotated[Optional[str], Field(description="Optional regex to filter callee method names")] = None,
        limit: Annotated[int, Field(description="Maximum number of results to fetch for caching")] = 1000,
        page: Annotated[int, Field(description="Page number")] = 1,
        page_size: Annotated[int, Field(description="Number of results per page")] = 100,
    ) -> Dict[str, Any]:
        """Find function call relationships in the codebase."""
        try:
            code_browsing_service = services["code_browsing_service"]
            return code_browsing_service.list_calls(
                codebase_hash=codebase_hash,
                caller_pattern=caller_pattern,
                callee_pattern=callee_pattern,
                limit=limit,
                page=page,
                page_size=page_size,
            )
        except ValidationError as e:
            logger.error(f"Error listing calls: {e}")
            return {
                "success": False,
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }


    @mcp.tool(
        description="""Get the call graph for a specific method.

Understand what functions a method calls (outgoing) or what functions
call it (incoming).

Args:
    codebase_hash: The codebase hash.
    method_name: Name of the method to analyze.
    depth: Traversal depth (default 5).
    direction: 'outgoing' (callees) or 'incoming' (callers).

Returns:
    A human-readable text summary:
    
    Call Graph for main (outgoing)
    ============================================================
    Root: main at main.c:10
    
    [DEPTH 1]
      main → init (config.c:25)
      main → process (core.c:50)
    
    [DEPTH 2]
      init → load_config (config.c:100)
      process → validate (core.c:120)
    
    Total: 4 edges

Notes:
    - Essential for impact analysis and understanding code dependencies.
    - Returns plain text.
    - Includes file and line number for each call target.
    - Line numbers refer to where the caller function starts, not the specific call site.

Examples:
    get_call_graph(codebase_hash="abc", method_name="main", direction="outgoing")
    get_call_graph(codebase_hash="abc", method_name="vuln_func", direction="incoming")""",
    )
    def get_call_graph(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        method_name: Annotated[str, Field(description="Name of the method to analyze (can be regex)")],
        depth: Annotated[int, Field(description="How many levels deep to traverse (max recommended: 10)")] = 5,
        direction: Annotated[str, Field(description="Either 'outgoing' (callees) or 'incoming' (callers)")] = "outgoing",
    ) -> str:
        """Build the call graph showing callers or callees for a method."""
        try:
            validate_codebase_hash(codebase_hash)

            if depth < 1 or depth > 15:
                raise ValidationError("Depth must be between 1 and 15")

            if direction not in ["outgoing", "incoming"]:
                raise ValidationError("Direction must be 'outgoing' or 'incoming'")

            query_executor = services["query_executor"]

            codebase_info = require_cpg(services, codebase_hash)

            query = QueryLoader.load(
                "call_graph",
                method_name=method_name,
                depth=depth,
                direction=direction
            )

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=120,
                limit=500,
            )

            return unwrap_result(result)

        except ValidationError as e:
            logger.error(f"Error getting call graph: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"


    @mcp.tool(
        description="""List parameters of a specific method.

Get detailed information about method parameters including their names,
types, and order.

Args:
    codebase_hash: The codebase hash.
    method_name: Method name pattern.

Returns:
    {
        "success": true,
        "methods": [
            {
                "method": "authenticate",
                "parameters": [
                    {"name": "username", "type": "string", "index": 1},
                    {"name": "password", "type": "string", "index": 2}
                ]
            }
        ]
    }

Notes:
    - Useful for understanding function signatures.

Examples:
    list_parameters(codebase_hash="abc", method_name="login")""",
    )
    def list_parameters(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        method_name: Annotated[str, Field(description="Name of the method (can be regex pattern)")],
    ) -> Dict[str, Any]:
        """Get parameter names, types, and order for a method."""
        try:
            code_browsing_service = services["code_browsing_service"]
            return code_browsing_service.list_parameters(
                codebase_hash=codebase_hash,
                method_name=method_name,
            )
        except ValidationError as e:
            logger.error(f"Error listing parameters: {e}")
            return {
                "success": False,
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }


    @mcp.tool(
        description="""Execute a raw CPGQL query against the codebase.

Run arbitrary Code Property Graph Query Language (CPGQL) queries
for advanced analysis.

Args:
    codebase_hash: The codebase hash.
    query: The CPGQL query string.
    timeout: Optional execution timeout.
    validate: Validate syntax before execution (default False).

Returns:
    {
        "success": true,
        "stdout": "raw output",
        "stderr": "error output"
    }

Notes:
    - Power user tool. Requires knowledge of Joern CPGQL.
    - Use get_cpgql_syntax_help for reference.

Examples:
    run_cpgql_query(codebase_hash="abc", query="cpg.method.name.l")""",
    )
    def run_cpgql_query(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        query: Annotated[str, Field(description="The CPGQL query string to execute")],
        timeout: Annotated[Optional[int], Field(description="Optional timeout in seconds")] = None,
        validate: Annotated[bool, Field(description="If true, validate query syntax before executing")] = False,
    ) -> Dict[str, Any]:
        """Run a raw CPGQL query for custom CPG analysis."""
        try:
            from ..utils.cpgql_validator import CPGQLValidator

            validate_codebase_hash(codebase_hash)

            if not query or not query.strip():
                raise ValidationError("Query cannot be empty")

            # Security blocklist for the raw-query escape hatch. Always enforced
            # (independent of the optional `validate` syntax check below) — this is
            # the one tool that forwards untrusted text to the Joern Scala REPL.
            # Defense-in-depth: the real boundary is the Joern worker sandbox.
            validate_cpgql_query(query.strip())

            query_executor = services["query_executor"]

            codebase_info = require_cpg(services, codebase_hash)

            validation_result = None
            if validate:
                validation_result = CPGQLValidator.validate_query(query.strip())
                if not validation_result['valid'] and validation_result['errors']:
                    return {
                        "success": False,
                        "validation": validation_result,
                        "error": "Query validation failed",
                    }

            # Dataflow queries (reachableByFlows) legitimately need more time.
            # Use a higher default when the caller didn't specify an explicit timeout.
            from ..services.query_executor import _DATAFLOW_PATTERNS, _DATAFLOW_DEFAULT_TIMEOUT
            _effective_timeout = timeout
            if _effective_timeout is None:
                _effective_timeout = (
                    _DATAFLOW_DEFAULT_TIMEOUT
                    if any(p in query for p in _DATAFLOW_PATTERNS)
                    else 30
                )

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query.strip(),
                timeout=_effective_timeout,
                limit=None,
            )

            response = {
                "success": result.success,
                "data": result.data,
                "row_count": result.row_count,
                "execution_time": getattr(result, "execution_time", None),
            }

            if getattr(result, "truncated", False):
                response["truncated"] = True
                response["truncation_note"] = (
                    "Results were capped by the server's size limit; refine the query "
                    "(filter by filename, add .take(n), or narrow the traversal) to see the rest."
                )

            if not result.success and getattr(result, "error", None):
                response["error"] = result.error
            if not result.success and getattr(result, "error_code", None):
                response["error_code"] = result.error_code

            if validate and validation_result:
                response["validation"] = validation_result

            if not response["success"] and result.error:
                error_suggestion = CPGQLValidator.get_error_suggestion(result.error)
                if error_suggestion:
                    response["suggestion"] = error_suggestion
                    response["help"] = {
                        "description": error_suggestion.get("description"),
                        "solution": error_suggestion.get("solution"),
                        "examples": error_suggestion.get("examples", [])[:3],
                    }
            return response

        except ValidationError as e:
            logger.error(f"Error executing CPGQL query: {e}")
            return {
                "success": False,
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Unexpected error executing CPGQL query: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }

    @mcp.tool(
        description="""Find bounds checks near buffer access.

Verify if buffer accesses have corresponding bounds checks by analyzing
comparison operations involving the index variable.

Args:
    codebase_hash: The codebase hash.
    buffer_access_location: 'filename:line' of the access (e.g., 'buf[i] = x').

Returns:
    A human-readable text summary of the bounds check analysis.

Notes:
    - Helps identify potential buffer overflow vulnerabilities.
    - Checks for missing bounds checks or checks that happen too late.
    - filename in buffer_access_location should be relative to the project root (e.g., 'src/parser.c:100').

Examples:
    find_bounds_checks(codebase_hash="abc", buffer_access_location="parser.c:3393")""",
    )
    def find_bounds_checks(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        buffer_access_location: Annotated[str, Field(description="Location of buffer access in format 'filename:line' (e.g., 'parser.c:3393')")],
    ) -> str:
        """Check if buffer accesses have proper bounds validation."""
        try:
            validate_codebase_hash(codebase_hash)

            if ":" not in buffer_access_location:
                raise ValidationError(
                    "buffer_access_location must be in format 'filename:line'"
                )

            filename, line_str = buffer_access_location.rsplit(":", 1)
            try:
                line_num = int(line_str)
            except ValueError:
                raise ValidationError(f"Invalid line number: {line_str}")

            query_executor = services["query_executor"]

            codebase_info = require_cpg(services, codebase_hash)

            query = QueryLoader.load(
                "bounds_checks",
                filename=filename,
                line_num=line_num
            )

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
            )

            if result.success and result.data:
                # Text queries return a single-element list wrapping the rendered text.
                output = result.data[0] if isinstance(result.data, list) else str(result.data)
                return output.strip()
            else:
                return f"Error: {result.error if not result.success else 'No data returned'}"

        except ValidationError as e:
            logger.error(f"Error finding bounds checks: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"

    @mcp.tool(
        description="""Get comprehensive CPGQL syntax help and examples.

Provides syntax documentation, common patterns, node types, and error solutions.

Args:
    None.

Returns:
    {
        "success": true,
        "syntax_helpers": {...},
        "error_guide": {...},
        "quick_reference": {...}
    }

Notes:
    - Use this to learn how to write queries for run_cpgql_query.

Examples:
    get_cpgql_syntax_help()""",
    )
    def get_cpgql_syntax_help() -> Dict[str, Any]:
        """Get CPGQL syntax documentation and common query patterns."""
        try:
            from ..utils.cpgql_validator import CPGQLValidator
            
            helpers = CPGQLValidator.get_syntax_helpers()
            
            return {
                "success": True,
                "syntax_helpers": helpers,
                "error_guide": {
                    "common_errors": [
                        {
                            "error": "matches is not a member of Iterator[String]",
                            "cause": "Trying to call .matches() directly on a stream",
                            "solution": "Use .filter() with lambda: .filter(_.property.matches(\"regex\"))",
                            "examples": [
                                "cpg.method.filter(_.name.matches(\"process.*\")).l",
                                "cpg.call.filter(_.code.matches(\".*malloc.*\")).l",
                            ]
                        },
                        {
                            "error": "value contains is not a member",
                            "cause": "Substring matching syntax error",
                            "solution": "Use inside filter lambda: .filter(_.property.contains(\"text\"))",
                            "examples": [
                                "cpg.literal.filter(_.code.contains(\"password\")).l",
                                "cpg.call.filter(_.code.contains(\"system\")).l",
                            ]
                        },
                        {
                            "error": "not found: value _",
                            "cause": "Lambda syntax error or invalid property access",
                            "solution": "Ensure lambda uses underscore: _ (not $, @, or other symbols)",
                            "examples": [
                                "cpg.method.filter(_.name.nonEmpty).l",
                                "cpg.call.where(_.method.name != \"\").l",
                            ]
                        },
                        {
                            "error": "Unmatched closing parenthesis",
                            "cause": "Syntax error - mismatched parentheses",
                            "solution": "Count opening and closing parentheses - they must match",
                            "examples": [
                                "cpg.method.filter(_.name.matches(\"test.*\")).l",
                            ]
                        },
                    ],
                    "tips": [
                        "Always use .l or .toJsonPretty at the end to get results",
                        "Use .filter(_) or .where(_) with underscore lambda for conditions",
                        "String literals in filter need quotes: filter(_.name == \"value\")",
                        "Regex patterns must be in quotes and escaped: \".*pattern.*\"",
                        "For better performance, filter before calling .l",
                    ]
                },
                "quick_reference": {
                    "string_methods": {
                        "exact_match": '.name("exactString")',
                        "regex_match": '.filter(_.name.matches("regex.*"))',
                        "substring_match": '.filter(_.code.contains("substring"))',
                        "case_insensitive": '.filter(_.name.toLowerCase.matches("pattern.*"))',
                        "not_empty": '.filter(_.name.nonEmpty)',
                        "equals": '.filter(_.name == "value")',
                        "not_equals": '.filter(_.name != "value")',
                    },
                    "common_node_properties": {
                        "method": ["name", "filename", "signature", "lineNumber", "isExternal"],
                        "call": ["name", "code", "filename", "lineNumber"],
                        "literal": ["code", "typeFullName", "filename", "lineNumber"],
                        "parameter": ["name", "typeFullName", "index"],
                        "file": ["name", "hash"],
                    },
                    "result_formatting": {
                        "json_pretty": '.toJsonPretty  # Pretty-printed JSON',
                        "json_compact": '.toJson  # Compact JSON',
                        "list": '.l  # Scala list (automatically formatted)',
                        "count": '.size  # Get count as number',
                        "single_item": '.head  # Get first result',
                        "optional": '.headOption  # Get optional first result',
                    }
                }
            }
        except Exception as e:
            logger.error(f"Error getting CPGQL syntax help: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }

    # Semantic analysis tools

    @mcp.tool(
        description="""Get control flow graph (CFG) for a method.

Understand the control flow of a method with a human-readable graph.

Args:
    codebase_hash: The codebase hash.
    method_name: Name of the method.
    max_nodes: Limit nodes returned (default 100).

Returns:
    A human-readable text graph:
    
    Control Flow Graph for main
    ============================================================
    Nodes:
      [1001] ControlStructure: if (x > 0)
      [1002] Return: return x
    
    Edges:
      [1001] -> [1002] [Label: TRUE]

Notes:
    - Essential for understanding loops, conditions, and execution paths.
    - Returns plain text.

Examples:
    get_cfg(codebase_hash="abc", method_name="main")""",
    )
    def get_cfg(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        method_name: Annotated[str, Field(description="Name of the method (can be regex pattern)")],
        max_nodes: Annotated[int, Field(description="Maximum CFG nodes to return (for large methods)")] = 100,
    ) -> str:
        """Get nodes and edges representing control flow in a method."""
        try:
            validate_codebase_hash(codebase_hash)
            query_executor = services["query_executor"]

            codebase_info = require_cpg(services, codebase_hash)

            query = QueryLoader.load(
                "cfg",
                method_name=method_name,
                max_nodes=max_nodes
            )

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
                limit=max_nodes,
            )

            return unwrap_result(result)

        except ValidationError as e:
            logger.error(f"Error getting CFG: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error getting CFG: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"


    @mcp.tool(
        description="""Get type/struct definition with members.

Inspect struct or class memory layouts.

Args:
    codebase_hash: The codebase hash.
    type_name: Regex for type name.
    limit: Max results.

Returns:
    {
        "success": true,
        "types": [
            {
                "name": "UserStruct",
                "members": [{"name": "id", "type": "int"}, {"name": "buf", "type": "char*"}]
            }
        ]
    }

Notes:
    - Essential for understanding buffer sizes and memory layouts.
    - Does not read header files; uses CPG type info.

Examples:
    get_type_definition(codebase_hash="abc", type_name=".*request_t.*")""",
    )
    def get_type_definition(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        type_name: Annotated[str, Field(description="Type name pattern (regex, e.g., '.*Buffer.*')")],
        limit: Annotated[int, Field(description="Maximum types to return")] = 10,
    ) -> Dict[str, Any]:
        """Get struct/class definition with member names and types."""
        try:
            validate_codebase_hash(codebase_hash)
            query_executor = services["query_executor"]

            codebase_info = require_cpg(services, codebase_hash)

            query = QueryLoader.load(
                "type_definition",
                type_name=type_name,
                limit=limit
            )

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
                limit=limit,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": result.error,
                }

            types = []
            if result.data:
                for item in result.data:
                    if isinstance(item, dict):
                        types.append({
                            "name": item.get("_1"),
                            "fullName": item.get("_2"),
                            "filename": item.get("_3"),
                            "lineNumber": item.get("_4"),
                            "members": item.get("_5", []),
                        })

            return {
                "success": True,
                "types": types,
                "total": len(types),
            }

        except ValidationError as e:
            logger.error(f"Error getting type definition: {e}")
            return {
                "success": False,
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Unexpected error getting type definition: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }


