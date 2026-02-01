"""
Code Browsing MCP Tools for CodeBadger Server
Tools for exploring and navigating codebase structure
"""

import logging
import os
import re
from typing import Any, Dict, Optional, Annotated
from pydantic import Field

from ..exceptions import (
            ValidationError,
)
from ..utils.validators import validate_codebase_hash

logger = logging.getLogger(__name__)


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
    list_methods(codebase_hash="abc", callee_pattern="memcpy")"""
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
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool(
        description="""List source files in the codebase as a tree structure.

Args:
    codebase_hash: The codebase hash.
    local_path: Optional relative path to list from.

Returns:
    {
        "success": true,
        "tree": "project/\\n├── src/\\n│   ├── main.c\\n│   └── utils.c\\n└── README.md",
        "total": 4
    }

Notes:
    - Returns a text-based tree representation of the file structure.
    - The .git folder is automatically excluded.
    - Each directory is limited to showing 20 items (50 when local_path is specified).

Examples:
    list_files(codebase_hash="abc")
    list_files(codebase_hash="abc", local_path="src/lib")"""
    )
    def list_files(
        codebase_hash: Annotated[str, Field(description="The codebase hash from create_cpg_create")],
        local_path: Annotated[Optional[str], Field(description="Optional path inside the codebase to list (relative to source root or absolute). When provided, per-directory limit is increased to 50.")] = None,
    ) -> Dict[str, Any]:
        """Get all source files as a tree structure."""
        try:
            code_browsing_service = services["code_browsing_service"]
            return code_browsing_service.list_files(
                codebase_hash=codebase_hash,
                local_path=local_path,
            )
        except ValidationError as e:
            logger.error(f"Error listing files: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }


    @mcp.tool(
        description="""Get the source code of a specific method.

Retrieve the actual source code for a method to understand its implementation.

Args:
    codebase_hash: The codebase hash.
    method_name: Exact name or regex for method.
    filename: Optional filename to disambiguate (relative to project root).

Returns:
    {
        "success": true,
        "methods": [
            {
                "name": "main",
                "filename": "main.c",
                "lineNumber": 10,
                "lineNumberEnd": 20,
                "code": "int main() { ... }"
            }
        ]
    }

Notes:
    - Returns list in case multiple methods match the pattern.
    - filename should be relative to the project root (e.g., 'src/main.c' not '/absolute/path/src/main.c').

Examples:
    get_method_source(codebase_hash="abc", method_name="main")
    get_method_source(codebase_hash="abc", method_name="init", filename="driver.c")"""
    )
    def get_method_source(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        method_name: Annotated[str, Field(description="Name of the method (can be regex pattern)")],
        filename: Annotated[Optional[str], Field(description="Optional filename to disambiguate methods with same name")] = None,
    ) -> Dict[str, Any]:
        """Retrieve the full source code of a method by name."""
        try:
            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Build query to get method metadata
            query_parts = [f'cpg.method.name("{method_name}")']

            if filename:
                query_parts.append(f'.filename(".*{filename}.*")')

            query_parts.append(
                ".map(m => (m.name, m.filename, m.lineNumber.getOrElse(-1), m.lineNumberEnd.getOrElse(-1)))"
            )
            query = "".join(query_parts) + ".toJsonPretty"

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
                limit=10,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            methods = []
            method_name_result = ""
            method_filename = ""
            line_number = -1
            line_number_end = -1

            for item in result.data:
                if isinstance(item, dict):
                    method_name_result = item.get("_1", "")
                    method_filename = item.get("_2", "")
                    line_number = item.get("_3", -1)
                    line_number_end = item.get("_4", -1)

            # Get the full source code using file reading logic
            if method_filename and line_number > 0 and line_number_end > 0:
                try:
                    # Get playground path
                    playground_path = os.path.abspath(
                        os.path.join(
                            os.path.dirname(__file__), "..", "..", "playground"
                        )
                    )

                    # Get source directory from session
                    if codebase_info.source_type == "github":
                        # For GitHub repos, use the cached directory
                        from .core_tools import get_cpg_cache_key
                        cpg_cache_key = get_cpg_cache_key(
                            codebase_info.source_type, codebase_info.source_path, codebase_info.language
                        )
                        source_dir = os.path.join(
                            playground_path, "codebases", cpg_cache_key
                        )
                    else:
                        # For local paths, use the session source path directly
                        source_path = codebase_info.source_path
                        if not os.path.isabs(source_path):
                            source_path = os.path.abspath(source_path)
                        source_dir = source_path

                    # Construct full file path
                    file_path = os.path.join(source_dir, method_filename)

                    # Check if file exists and read it
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        with open(
                            file_path, "r", encoding="utf-8", errors="replace"
                        ) as f:
                            lines = f.readlines()

                        # Validate line numbers
                        total_lines = len(lines)
                        if (
                            line_number <= total_lines
                            and line_number_end >= line_number
                        ):
                            # Extract the code snippet (lines are 0-indexed in the list)
                            actual_end_line = min(line_number_end, total_lines)
                            code_lines = lines[line_number - 1: actual_end_line]
                            full_code = "".join(code_lines)
                        else:
                            full_code = f"// Invalid line range: {line_number}-{line_number_end}, file has {total_lines} lines"
                    else:
                        full_code = f"// Source file not found: {method_filename}"
                except Exception as e:
                    full_code = f"// Error reading source file: {str(e)}"
            else:
                full_code = "// Unable to determine line range for method"

            methods.append(
                {
                    "name": method_name_result,
                    "filename": method_filename,
                    "lineNumber": line_number,
                    "lineNumberEnd": line_number_end,
                    "code": full_code,
                }
            )

            return {"success": True, "methods": methods, "total": len(methods)}

        except ValidationError as e:
            logger.error(f"Error getting method source: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
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
    list_calls(codebase_hash="abc", caller_pattern="main")"""
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
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
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
    {
        "success": true,
        "root_method": "authenticate",
        "direction": "outgoing",
        "calls": [
            {"from": "authenticate", "to": "validate_password", "depth": 1},
            {"from": "validate_password", "to": "hash_password", "depth": 2}
        ]
    }

Notes:
    - Essential for impact analysis and understanding code dependencies.

Examples:
    get_call_graph(codebase_hash="abc", method_name="main", direction="outgoing")
    get_call_graph(codebase_hash="abc", method_name="vuln_func", direction="incoming")"""
    )
    def get_call_graph(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        method_name: Annotated[str, Field(description="Name of the method to analyze (can be regex)")],
        depth: Annotated[int, Field(description="How many levels deep to traverse (max recommended: 10)")] = 5,
        direction: Annotated[str, Field(description="Either 'outgoing' (callees) or 'incoming' (callers)")] = "outgoing",
    ) -> Dict[str, Any]:
        """Build the call graph showing callers or callees for a method."""
        try:
            validate_codebase_hash(codebase_hash)

            if depth < 1 or depth > 15:
                raise ValidationError("Depth must be between 1 and 15")

            if direction not in ["outgoing", "incoming"]:
                raise ValidationError("Direction must be 'outgoing' or 'incoming'")

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Build improved CPGQL query with proper structure
            query_template = r'''{
  def escapeJson(s: String): String = {
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
  }

  val methodName = "METHOD_NAME_PLACEHOLDER"
  val maxDepth = DEPTH_PLACEHOLDER
  val direction = "DIRECTION_PLACEHOLDER"
  val maxResults = 500

  val rootMethodOpt = cpg.method.name(methodName).headOption

  val result = rootMethodOpt match {
    case Some(rootMethod) => {
      val rootName = rootMethod.name
      val allCalls = scala.collection.mutable.ListBuffer[Map[String, Any]]()
      
      if (direction == "outgoing") {
        var toVisit = scala.collection.mutable.Queue[(io.shiftleft.codepropertygraph.generated.nodes.Method, Int)]()
        var visited = Set[String]()
        var edgesVisited = Set[(String, String, Int)]()
        
        toVisit.enqueue((rootMethod, 0))
        
        while (toVisit.nonEmpty && allCalls.size < maxResults) {
          val (current, currentDepth) = toVisit.dequeue()
          val currentName = current.name
          
          if (!visited.contains(currentName) && currentDepth < maxDepth) {
            visited = visited + currentName
            
            val callees = current.call.callee.l
              .filterNot(_.name.startsWith("<operator>"))
              .take(50)
            
            for (callee <- callees) {
              val calleeName = callee.name
              val edgeKey = (currentName, calleeName, currentDepth + 1)
              
              if (!edgesVisited.contains(edgeKey)) {
                edgesVisited = edgesVisited + edgeKey
                allCalls += Map(
                  "from" -> currentName,
                  "to" -> escapeJson(calleeName),
                  "depth" -> (currentDepth + 1)
                )
                
                if (!visited.contains(calleeName) && currentDepth + 1 < maxDepth) {
                  toVisit.enqueue((callee, currentDepth + 1))
                }
              }
            }
          }
        }
        
        List(
          Map(
            "success" -> true,
            "root_method" -> rootName,
            "direction" -> direction,
            "calls" -> allCalls.toList.sortBy(c => (c.getOrElse("depth", 0).asInstanceOf[Int], c.getOrElse("from", "").asInstanceOf[String])),
            "total" -> allCalls.size
          )
        )
      } else if (direction == "incoming") {
        var toVisit = scala.collection.mutable.Queue[(io.shiftleft.codepropertygraph.generated.nodes.Method, Int)]()
        var visited = Set[String]()
        var edgesVisited = Set[(String, String, Int)]()
        
        val directCallers = rootMethod.caller.l.filterNot(_.name.startsWith("<operator>"))
        for (caller <- directCallers) {
          val edgeKey = (caller.name, rootName, 1)
          if (!edgesVisited.contains(edgeKey)) {
            edgesVisited = edgesVisited + edgeKey
            allCalls += Map(
              "from" -> escapeJson(caller.name),
              "to" -> rootName,
              "depth" -> 1
            )
            toVisit.enqueue((caller, 1))
          }
        }
        
        visited = visited + rootName
        
        while (toVisit.nonEmpty && allCalls.size < maxResults) {
          val (current, currentDepth) = toVisit.dequeue()
          val currentName = current.name
          
          if (!visited.contains(currentName) && currentDepth < maxDepth) {
            visited = visited + currentName
            
            val incomingCallers = current.caller.l
              .filterNot(_.name.startsWith("<operator>"))
              .take(50)
            
            for (caller <- incomingCallers) {
              val callerName = caller.name
              val edgeKey = (callerName, rootName, currentDepth + 1)
              
              if (!edgesVisited.contains(edgeKey)) {
                edgesVisited = edgesVisited + edgeKey
                allCalls += Map(
                  "from" -> escapeJson(callerName),
                  "to" -> rootName,
                  "depth" -> (currentDepth + 1)
                )
                
                if (!visited.contains(callerName) && currentDepth + 1 < maxDepth) {
                  toVisit.enqueue((caller, currentDepth + 1))
                }
              }
            }
          }
        }
        
        List(
          Map(
            "success" -> true,
            "root_method" -> rootName,
            "direction" -> direction,
            "calls" -> allCalls.toList.sortBy(c => (c.getOrElse("depth", 0).asInstanceOf[Int], c.getOrElse("from", "").asInstanceOf[String])),
            "total" -> allCalls.size
          )
        )
      } else {
        List(
          Map(
            "success" -> false,
            "error" -> Map(
              "code" -> "INVALID_DIRECTION",
              "message" -> s"Direction must be 'outgoing' or 'incoming', got: '$direction'"
            )
          )
        )
      }
    }
    case None => {
      List(
        Map(
          "success" -> false,
          "error" -> Map(
            "code" -> "METHOD_NOT_FOUND",
            "message" -> s"Method not found: $methodName"
          )
        )
      )
    }
  }

  result.toJsonPretty
}'''

            query = query_template.replace("METHOD_NAME_PLACEHOLDER", method_name)
            query = query.replace("DEPTH_PLACEHOLDER", str(depth))
            query = query.replace("DIRECTION_PLACEHOLDER", direction)

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=120,
                limit=500,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            # Parse the JSON result
            import json

            if isinstance(result.data, list) and len(result.data) > 0:
                result_data = result.data[0]

                # Handle JSON string response
                if isinstance(result_data, str):
                    result_obj = json.loads(result_data)
                else:
                    result_obj = result_data

                # Extract calls and ensure proper structure
                if result_obj.get("success"):
                    return {
                        "success": True,
                        "root_method": result_obj.get("root_method", method_name),
                        "direction": result_obj.get("direction", direction),
                        "calls": result_obj.get("calls", []),
                        "total": result_obj.get("total", 0),
                    }
                else:
                    return {
                        "success": False,
                        "error": result_obj.get("error", {"code": "UNKNOWN", "message": "Unknown error"}),
                    }
            else:
                return {
                    "success": False,
                    "error": {"code": "NO_RESULT", "message": "Query returned no results"},
                }

        except ValidationError as e:
            logger.error(f"Error getting call graph: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

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
    list_parameters(codebase_hash="abc", method_name="login")"""
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
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }


    @mcp.tool(
        description="""Get a high-level summary of the codebase structure.

Provides an overview including file count, method count, language,
and other metadata.

Args:
    codebase_hash: The codebase hash.

Returns:
    {
        "success": true,
        "summary": {
            "language": "C",
            "total_files": 15,
            "total_methods": 127
            "lines_of_code": 5432
        }
    }

Notes:
    - Useful as a first step when exploring a new codebase.

Examples:
    get_codebase_summary(codebase_hash="abc")"""
    )
    def get_codebase_summary(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")]
    ) -> Dict[str, Any]:
        """Get file count, method count, and other high-level metrics."""
        try:
            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Robust query to get all stats in one go
            stats_query = """
            {
                val numFiles = cpg.file.size
                val numMethods = cpg.method.size
                val numMethodsUser = cpg.method.isExternal(false).size
                val numCalls = cpg.call.size
                val numLiterals = cpg.literal.size
                val language = cpg.metaData.language.headOption.getOrElse("unknown")
                
                Map(
                    "success" -> true,
                    "language" -> language,
                    "total_files" -> numFiles,
                    "total_methods" -> numMethods,
                    "user_defined_methods" -> numMethodsUser,
                    "total_calls" -> numCalls,
                    "total_literals" -> numLiterals
                ).toJsonPretty
            }
            """

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=stats_query,
                timeout=30,
                limit=1,
            )

            if not result.success:
                logger.error(f"Query failed: {result.error}")
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error}
                }

            import json
            summary = {
                "language": "unknown",
                "total_files": 0,
                "total_methods": 0,
                "user_defined_methods": 0,
                "external_methods": 0,
                "total_calls": 0,
                "total_literals": 0,
            }

            try:
                # result.data can be:
                # 1. List of single-key dicts (Scala Map.toJsonPretty format): [{"key1": val1}, {"key2": val2}, ...]
                # 2. List containing a single dict with all keys (expected format)
                # 3. List containing a JSON string (to be parsed)
                if result.data and isinstance(result.data, list) and len(result.data) > 0:
                    data = {}
                    
                    # Check if it's a list of single-key dicts (Scala Map format)
                    if all(isinstance(item, dict) and len(item) == 1 for item in result.data):
                        # Merge all single-key dicts into one
                        for item in result.data:
                            data.update(item)
                        logger.debug(f"Merged Scala Map format data: {data}")
                    else:
                        # First element is either a dict or a JSON string
                        raw_data = result.data[0]
                        if isinstance(raw_data, str):
                            data = json.loads(raw_data)
                        elif isinstance(raw_data, dict):
                            data = raw_data
                        else:
                            data = {}
                    
                    # Extract data based on the format
                    if "_1" in data:
                        # Mock format: {"_1": language, "_2": 5, "_3": 10, ...}
                        summary["language"] = data.get("_1", "unknown")
                        summary["total_files"] = data.get("_2", 0)
                        summary["total_methods"] = data.get("_3", 0)
                        summary["user_defined_methods"] = data.get("_4", 0)
                        summary["total_calls"] = data.get("_5", 0)
                        summary["total_literals"] = data.get("_6", 0)
                        summary["external_methods"] = (
                            summary["total_methods"] - summary["user_defined_methods"]
                        )
                    else:
                        # Joern/Scala format with named keys
                        summary["language"] = data.get("language", "unknown")
                        summary["total_files"] = data.get("total_files", 0)
                        summary["total_methods"] = data.get("total_methods", 0)
                        summary["user_defined_methods"] = data.get("user_defined_methods", 0)
                        summary["total_calls"] = data.get("total_calls", 0)
                        summary["total_literals"] = data.get("total_literals", 0)
                        summary["external_methods"] = (
                            summary["total_methods"] - summary["user_defined_methods"]
                        )
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse summary JSON: {e}")
                return {
                    "success": False,
                    "error": {"code": "PARSE_ERROR", "message": f"Failed to parse result: {str(e)}"}
                }
            except Exception as e:
                logger.error(f"Error processing summary data: {e}")
                # Return partial summary instead of failing completely

            return {"success": True, "summary": summary}

        except ValidationError as e:
            logger.error(f"Error getting codebase summary: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool(
        description="""Retrieve a code snippet from a specific file with line range.

Get the source code from a file between specified start and end line numbers.

Args:
    codebase_hash: The codebase hash.
    filename: Relative path to source file (relative to project root).
    start_line: Start line (1-indexed).
    end_line: End line (1-indexed).

Returns:
    {
        "success": true,
        "filename": "main.c",
        "start_line": 10,
        "end_line": 20,
        "code": "example code here"
    }

Notes:
    - Useful for examining specific parts of the codebase.
    - filename should be relative to the project root (e.g., 'src/main.c' not '/absolute/path/src/main.c').

Examples:
    get_code_snippet(codebase_hash="abc", filename="main.c", start_line=10, end_line=20)"""
    )
    def get_code_snippet(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        filename: Annotated[str, Field(description="Name of the file to retrieve code from (relative to source root)")],
        start_line: Annotated[int, Field(description="Starting line number (1-indexed)")],
        end_line: Annotated[int, Field(description="Ending line number (1-indexed, inclusive)")],
    ) -> Dict[str, Any]:
        """Read specific lines from a source file."""
        try:
            validate_codebase_hash(codebase_hash)

            if start_line < 1 or end_line < start_line:
                raise ValidationError(
                    "Invalid line range: start_line must be >= 1 and end_line >= start_line"
                )

            codebase_tracker = services["codebase_tracker"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Get playground path
            playground_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "playground")
            )

            # Get source directory from session
            if codebase_info.source_type == "github":
                # For GitHub repos, use the cached directory
                from .core_tools import get_cpg_cache_key
                cpg_cache_key = get_cpg_cache_key(
                    codebase_info.source_type, codebase_info.source_path, codebase_info.language
                )
                source_dir = os.path.join(playground_path, "codebases", cpg_cache_key)
            else:
                # For local paths, use the session source path directly
                source_path = codebase_info.source_path
                if not os.path.isabs(source_path):
                    source_path = os.path.abspath(source_path)
                source_dir = source_path

            # Construct full file path
            file_path = os.path.join(source_dir, filename)

            # Check if file exists
            if not os.path.exists(file_path):
                raise ValidationError(
                    f"File '{filename}' not found in source directory"
                )

            if not os.path.isfile(file_path):
                raise ValidationError(f"'{filename}' is not a file")

            # Read the file
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            # Validate line numbers
            total_lines = len(lines)
            if start_line > total_lines:
                raise ValidationError(
                    f"start_line {start_line} exceeds file length {total_lines}"
                )

            if end_line > total_lines:
                end_line = total_lines

            # Extract the code snippet (lines are 0-indexed in the list)
            code_lines = lines[start_line - 1: end_line]
            code = "".join(code_lines)

            return {
                "success": True,
                "filename": filename,
                "start_line": start_line,
                "end_line": end_line,
                "code": code,
            }

        except ValidationError as e:
            logger.error(f"Error getting code snippet: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
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
    run_cpgql_query(codebase_hash="abc", query="cpg.method.name.l")"""
    )
    def run_cpgql_query(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        query: Annotated[str, Field(description="The CPGQL query string to execute")],
        timeout: Annotated[Optional[int], Field(description="Optional timeout in seconds")] = None,
        validate: Annotated[bool, Field(description="If true, validate query syntax before executing")] = False,
    ) -> Dict[str, Any]:
        """Run a raw CPGQL query for custom CPG analysis."""
        try:
            from ..utils.cpgql_validator import CPGQLValidator, QueryTransformer
            import time
            from ..services.joern_client import JoernServerClient
            
            validate_codebase_hash(codebase_hash)

            if not query or not query.strip():
                raise ValidationError("Query cannot be empty")

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Validate query if requested
            validation_result = None
            if validate:
                validation_result = CPGQLValidator.validate_query(query.strip())
                if not validation_result['valid'] and validation_result['errors']:
                    return {
                        "success": False,
                        "validation": validation_result,
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Query validation failed",
                            "details": validation_result['errors'],
                        },
                    }

            # Use the QueryExecutor service to get structured output (data and row_count)
            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query.strip(),
                timeout=timeout or 30,
                limit=None,
            )

            response = {
                "success": result.success,
                "data": result.data,
                "row_count": result.row_count,
                "execution_time": getattr(result, "execution_time", None),
            }

            # Include error information if present
            if not result.success and getattr(result, "error", None):
                response["error"] = result.error

            # If validation was requested, include it in response
            if validate and validation_result:
                response["validation"] = validation_result

            # If query failed, try to provide helpful suggestions from stderr (if available)
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
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error executing CPGQL query: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool(
        description="""Find bounds checks near buffer access.

Verify if buffer accesses have corresponding bounds checks by analyzing
comparison operations involving the index variable.

Args:
    codebase_hash: The codebase hash.
    buffer_access_location: 'filename:line' of the access (e.g., 'buf[i] = x').

Returns:
    {
        "success": true,
        "buffer_access": {...},
        "bounds_checks": [...],
        "check_before_access": true,
        "check_after_access": false
    }

Notes:
    - Helps identify potential buffer overflow vulnerabilities.
    - Checks for missing bounds checks or checks that happen too late.
    - filename in buffer_access_location should be relative to the project root (e.g., 'src/parser.c:100').

Examples:
    find_bounds_checks(codebase_hash="abc", buffer_access_location="parser.c:3393")"""
    )
    def find_bounds_checks(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        buffer_access_location: Annotated[str, Field(description="Location of buffer access in format 'filename:line' (e.g., 'parser.c:3393')")],
    ) -> Dict[str, Any]:
        """Check if buffer accesses have proper bounds validation."""
        try:
            validate_codebase_hash(codebase_hash)

            # Parse the buffer access location
            if ":" not in buffer_access_location:
                raise ValidationError(
                    "buffer_access_location must be in format 'filename:line'"
                )

            filename, line_str = buffer_access_location.rsplit(":", 1)
            try:
                line_num = int(line_str)
            except ValueError:
                raise ValidationError(f"Invalid line number: {line_str}")

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Build multi-line Scala query for bounds check analysis
            query = f'''
{{
  def escapeJson(s: String): String = {{
    s.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"").replace("\\n", "\\\\n").replace("\\r", "\\\\r").replace("\\t", "\\\\t")
  }}
  
  def extractIndexVariable(indexExpr: String): String = {{
    indexExpr.replaceAll("[^a-zA-Z0-9_].*", "").trim
  }}
  
  def getOperatorSymbol(operatorName: String): String = {{
    operatorName match {{
      case "<operator>.lessThan" => "<"
      case "<operator>.greaterThan" => ">"
      case "<operator>.lessEqualsThan" => "<="
      case "<operator>.greaterEqualsThan" => ">="
      case "<operator>.notEquals" => "!="
      case "<operator>.equals" => "=="
      case _ => "?"
    }}
  }}
  
  val filename = "{filename}"
  val lineNum = {line_num}
  
  val bufferAccessOpt = cpg.call
    .name("<operator>.indirectIndexAccess")
    .filter(c => {{
      val f = c.file.name.headOption.getOrElse("")
      f.endsWith("/" + filename) || f == filename
    }})
    .filter(c => c.lineNumber.getOrElse(-1) == lineNum)
    .headOption
  
  val resultMap = bufferAccessOpt match {{
    case Some(bufferAccess) =>
      val accessLine = bufferAccess.lineNumber.getOrElse(0)
      val args = bufferAccess.argument.l
      
      val bufferName = if (args.nonEmpty) escapeJson(args.head.code) else "unknown"
      val indexExpr = if (args.size > 1) escapeJson(args.last.code) else "unknown"
      val indexVar = extractIndexVariable(args.lastOption.map(_.code).getOrElse(""))
      
      val method = bufferAccess.method
      
      val comparisons = method.call
        .filter(c => {{
          val name = c.name
          name.contains("<operator>") && 
          (name.contains("essThan") || name.contains("ualsThan") || name.contains("quals") || name.contains("otEquals"))
        }})
        .filter(cmp => {{
          val cmpCode = cmp.code
          cmpCode.contains(indexVar) || cmpCode.contains(indexExpr.replaceAll("\\\\\\\\\"", "\""))
        }})
        .l
      
      val boundsChecksList = comparisons
        .map(cmp => {{
          val cmpLine = cmp.lineNumber.getOrElse(0)
          val position = if (cmpLine < accessLine) {{
            "BEFORE_ACCESS"
          }} else if (cmpLine > accessLine) {{
            "AFTER_ACCESS"
          }} else {{
            "SAME_LINE"
          }}
          
          val cmpArgs = cmp.argument.l
          val leftArg = if (cmpArgs.nonEmpty) cmpArgs.head.code else "?"
          val rightArg = if (cmpArgs.size > 1) cmpArgs.last.code else "?"
          val operator = getOperatorSymbol(cmp.name)
          
          Map(
            "line" -> cmpLine,
            "code" -> escapeJson(cmp.code),
            "checked_variable" -> escapeJson(leftArg),
            "bound" -> escapeJson(rightArg),
            "operator" -> operator,
            "position" -> position
          )
        }})
        .take(50)
      
      val checkBefore = comparisons.exists(c => c.lineNumber.getOrElse(0) < accessLine)
      val checkAfter = comparisons.exists(c => c.lineNumber.getOrElse(0) > accessLine)
      
      Map(
        "success" -> true,
        "buffer_access" -> Map(
          "line" -> accessLine,
          "code" -> escapeJson(bufferAccess.code),
          "buffer" -> bufferName,
          "index" -> indexExpr
        ),
        "bounds_checks" -> boundsChecksList,
        "check_before_access" -> checkBefore,
        "check_after_access" -> checkAfter,
        "index_variable" -> indexVar
      )
    
    case None =>
      Map(
        "success" -> false,
        "error" -> Map(
          "code" -> "NOT_FOUND",
          "message" -> s"No buffer access found at $filename:$lineNum"
        )
      )
  }}
  
  List(resultMap)
}}.toJsonPretty'''

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            # Parse the JSON result - the query now uses Map().toJsonPretty
            import json

            if isinstance(result.data, list) and len(result.data) > 0:
                # The result should be a parsed JSON object already
                result_data = result.data[0]
                
                # If it's already a dict, return it directly
                if isinstance(result_data, dict):
                    return result_data
                
                # Otherwise try to parse as string
                elif isinstance(result_data, str):
                    try:
                        return json.loads(result_data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse bounds check JSON: {e}, raw: {result_data[:200]}")
                        return {
                            "success": False,
                            "error": {"code": "PARSE_ERROR", "message": f"Failed to parse result: {str(e)}"},
                        }
                else:
                    logger.error(f"Unexpected result_data type: {type(result_data)}, value: {result_data}")
                    return {
                        "success": False,
                        "error": {"code": "UNEXPECTED_FORMAT", "message": "Unexpected response format"},
                    }
            else:
                return {
                    "success": False,
                    "error": {
                        "code": "NO_RESULT",
                        "message": "Query returned no results",
                    },
                }

        except ValidationError as e:
            logger.error(f"Error finding bounds checks: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

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
    get_cpgql_syntax_help()"""
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
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    # ============================================================================
    # SEMANTIC ANALYSIS TOOLS
    # ============================================================================

    @mcp.tool(
        description="""Get control flow graph (CFG) for a method.

Returns nodes and edges representing control flow.

Args:
    codebase_hash: The codebase hash.
    method_name: Name of the method.
    max_nodes: Limit nodes returned (default 100).

Returns:
    {
        "success": true,
        "method_name": "main",
        "cfg": {
            "nodes": [{"id": "1", "code": "if (x)", "type": "ControlStructure"}],
            "edges": [{"from": "1", "to": "2", "label": "TRUE"}]
        }
    }

Notes:
    - Essential for understanding loops, conditions, and execution paths.

Examples:
    get_cfg(codebase_hash="abc", method_name="main")"""
    )
    def get_cfg(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        method_name: Annotated[str, Field(description="Name of the method (can be regex pattern)")],
        max_nodes: Annotated[int, Field(description="Maximum CFG nodes to return (for large methods)")] = 100,
    ) -> Dict[str, Any]:
        """Get nodes and edges representing control flow in a method."""
        try:
            validate_codebase_hash(codebase_hash)
            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}")

            # Query for CFG nodes AND edges
            query = f'''{{
              val m = cpg.method.name("{method_name}").take(1).l.headOption
              m match {{
                case Some(method) =>
                  val nodes = method.cfgNode.take({max_nodes}).map(n => Map(
                    "_1" -> n.id,
                    "_2" -> n.code.take(100),
                    "_3" -> n.getClass.getSimpleName
                  )).l
                  val nodeIds = nodes.map(_("_1")).toSet
                  val edges = method.cfgNode.take({max_nodes}).flatMap(n => 
                    n.cfgNext.filter(next => nodeIds.contains(next.id)).map(next => 
                      Map("_1" -> n.id, "_2" -> next.id)
                    )
                  ).l.distinct
                  Map("nodes" -> nodes, "edges" -> edges)
                case None => Map("nodes" -> List(), "edges" -> List())
              }}
            }}.toJsonPretty'''

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
                limit=max_nodes,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            nodes = []
            edges = []
            if result.data:
                # Result is a single map with "nodes" and "edges"
                data = result.data[0] if result.data else {}
                if isinstance(data, dict):
                    raw_nodes = data.get("nodes", [])
                    raw_edges = data.get("edges", [])
                    for item in raw_nodes:
                        if isinstance(item, dict):
                            nodes.append({
                                "id": item.get("_1"),
                                "code": item.get("_2"),
                                "type": item.get("_3"),
                            })
                    for item in raw_edges:
                        if isinstance(item, dict):
                            edges.append({
                                "from": item.get("_1"),
                                "to": item.get("_2"),
                            })

            return {
                "success": True,
                "method_name": method_name,
                "nodes": nodes,
                "edges": edges,
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "max_nodes": max_nodes,
                "truncated": len(nodes) >= max_nodes,
            }

        except ValidationError as e:
            logger.error(f"Error getting CFG: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error getting CFG: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }


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
    get_type_definition(codebase_hash="abc", type_name=".*request_t.*")"""
    )
    def get_type_definition(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        type_name: Annotated[str, Field(description="Type name pattern (regex, e.g., '.*Buffer.*')")],
        limit: Annotated[int, Field(description="Maximum types to return")] = 10,
    ) -> Dict[str, Any]:
        """Get struct/class definition with member names and types."""
        try:
            validate_codebase_hash(codebase_hash)
            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}")

            # Query for type definitions with members
            query = f'''cpg.typeDecl.name("{type_name}").filter(_.member.nonEmpty).take({limit}).map {{ t =>
              Map(
                "_1" -> t.name,
                "_2" -> t.fullName,
                "_3" -> t.file.name.headOption.getOrElse("unknown"),
                "_4" -> t.lineNumber.getOrElse(-1),
                "_5" -> t.member.take(20).map(m => Map("name" -> m.name, "type" -> m.typeFullName)).l
              )
            }}.toJsonPretty'''

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
                    "error": {"code": "QUERY_ERROR", "message": result.error},
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
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error getting type definition: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }


    @mcp.tool(
        description="""Check if calls at a location might be macro expansions.

Detects potential macros using heuristics (naming conventions, dispatch type).

Args:
    codebase_hash: The codebase hash.
    filename: Filename (partial, relative to project root).
    line_number: Optional line number.

Returns:
    {
        "success": true,
        "calls": [
            {"name": "COPY_BUF", "is_macro": true, "macro_hints": ["ALL_CAPS"]}
        ]
    }

Notes:
    - Heuristic only (NOT definitive).
    - C/C++ macros are expanded before the CPG is built.
    - filename should be relative to the project root (e.g., 'src/main.c').

Examples:
    get_macro_expansion(codebase_hash="abc", filename="main.c", line_number=42)"""
    )
    def get_macro_expansion(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        filename: Annotated[str, Field(description="Filename to search (partial match)")],
        line_number: Annotated[Optional[int], Field(description="Optional line number to filter")] = None,
    ) -> Dict[str, Any]:
        """Detect potential macro expansions using naming heuristics."""
        try:
            validate_codebase_hash(codebase_hash)
            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}")

            # Build query with optional line filter
            line_filter = f".lineNumber({line_number})" if line_number else ""
            query = f'''cpg.call.where(_.file.name(".*{filename}.*")){line_filter}.take(50).map {{ c =>
              Map(
                "_1" -> c.name,
                "_2" -> c.code.take(100),
                "_3" -> c.lineNumber.getOrElse(-1),
                "_4" -> c.file.name.headOption.getOrElse("unknown"),
                "_5" -> c.dispatchType
              )
            }}.toJsonPretty'''

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=30,
                limit=50,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            # Deduplicate by name - keep first occurrence of each unique name
            seen_names = set()
            calls = []
            if result.data:
                for item in result.data:
                    if isinstance(item, dict):
                        name = item.get("_1", "")
                        
                        # Skip if already seen this name (deduplication)
                        if name in seen_names:
                            continue
                        seen_names.add(name)
                        
                        dispatch = item.get("_5", "")
                        
                        # Multiple heuristics for macro detection
                        hints = []
                        is_inlined = dispatch == "INLINED"
                        # ALL_CAPS: uppercase letters and underscores only, length > 1, not operators
                        is_all_caps = (
                            len(name) > 1 and 
                            all(c.isupper() or c == '_' for c in name) and
                            not name.startswith("<operator>")
                        )
                        
                        if is_inlined:
                            hints.append("INLINED_DISPATCH")
                        if is_all_caps:
                            hints.append("ALL_CAPS_NAME")
                        
                        calls.append({
                            "name": name,
                            "code": item.get("_2"),
                            "lineNumber": item.get("_3"),
                            "filename": item.get("_4"),
                            "dispatch_type": dispatch,
                            "is_macro": len(hints) > 0,
                            "macro_hints": hints,
                        })

            return {
                "success": True,
                "calls": calls,
                "total": len(calls),
                "unique_names": len(seen_names),
                "note": "Heuristic detection only. Macros are expanded before CPG analysis.",
            }

        except ValidationError as e:
            logger.error(f"Error getting macro expansion: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error getting macro expansion: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }
