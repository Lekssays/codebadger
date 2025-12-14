"""
Taint Analysis MCP Tools for CodeBadger Server
Security-focused tools for analyzing data flows and vulnerabilities
"""

import logging
import re
from typing import Any, Dict, Optional, Annotated
from pydantic import Field

from ..exceptions import (
            ValidationError,
)
from ..utils.validators import validate_codebase_hash

logger = logging.getLogger(__name__)


def register_taint_analysis_tools(mcp, services: dict):
    """Register taint analysis MCP tools with the FastMCP server"""

    @mcp.tool(
        description="""Locate likely external input points (taint sources).

Search for function calls that could be entry points for untrusted data,
such as user input, environment variables, or network data. Useful for
identifying where external data enters the program.

The tool uses a comprehensive list of default sources configured in the
system configuration unless specific patterns are provided.

Returns:
    {
        "success": true,
        "sources": [
            {
                "node_id": "12345",
                "name": "getenv",
                "code": "getenv(\"PATH\")",
                "filename": "main.c",
                "lineNumber": 42,
                "method": "main"
            }
        ],
        "total": 1
    }"""
    )
    def find_taint_sources(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        language: Annotated[Optional[str], Field(description="Programming language to use for default patterns (e.g., 'c', 'java'). If not provided, uses the session's language")] = None,
        source_patterns: Annotated[Optional[list], Field(description="Optional list of regex patterns to match source function names (e.g., ['getenv', 'fgets', 'scanf']). If not provided, uses default patterns")] = None,
        filename: Annotated[Optional[str], Field(description="Optional filename to filter results (e.g., 'shell.c', 'main.c'). Uses regex matching, so partial names work (e.g., 'shell' matches 'shell.c')")] = None,
        limit: Annotated[int, Field(description="Maximum number of results to return")] = 200,
    ) -> Dict[str, Any]:
        """Locate likely external input points (taint sources)."""
        try:
            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Determine language and patterns
            lang = language or codebase_info.language or "c"
            cfg = services["config"]
            taint_cfg = (
                getattr(cfg.cpg, "taint_sources", {})
                if hasattr(cfg.cpg, "taint_sources")
                else {}
            )

            patterns = source_patterns or taint_cfg.get(lang, [])
            if not patterns:
                return {"success": True, "sources": [], "total": 0, "message": f"No taint sources configured for language {lang}"}

            # Build Joern query searching for call names matching any pattern
            # Remove trailing parens from patterns for proper regex matching
            cleaned_patterns = [p.rstrip("(") for p in patterns]
            joined = "|".join([re.escape(p) for p in cleaned_patterns])
            
            # Build query with optional file filter
            if filename:
                # Use regex to match filename - handles both full and partial matches
                query = f'cpg.call.name("{joined}").where(_.file.name(".*{filename}.*")).map(c => (c.id, c.name, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName)).take({limit})'
            else:
                query = f'cpg.call.name("{joined}").map(c => (c.id, c.name, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName)).take({limit})'

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

            sources = []
            for item in result.data:
                if isinstance(item, dict):
                    sources.append(
                        {
                            "node_id": item.get("_1"),
                            "name": item.get("_2"),
                            "code": item.get("_3"),
                            "filename": item.get("_4"),
                            "lineNumber": item.get("_5"),
                            "method": item.get("_6"),
                        }
                    )

            return {"success": True, "sources": sources, "total": len(sources)}

        except ValidationError as e:
            logger.error(f"Error finding taint sources: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error finding taint sources: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool(
        description="""Locate dangerous sinks where tainted data could cause vulnerabilities.

Search for function calls that could be security-sensitive destinations
for data, such as system execution, file operations, or format strings.
Useful for identifying where untrusted data could cause harm.

The tool uses a comprehensive list of default sinks configured in the
system configuration unless specific patterns are provided.

Returns:
    {
        "success": true,
        "sinks": [
            {
                "node_id": "67890",
                "name": "system",
                "code": "system(cmd)",
                "filename": "main.c",
                "lineNumber": 100,
                "method": "execute_command"
            }
        ],
        "total": 1
    }"""
    )
    def find_taint_sinks(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        language: Annotated[Optional[str], Field(description="Programming language to use for default patterns (e.g., 'c', 'java'). If not provided, uses the session's language")] = None,
        sink_patterns: Annotated[Optional[list], Field(description="Optional list of regex patterns to match sink function names (e.g., ['system', 'popen', 'sprintf']). If not provided, uses default patterns")] = None,
        filename: Annotated[Optional[str], Field(description="Optional filename to filter results (e.g., 'shell.c', 'main.c'). Uses regex matching, so partial names work (e.g., 'shell' matches 'shell.c')")] = None,
        limit: Annotated[int, Field(description="Maximum number of results to return")] = 200,
    ) -> Dict[str, Any]:
        """Locate dangerous sinks where tainted data could cause vulnerabilities."""
        try:
            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            lang = language or codebase_info.language or "c"
            cfg = services["config"]
            taint_cfg = (
                getattr(cfg.cpg, "taint_sinks", {})
                if hasattr(cfg.cpg, "taint_sinks")
                else {}
            )

            patterns = sink_patterns or taint_cfg.get(lang, [])
            if not patterns:
                return {"success": True, "sinks": [], "total": 0, "message": f"No taint sinks configured for language {lang}"}

            # Remove trailing parens from patterns for proper regex matching
            cleaned_patterns = [p.rstrip("(") for p in patterns]
            joined = "|".join([re.escape(p) for p in cleaned_patterns])
            
            # Build query with optional file filter
            if filename:
                # Use regex to match filename - handles both full and partial matches
                query = f'cpg.call.name("{joined}").where(_.file.name(".*{filename}.*")).map(c => (c.id, c.name, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName)).take({limit})'
            else:
                query = f'cpg.call.name("{joined}").map(c => (c.id, c.name, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName)).take({limit})'

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

            sinks = []
            for item in result.data:
                if isinstance(item, dict):
                    sinks.append(
                        {
                            "node_id": item.get("_1"),
                            "name": item.get("_2"),
                            "code": item.get("_3"),
                            "filename": item.get("_4"),
                            "lineNumber": item.get("_5"),
                            "method": item.get("_6"),
                        }
                    )

            return {"success": True, "sinks": sinks, "total": len(sinks)}

        except ValidationError as e:
            logger.error(f"Error finding taint sinks: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error finding taint sinks: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool(
        description="""Find dataflow paths from source to sink by tracking through assignments and identifiers.

This tool traces how data flows from a source call (e.g., malloc, getenv) to a sink call
(e.g., free, system) by following the intermediate variables, assignments, and identifiers.

✅ WHAT IT CAN DO:
- Track return value flows: allocate() → variable → deallocate(variable)
  Example: ptr = allocate_memory(size); ... deallocate_memory(ptr);
- Trace variable assignments across statements in the same function
  Example: input = get_user_data(); ... temp = input; ... process(temp);
- Find direct identifier matches between source output and sink input
- Work within intra-procedural scope (same function/method)

❌ WHAT IT CANNOT DO:
- Interprocedural dataflow (across function boundaries)
  Example: Can't track: main() calls helper(x) which passes x to worker(y)
  Reason: Requires alias analysis and parameter tracking
- Complex transformations or computations on data
  Example: Can't track: ptr = allocate(10); ptr2 = ptr + offset; deallocate(ptr2);
  Reason: Doesn't understand pointer arithmetic
- Array element or struct field flows
  Example: Limited for: arr[i].field = allocate(); ... deallocate(arr[j].field);
  Reason: Needs field-sensitive analysis
- Control-flow dependent paths
  Example: May miss: if(cond) ptr = allocate(); ... if(cond) deallocate(ptr);
  Reason: Doesn't analyze conditions

💡 HOW IT WORKS:
1. Locates the source call (e.g., allocate_memory at line 42)
2. Finds what variable receives the result (e.g., buffer = allocate_memory())
3. Searches for that identifier in sink call arguments (e.g., deallocate_memory(buffer))
4. Reports if there's a direct match

🔧 USE THIS TOOL WHEN:
- Checking for resource leaks: allocate/acquire → deallocate/release
- Finding use-after-free: deallocate → subsequent use
- Tracing user input: get_input/read_data → dangerous_function
- Simple variable flow within one function

⚠️ LIMITATIONS TO UNDERSTAND:
- This is a SIMPLE identifier-based flow tracker, not full taint analysis
- It finds DIRECT identifier matches, not semantic dataflow
- For complex analysis, combine with get_call_graph and manual inspection
- Best used as a starting point for deeper investigation

Returns:
    When source AND sink are provided:
    {
        "success": true,
        "source": { "node_id": "12345", "code": "allocate_memory(100)", ... },
        "sink": { "node_id": "67890", "code": "deallocate_memory(buffer)", ... },
        "flow_found": true,
        "flow_type": "direct_identifier_match",
        "intermediate_variable": "buffer",
        "details": { ... }
    }

    When ONLY source is provided:
    {
        "success": true,
        "source": { ... },
        "flows": [
            {
                "path_id": 0,
                "path_length": 3,
                "nodes": [ ... ]
            }
        ],
        "total_flows": 1,
        "message": "Found 1 flows from source to dangerous sinks"
    }

Example - Source and Sink provided:
    find_taint_flows(
        codebase_hash="abc-123",
        source_location="main.c:42",   # allocate_memory(100)
        sink_location="main.c:58"      # deallocate_memory(buffer)
    )
    # Result: ✓ Found flow through variable 'buffer'

Example - Only Source provided:
    find_taint_flows(
        codebase_hash="abc-123",
        source_location="main.c:42"    # allocate_memory(100)
    )
    # Result: ✓ Found flows to all dangerous sinks (free, system, etc.) that use the allocated variable"""
    )
    def find_taint_flows(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        source_node_id: Annotated[Optional[str], Field(description="Node ID of source call (from find_taint_sources). Example: '12345'")] = None,
        sink_node_id: Annotated[Optional[str], Field(description="Node ID of sink call (from find_taint_sinks). Example: '67890'")] = None,
        source_location: Annotated[Optional[str], Field(description="Alternative: 'filename:line' or 'filename:line:method'. Example: 'main.c:42' or 'main.c:42:process_data'")] = None,
        sink_location: Annotated[Optional[str], Field(description="Alternative: 'filename:line' or 'filename:line:method'. Example: 'main.c:58' or 'main.c:58:process_data'")] = None,
        max_path_length: Annotated[int, Field(description="Maximum length of dataflow paths to consider in elements. Paths with more elements will be filtered out to avoid extremely long chains")] = 20,
        timeout: Annotated[int, Field(description="Maximum execution time in seconds")] = 60,
    ) -> Dict[str, Any]:
        """Find dataflow paths from source to sink by tracking through assignments and identifiers."""
        try:
            validate_codebase_hash(codebase_hash)

            # Validate that we have proper source and sink specifications
            if not source_node_id and not source_location:
                raise ValidationError(
                    "Either source_node_id or source_location must be provided"
                )
            if not sink_node_id and not sink_location and (source_node_id or source_location):
                # If only source is provided, that's fine - we'll find flows to any sink
                pass
            elif not sink_node_id and not sink_location:
                # If neither source nor sink is provided, that's an error
                raise ValidationError(
                    "Either source_node_id/source_location or sink_node_id/sink_location must be provided"
                )
            elif sink_node_id or sink_location:
                # If only sink is provided, that's an error
                if not source_node_id and not source_location:
                    raise ValidationError(
                        "Only sink provided - not supported. Please provide a source to find flows from."
                    )

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Resolve source and sink nodes
            source_info = None
            sink_info = None
            has_sink = bool(sink_node_id or sink_location)

            # Helper function to resolve node by ID or location
            def resolve_node(node_id, location, node_type):
                if node_id:
                    try:
                        node_id_long = int(node_id)
                    except ValueError:
                        raise ValidationError(
                            f"{node_type}_node_id must be a valid integer: {node_id}"
                        )
                    query = f'cpg.call.id({node_id_long}L).map(c => (c.id, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName)).take(1).l'
                else:
                    parts = location.split(":")
                    if len(parts) < 2:
                        raise ValidationError(
                            f"{node_type}_location must be in format 'filename:line' or 'filename:line:call_name'"
                        )
                    filename = parts[0]
                    try:
                        line_num = int(parts[1])
                    except ValueError:
                        raise ValidationError(
                            f"Line number must be a valid integer: {parts[1]}"
                        )
                    method_name = parts[2] if len(parts) > 2 else None

                    if method_name:
                        query = f'cpg.call.where(_.file.name(".*{filename}$")).lineNumber({line_num}).filter(_.method.fullName.contains("{method_name}")).map(c => (c.id, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName)).take(1).l'
                    else:
                        query = f'cpg.call.where(_.file.name(".*{filename}$")).lineNumber({line_num}).map(c => (c.id, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName)).take(1).l'

                result = query_executor.execute_query(
                    codebase_hash=codebase_hash,
                    cpg_path=codebase_info.cpg_path,
                    query=query,
                    timeout=10,
                    limit=1,
                )

                if result.success and result.data and len(result.data) > 0:
                    item = result.data[0]
                    if isinstance(item, dict) and item.get("_1"):
                        return {
                            "node_id": item.get("_1"),
                            "code": item.get("_2"),
                            "filename": item.get("_3"),
                            "lineNumber": item.get("_4"),
                            "method": item.get("_5"),
                        }
                return None

            source_info = resolve_node(source_node_id, source_location, "source")
            if has_sink:
                sink_info = resolve_node(sink_node_id, sink_location, "sink")

            # If source not found, return early
            if not source_info:
                return {
                    "success": False,
                    "source": source_info,
                    "sink": sink_info,
                    "flow_found": False,
                    "message": f"Could not resolve source from provided identifiers",
                }

            # If sink is required but not found, return early
            if has_sink and not sink_info:
                return {
                    "success": False,
                    "source": source_info,
                    "sink": sink_info,
                    "flow_found": False,
                    "message": f"Could not resolve sink from provided identifiers",
                }

            # Build dataflow query to find paths from source to sink
            source_id = source_info["node_id"]
            
            if has_sink:
                # Specific sink mode: find flows between source and sink
                sink_id = sink_info["node_id"]
                query = f'{{ val source = cpg.call.id({source_id}L).l.headOption; val sink = cpg.call.id({sink_id}L).l.headOption; val flows = if (source.nonEmpty && sink.nonEmpty) {{ val sourceCall = source.get; val sinkCall = sink.get; val assignments = sourceCall.inAssignment.l; if (assignments.nonEmpty) {{ val assign = assignments.head; val targetVar = assign.target.code; val sinkArgs = sinkCall.argument.code.l; val matches = sinkArgs.contains(targetVar); if (matches) {{ List(Map("_1" -> 0, "_2" -> 3, "_3" -> List(Map("_1" -> sourceCall.code, "_2" -> sourceCall.file.name.headOption.getOrElse("unknown"), "_3" -> sourceCall.lineNumber.getOrElse(-1), "_4" -> "CALL"), Map("_1" -> targetVar, "_2" -> assign.file.name.headOption.getOrElse("unknown"), "_3" -> assign.lineNumber.getOrElse(-1), "_4" -> "IDENTIFIER"), Map("_1" -> sinkCall.code, "_2" -> sinkCall.file.name.headOption.getOrElse("unknown"), "_3" -> sinkCall.lineNumber.getOrElse(-1), "_4" -> "CALL")))) }} else {{ List() }} }} else {{ List() }} }} else {{ List() }}; flows }}.toJsonPretty'
            else:
                # Source-only mode: find flows from source to any dangerous sink
                query = f'{{ val source = cpg.call.id({source_id}L).l.headOption; val flows = if (source.nonEmpty) {{ val sourceCall = source.get; val assignments = sourceCall.inAssignment.l; if (assignments.nonEmpty) {{ val assign = assignments.head; val targetVar = assign.target.code; val dangerousSinks = Set("system", "popen", "execl", "execv", "sprintf", "fprintf", "free", "delete"); val sinkPattern = dangerousSinks.mkString("|"); val sinkCalls = cpg.call.name(sinkPattern).filter(sink => {{ val sinkArgs = sink.argument.code.l; sinkArgs.contains(targetVar) }}).l.take(20); sinkCalls.map(sink => Map("_1" -> 0, "_2" -> 3, "_3" -> List(Map("_1" -> sourceCall.code, "_2" -> sourceCall.file.name.headOption.getOrElse("unknown"), "_3" -> sourceCall.lineNumber.getOrElse(-1), "_4" -> "CALL"), Map("_1" -> targetVar, "_2" -> assign.file.name.headOption.getOrElse("unknown"), "_3" -> assign.lineNumber.getOrElse(-1), "_4" -> "IDENTIFIER"), Map("_1" -> sink.code, "_2" -> sink.file.name.headOption.getOrElse("unknown"), "_3" -> sink.lineNumber.getOrElse(-1), "_4" -> "CALL")))) }} else {{ List() }} }} else {{ List() }}; flows }}.toJsonPretty'

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=timeout,
                limit=1,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            # Parse result
            flows = []
            if result.success and result.data:
                # Result is a list of flow maps
                for item in result.data:
                    if (
                        isinstance(item, dict)
                        and "_1" in item
                        and "_2" in item
                        and "_3" in item
                    ):
                        flows.append(
                            {
                                "path_id": item["_1"],
                                "path_length": item["_2"],
                                "nodes": item["_3"],
                            }
                        )

            if has_sink:
                # Specific sink mode: return single flow result
                flow_found = len(flows) > 0
                return {
                    "success": True,
                    "source": source_info,
                    "sink": sink_info,
                    "flow_found": flow_found,
                    "flow_type": "direct_identifier_match" if flow_found else None,
                    "intermediate_variable": flows[0]["nodes"][1]["_1"] if flow_found else None,
                    "details": {
                        "assignment": flows[0]["nodes"][1]["_1"] if flow_found else None,
                        "assignment_line": flows[0]["nodes"][1]["_3"] if flow_found else None,
                        "variable_uses": 1 if flow_found else 0,
                        "explanation": f"{source_info['code']} result assigned to variable and used in {sink_info['code']}" if flow_found else None,
                    } if flow_found else None,
                }
            else:
                # Source-only mode: return multiple flows
                return {
                    "success": True,
                    "source": source_info,
                    "flows": flows,
                    "total_flows": len(flows),
                    "message": f"Found {len(flows)} flows from source to dangerous sinks" if flows else "No flows found from source to dangerous sinks",
                }

        except ValidationError as e:
            logger.error(f"Error finding taint flows: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error finding taint flows: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool(
        description="""Check if one method can reach another through the call graph.

Determines whether the target method is reachable from the source method
by following function calls. Useful for understanding code dependencies
and potential execution paths.

Returns:
    {
        "success": true,
        "reachable": true,
        "source_method": "main",
        "target_method": "helper",
        "message": "Method 'helper' is reachable from 'main'"
    }"""
    )
    def check_method_reachability(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        source_method: Annotated[str, Field(description="Name of the source method (can be regex pattern)")],
        target_method: Annotated[str, Field(description="Name of the target method (can be regex pattern)")],
    ) -> Dict[str, Any]:
        """Check if one method can reach another through the call graph."""
        try:
            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Escape patterns for regex
            source_escaped = re.escape(source_method)
            target_escaped = re.escape(target_method)

            # Query to check reachability using depth-independent BFS traversal.
            # Instead of manually checking levels 1-5, we use a recursive function
            # to traverse the entire call graph regardless of depth.
            query = (
                f'val source = cpg.method.name("{source_escaped}").l\n'
                f'val target = cpg.method.name("{target_escaped}").l\n'
                f"val reachable = if (source.nonEmpty && target.nonEmpty) {{\n"
                f"  val targetName = target.head.name\n"
                f"  var visited = Set[String]()\n"
                f"  var toVisit = scala.collection.mutable.Queue[io.shiftleft.codepropertygraph.generated.nodes.Method]()\n"
                f"  toVisit.enqueue(source.head)\n"
                f"  var found = false\n"
                f"  \n"
                f"  while (toVisit.nonEmpty && !found) {{\n"
                f"    val current = toVisit.dequeue()\n"
                f"    val currentName = current.name\n"
                f"    if (!visited.contains(currentName)) {{\n"
                f"      visited = visited + currentName\n"
                f"      val callees = current.call.callee.l\n"
                f"      for (callee <- callees) {{\n"
                f"        val calleeName = callee.name\n"
                f"        if (calleeName == targetName) {{\n"
                f"          found = true\n"
                f'        }} else if (!visited.contains(calleeName) && !calleeName.startsWith("<operator>")) {{\n'
                f"          toVisit.enqueue(callee)\n"
                f"        }}\n"
                f"      }}\n"
                f"    }}\n"
                f"  }}\n"
                f"  found\n"
                f"}} else false\n"
                f"List(reachable).toJsonPretty"
            )

            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=60,
                limit=1,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            reachable = False
            if result.data and len(result.data) > 0:
                # The query returns a boolean result
                reachable = bool(result.data[0])

            message = (
                f"Method '{target_method}' is {'reachable' if reachable else 'not reachable'} "
                f"from '{source_method}'"
            )

            return {
                "success": True,
                "reachable": reachable,
                "source_method": source_method,
                "target_method": target_method,
                "message": message,
            }

        except ValidationError as e:
            logger.error(f"Error checking method reachability: {e}")
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
        description="""Build a program slice from a specific call node.

Creates a backward program slice showing all code that could affect the
execution at a specific point. This includes:
- The call itself and its arguments
- Dataflow: all assignments and operations affecting argument variables
- Control flow: conditions that determine whether the call executes
- Call graph: functions called and their data dependencies

**Important**: Use node IDs (from list_calls) or specify exact locations to
avoid ambiguity, especially when multiple calls appear on the same line.

Returns:
    {
        "success": true,
        "slice": {
            "target_call": {
                "node_id": "12345",
                "name": "memcpy",
                "code": "memcpy(buf, src, size)",
                "filename": "main.c",
                "lineNumber": 42,
                "method": "process_data",
                "arguments": ["buf", "src", "size"]
            },
            "dataflow": [ ... ],
            "control_dependencies": [ ... ]
        },
        "total_nodes": 15
    }"""
    )
    def get_program_slice(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        node_id: Annotated[Optional[str], Field(description="Preferred: Direct CPG node ID of the target call (Get from list_calls or other query results). Example: '12345'")] = None,
        location: Annotated[Optional[str], Field(description="Alternative: 'filename:line_number' or 'filename:line_number:call_name'. Example: 'main.c:42' or 'main.c:42:memcpy'")] = None,
        include_dataflow: Annotated[bool, Field(description="Include dataflow (variable assignments) in slice")] = True,
        include_control_flow: Annotated[bool, Field(description="Include control dependencies (if/while conditions)")] = True,
        max_depth: Annotated[int, Field(description="Maximum depth for dataflow tracking")] = 5,
        timeout: Annotated[int, Field(description="Maximum execution time in seconds")] = 60,
    ) -> Dict[str, Any]:
        """Build a program slice from a specific call node."""
        try:
            validate_codebase_hash(codebase_hash)

            # Validate that we have proper node identification
            if not node_id and not location:
                raise ValidationError("Either node_id or location must be provided")

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Parse location if provided
            filename = None
            line_num = None
            call_name = None
            
            if location:
                parts = location.split(":")
                if len(parts) < 2:
                    raise ValidationError(
                        "location must be in format 'filename:line' or 'filename:line:callname'"
                    )
                filename = parts[0]
                try:
                    line_num = int(parts[1])
                except ValueError:
                    raise ValidationError(f"Invalid line number in location: {parts[1]}")
                call_name = parts[2] if len(parts) > 2 else ""

            # Build multi-line Scala query (complex queries need proper block structure)
            query = f'''
{{
  def escapeJson(s: String): String = {{
    s.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"").replace("\\n", "\\\\n").replace("\\r", "\\\\r").replace("\\t", "\\\\t")
  }}
  
  def normalizeFilename(path: String, filename: String): Boolean = {{
    path.endsWith("/" + filename) || path == filename
  }}
  
  val filename = "{filename}"
  val lineNum = {line_num}
  val useNodeId = {str(node_id is not None).lower()}
  val nodeId = "{node_id if node_id else ""}"
  val callName = "{call_name if call_name else ""}"
  val includeDataflow = {str(include_dataflow).lower()}
  val includeControlFlow = {str(include_control_flow).lower()}
  val maxDepth = {max_depth}
  
  // Find target method
  val targetMethodOpt = if (useNodeId && nodeId.nonEmpty) {{
    cpg.call.id(nodeId.toLong).method.headOption
  }} else {{
    cpg.method
      .filter(m => normalizeFilename(m.file.name.headOption.getOrElse(""), filename))
      .filter(m => {{
        val start = m.lineNumber.getOrElse(-1)
        val end = m.lineNumberEnd.getOrElse(-1)
        start <= lineNum && end >= lineNum
      }})
      .headOption
  }}
  
  // Process result
  targetMethodOpt match {{
    case Some(method) => {{
      // Find target call
      val targetCallOpt = if (useNodeId && nodeId.nonEmpty) {{
        cpg.call.id(nodeId.toLong).headOption
      }} else {{
        val callsOnLine = method.call.filter(c => c.lineNumber.getOrElse(-1) == lineNum).l
        if (callName.nonEmpty && callsOnLine.nonEmpty) {{
          callsOnLine.filter(_.name == callName).headOption
        }} else if (callsOnLine.nonEmpty) {{
          callsOnLine.headOption
        }} else {{
          None
        }}
      }}
      
      targetCallOpt match {{
        case Some(targetCall) => {{
          // Collect dataflow information
          val dataflow = if (includeDataflow) {{
            val argVars = targetCall.argument.code.l
            method.assignment
              .filter(assign => assign.lineNumber.getOrElse(-1) < lineNum)
              .filter(assign => {{
                val targetCode = assign.target.code
                argVars.exists(arg => arg.contains(targetCode.trim) || targetCode.contains(arg.trim))
              }})
              .map(assign => Map(
                "variable" -> assign.target.code,
                "code" -> escapeJson(assign.code),
                "filename" -> escapeJson(assign.file.name.headOption.getOrElse("unknown")),
                "lineNumber" -> assign.lineNumber.getOrElse(-1),
                "method" -> escapeJson(assign.method.fullName)
              ))
              .l
              .take(100)
          }} else {{
            List()
          }}
          
          // Collect control flow information
          val controlDeps = if (includeControlFlow) {{
            method.ast
              .isControlStructure
              .filter(ctrl => {{
                val ctrlLine = ctrl.lineNumber.getOrElse(-1)
                ctrlLine < lineNum && ctrlLine >= 0
              }})
              .map(ctrl => Map(
                "code" -> escapeJson(ctrl.code),
                "filename" -> escapeJson(ctrl.file.name.headOption.getOrElse("unknown")),
                "lineNumber" -> ctrl.lineNumber.getOrElse(-1),
                "method" -> escapeJson(ctrl.method.fullName)
              ))
              .l
              .take(50)
          }} else {{
            List()
          }}
          
          // Build target call map
          val targetCallMap = Map(
            "node_id" -> targetCall.id.toString,
            "name" -> targetCall.name,
            "code" -> escapeJson(targetCall.code),
            "filename" -> escapeJson(targetCall.file.name.headOption.getOrElse("unknown")),
            "lineNumber" -> targetCall.lineNumber.getOrElse(-1),
            "method" -> escapeJson(targetCall.method.fullName),
            "arguments" -> targetCall.argument.code.l
          )
          
          // Build success response
          Map(
            "success" -> true,
            "slice" -> Map(
              "target_call" -> targetCallMap,
              "dataflow" -> dataflow,
              "control_dependencies" -> controlDeps
            ),
            "total_nodes" -> (1 + dataflow.size + controlDeps.size)
          )
        }}
        case None => {{
          Map(
            "success" -> false,
            "error" -> Map(
              "code" -> "CALL_NOT_FOUND",
              "message" -> "No call found at specified location"
            )
          )
        }}
      }}
    }}
    case None => {{
      Map(
        "success" -> false,
        "error" -> Map(
          "code" -> "METHOD_NOT_FOUND",
          "message" -> "No method found containing the specified line"
        )
      )
    }}
  }}
}}.toJsonPretty'''

            # Execute the query
            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=timeout,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            # Parse the JSON result (same as get_data_dependencies)
            import json

            if isinstance(result.data, list) and len(result.data) > 0:
                result_data = result.data[0]

                # Handle JSON string response
                if isinstance(result_data, str):
                    return json.loads(result_data)
                else:
                    return result_data
            else:
                return {
                    "success": False,
                    "error": {
                        "code": "NO_RESULT",
                        "message": "Query returned no results",
                    },
                }

        except ValidationError as e:
            logger.error(f"Error getting program slice: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error getting program slice: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }


    @mcp.tool(
        description="""Analyze variable data flow in backward or forward direction.

Backward: Find definitions, assignments, and modifications affecting a variable.
Forward: Find usages and propagations of a variable.

Returns: {success, target: {file, line, variable, method}, direction, dependencies: [{line, code, type, filename}], total}"""
    )
    def get_variable_flow(
        codebase_hash: str,
        location: str,
        variable: str,
        direction: str = "backward",
    ) -> Dict[str, Any]:
        """
        Analyze variable data flow.

        Args:
            codebase_hash: The codebase hash from generate_cpg
            location: Location as "filename:line" (e.g., "parser.c:3393")
            variable: Variable name to analyze (e.g., "len", "buffer")
            direction: "backward" (what affects it) or "forward" (what it affects)
        """

                variable="len",
                direction="forward"
            )
            # Returns all usages and propagations of 'len' after line 3383
        """
        try:
            validate_codebase_hash(codebase_hash)

            # Validate location format
            if ":" not in location:
                raise ValidationError("location must be in format 'filename:line'")

            parts = location.rsplit(":", 1)
            if len(parts) != 2:
                raise ValidationError("location must be in format 'filename:line'")

            filename = parts[0]
            try:
                line_num = int(parts[1])
            except ValueError:
                raise ValidationError(f"Invalid line number: {parts[1]}")

            # Validate direction
            if direction not in ["backward", "forward"]:
                raise ValidationError("direction must be 'backward' or 'forward'")

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists for this codebase
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Build improved CPGQL query with proper JSON output
            # This query correctly handles variable data flow analysis
            query_template = r'''{
  def escapeJson(s: String): String = {
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
  }

  val targetLine = LINE_NUM_PLACEHOLDER
  val varName = "VARIABLE_PLACEHOLDER"
  val filename = "FILENAME_PLACEHOLDER"
  val direction = "DIRECTION_PLACEHOLDER"
  val maxResults = 50

  val targetMethodOpt = cpg.method
    .filter(m => {
      val f = m.file.name.headOption.getOrElse("")
      f.endsWith(filename) || f.contains(filename)
    })
    .filter(m => {
      val start = m.lineNumber.getOrElse(-1)
      val end = m.lineNumberEnd.getOrElse(-1)
      start <= targetLine && end >= targetLine
    })
    .headOption

  val result = targetMethodOpt match {
    case Some(method) => {
      val methodName = method.name
      val methodFile = method.file.name.headOption.getOrElse("unknown")
      val dependencies = scala.collection.mutable.ListBuffer[Map[String, Any]]()

      if (direction == "backward") {
        val inits = method.local.name(varName).l
        inits.foreach { local =>
          dependencies += Map(
            "line" -> local.lineNumber.getOrElse(-1),
            "code" -> escapeJson(s"${local.typeFullName} ${local.code}"),
            "type" -> "initialization",
            "filename" -> escapeJson(methodFile)
          )
        }

        val assignments = method.assignment.l
          .filter(a => {
            val line = a.lineNumber.getOrElse(-1)
            line < targetLine
          })
          .filter(a => {
            val targetCode = a.target.code
            targetCode == varName || targetCode.startsWith(varName + "[") || targetCode.startsWith(varName + ".")
          })
          .take(maxResults)

        assignments.foreach { assign =>
          dependencies += Map(
            "line" -> assign.lineNumber.getOrElse(-1),
            "code" -> escapeJson(assign.code),
            "type" -> "assignment",
            "filename" -> escapeJson(methodFile)
          )
        }

        val modifications = method.call
          .name("<operator>.(postIncrement|preIncrement|postDecrement|preDecrement|assignmentPlus|assignmentMinus|assignmentMultiplication|assignmentDivision)")
          .l
          .filter(c => {
            val line = c.lineNumber.getOrElse(-1)
            line < targetLine
          })
          .filter(c => {
            val args = c.argument.code.l
            args.exists(arg => arg == varName || arg.startsWith(varName + "[") || arg.startsWith(varName + "."))
          })
          .take(maxResults)

        modifications.foreach { call =>
          dependencies += Map(
            "line" -> call.lineNumber.getOrElse(-1),
            "code" -> escapeJson(call.code),
            "type" -> "modification",
            "filename" -> escapeJson(methodFile)
          )
        }

        val funcCalls = method.call.l
          .filter(c => {
            val line = c.lineNumber.getOrElse(-1)
            line < targetLine
          })
          .filter(c => {
            val args = c.argument.code.l
            args.exists(arg => arg.contains("&" + varName) || arg.contains(varName))
          })
          .take(maxResults)

        funcCalls.foreach { call =>
          dependencies += Map(
            "line" -> call.lineNumber.getOrElse(-1),
            "code" -> escapeJson(call.code),
            "type" -> "function_call",
            "filename" -> escapeJson(methodFile)
          )
        }
      } else if (direction == "forward") {
        val usages = method.call.l
          .filter(c => {
            val line = c.lineNumber.getOrElse(-1)
            line > targetLine
          })
          .filter(c => {
            val args = c.argument.code.l
            args.exists(arg => arg.contains(varName))
          })
          .take(maxResults)

        usages.foreach { call =>
          dependencies += Map(
            "line" -> call.lineNumber.getOrElse(-1),
            "code" -> escapeJson(call.code),
            "type" -> "usage",
            "filename" -> escapeJson(methodFile)
          )
        }

        val propagations = method.assignment.l
          .filter(a => {
            val line = a.lineNumber.getOrElse(-1)
            line > targetLine
          })
          .filter(a => {
            val sourceCode = a.source.code
            sourceCode.contains(varName)
          })
          .take(maxResults)

        propagations.foreach { assign =>
          dependencies += Map(
            "line" -> assign.lineNumber.getOrElse(-1),
            "code" -> escapeJson(assign.code),
            "type" -> "propagation",
            "filename" -> escapeJson(methodFile)
          )
        }

        val mods = method.call
          .name("<operator>.(postIncrement|preIncrement|postDecrement|preDecrement|assignmentPlus|assignmentMinus)")
          .l
          .filter(c => {
            val line = c.lineNumber.getOrElse(-1)
            line > targetLine
          })
          .filter(c => {
            val args = c.argument.code.l
            args.exists(arg => arg == varName)
          })
          .take(maxResults)

        mods.foreach { call =>
          dependencies += Map(
            "line" -> call.lineNumber.getOrElse(-1),
            "code" -> escapeJson(call.code),
            "type" -> "modification",
            "filename" -> escapeJson(methodFile)
          )
        }
      }

      val sortedDeps = dependencies.sortBy(d => d.getOrElse("line", -1).asInstanceOf[Int])

      List(
        Map(
          "success" -> true,
          "target" -> Map(
            "file" -> methodFile,
            "line" -> targetLine,
            "variable" -> varName,
            "method" -> methodName
          ),
          "direction" -> direction,
          "dependencies" -> sortedDeps.toList,
          "total" -> sortedDeps.size
        )
      )
    }
    case None => {
      List(
        Map(
          "success" -> false,
          "error" -> Map(
            "code" -> "METHOD_NOT_FOUND",
            "message" -> s"No method found containing line $targetLine in file containing '$filename'"
          )
        )
      )
    }
  }

  result.toJsonPretty
}'''

            query = (
                query_template.replace("FILENAME_PLACEHOLDER", filename)
                .replace("LINE_NUM_PLACEHOLDER", str(line_num))
                .replace("VARIABLE_PLACEHOLDER", variable)
                .replace("DIRECTION_PLACEHOLDER", direction)
            )

            # Execute the query
            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=60,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            # Parse the JSON result (same as find_bounds_checks)
            import json

            if isinstance(result.data, list) and len(result.data) > 0:
                result_data = result.data[0]

                # Handle JSON string response
                if isinstance(result_data, str):
                    return json.loads(result_data)
                else:
                    return result_data
            else:
                return {
                    "success": False,
                    "error": {
                        "code": "NO_RESULT",
                        "message": "Query returned no results",
                    },
                }

        except ValidationError as e:
            logger.error(f"Error getting data dependencies: {e}")
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