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
such as user input, environment variables, or network data.

Args:
    codebase_hash: The codebase hash from generate_cpg.
    language: Optional language (c, java) for default patterns.
    source_patterns: Optional list of regex patterns for source functions (e.g., ['getenv', 'read']).
    filename: Optional regex to filter by filename.
    limit: Max results (default 200).

Returns:
    {
        "success": true,
        "sources": [
            {"node_id": "...", "name": "getenv", "code": "getenv(...)", "filename": "...", "lineNumber": 42}
        ],
        "total": 1
    }

Notes:
    - Uses default security patterns if no custom patterns provided.
    - Sources are the starting points for taint analysis.

Examples:
    find_taint_sources(codebase_hash="abc", language="c")
    find_taint_sources(codebase_hash="abc", source_patterns=["read_from_socket"])"""
    )
    def find_taint_sources(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        language: Annotated[Optional[str], Field(description="Programming language to use for default patterns (e.g., 'c', 'java'). If not provided, uses the session's language")] = None,
        source_patterns: Annotated[Optional[list], Field(description="Optional list of regex patterns to match source function names (e.g., ['getenv', 'fgets', 'scanf']). If not provided, uses default patterns")] = None,
        filename: Annotated[Optional[str], Field(description="Optional filename to filter results (e.g., 'shell.c', 'main.c'). Uses regex matching, so partial names work (e.g., 'shell' matches 'shell.c')")] = None,
        limit: Annotated[int, Field(description="Maximum number of results to return")] = 200,
    ) -> Dict[str, Any]:
        """Find function calls that are entry points for external/untrusted data."""
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

            return {
                "success": True,
                "sources": sources,
                "total": len(sources),
                "limit": limit,
                "has_more": len(sources) >= limit,
            }

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

Args:
    codebase_hash: The codebase hash from generate_cpg.
    language: Optional language (c, java) for default patterns.
    sink_patterns: Optional list of regex patterns for sink functions (e.g., ['system', 'exec']).
    filename: Optional regex to filter by filename.
    limit: Max results (default 200).

Returns:
    {
        "success": true,
        "sinks": [
            {"node_id": "...", "name": "system", "code": "system(...)", "filename": "...", "lineNumber": 100}
        ],
        "total": 1
    }

Notes:
    - Uses default dangerous function lists if no patterns provided.
    - Sinks are the destinations where tainted data causes harm.

Examples:
    find_taint_sinks(codebase_hash="abc", language="c")
    find_taint_sinks(codebase_hash="abc", sink_patterns=["custom_exec"])"""
    )
    def find_taint_sinks(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        language: Annotated[Optional[str], Field(description="Programming language to use for default patterns (e.g., 'c', 'java'). If not provided, uses the session's language")] = None,
        sink_patterns: Annotated[Optional[list], Field(description="Optional list of regex patterns to match sink function names (e.g., ['system', 'popen', 'sprintf']). If not provided, uses default patterns")] = None,
        filename: Annotated[Optional[str], Field(description="Optional filename to filter results (e.g., 'shell.c', 'main.c'). Uses regex matching, so partial names work (e.g., 'shell' matches 'shell.c')")] = None,
        limit: Annotated[int, Field(description="Maximum number of results to return")] = 200,
    ) -> Dict[str, Any]:
        """Find security-sensitive function calls where untrusted data could cause harm."""
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

            return {
                "success": True,
                "sinks": sinks,
                "total": len(sinks),
                "limit": limit,
                "has_more": len(sinks) >= limit,
            }

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
        description="""Find taint flows from sources to sinks across function boundaries.

Detects data flow from untrusted input sources (e.g., file I/O, user input) to
dangerous sinks (e.g., memory operations, system calls). Supports inter-procedural
analysis by tracking flows through function call chains.

Args:
    codebase_hash: The codebase hash from generate_cpg.
    source_pattern: Regex for source functions (e.g., 'fread|getenv|scanf').
    sink_pattern: Regex for sink functions (e.g., 'memcpy|strcpy|system').
    source_location: Alternative: specific source at 'file:line'.
    sink_location: Alternative: specific sink at 'file:line'.
    filename_filter: Limit analysis to specific file.
    max_depth: Call depth for inter-procedural tracking (0=intra-procedural, 1+=inter-procedural).

Returns:
    {
        "success": true,
        "mode": "forward|backward",
        "flows": [
            {
                "source": {"code": "...", "file": "...", "line": N},
                "sink": {"code": "...", "file": "...", "line": N},
                "bridge_function": "function_name",  # For inter-procedural flows
                "path_length": N
            }
        ]
    }

Notes:
    - max_depth=0: Intra-procedural only (sources and sinks in same function).
    - max_depth>=1: Inter-procedural (detects calls to functions containing sinks).
    - Use source_pattern + sink_pattern for broad analysis.
    - Use source_location/sink_location for targeted verification.

Examples:
    # Find flows from file I/O to memory operations (inter-procedural)
    find_taint_flows(codebase_hash="abc", source_pattern="fread", sink_pattern="memcpy", max_depth=2)
    
    # Verify specific source reaches specific sink
    find_taint_flows(codebase_hash="abc", source_location="io.c:100", sink_location="parser.c:500")"""
    )
    def find_taint_flows(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        source_pattern: Annotated[Optional[str], Field(description="Regex for source functions (e.g., 'fread|getenv')")] = None,
        sink_pattern: Annotated[Optional[str], Field(description="Regex for sink functions (e.g., 'memcpy|system')")] = None,
        source_location: Annotated[Optional[str], Field(description="Alternative: source at 'file:line' (e.g., 'parser.c:782')")] = None,
        sink_location: Annotated[Optional[str], Field(description="Alternative: sink at 'file:line' (e.g., 'parser.c:800')")] = None,
        filename_filter: Annotated[Optional[str], Field(description="Limit to specific file (e.g., 'parser.c')")] = None,
        max_depth: Annotated[int, Field(description="Call depth: 0=intra-procedural, 1+=inter-procedural")] = 2,
        max_results: Annotated[int, Field(description="Maximum flows to return")] = 10,
        timeout: Annotated[int, Field(description="Query timeout in seconds")] = 60,
    ) -> Dict[str, Any]:
        """Find data flow paths between sources and sinks using variable tracking."""
        try:
            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first.")

            # Validate input
            has_source_loc = bool(source_location)
            has_sink_loc = bool(sink_location)
            has_source_pattern = bool(source_pattern)
            has_sink_pattern = bool(sink_pattern)

            if not any([has_source_loc, has_sink_loc, has_source_pattern, has_sink_pattern]):
                raise ValidationError(
                    "Provide at least one of: source_location, sink_location, source_pattern, or sink_pattern"
                )

            # Default patterns
            default_sources = "getenv|fgets|scanf|fscanf|gets|read|recv|fread|getline"
            default_sinks = "system|popen|execl|execv|sprintf|fprintf|strcpy|memcpy|strcat"

            # Parse locations if provided
            def parse_location(loc):
                if not loc:
                    return None, None
                parts = loc.split(":")
                if len(parts) < 2:
                    raise ValidationError(f"Location must be 'file:line', got: {loc}")
                try:
                    return parts[0], int(parts[1])
                except ValueError:
                    raise ValidationError(f"Invalid line number in: {loc}")

            source_file, source_line = parse_location(source_location)
            sink_file, sink_line = parse_location(sink_location)
            
            # File filter
            file_filter = f'.where(_.file.name(".*{filename_filter}.*"))' if filename_filter else ""

            # Determine mode and build query
            if has_source_pattern or has_source_loc:
                # FORWARD MODE: Find sinks reachable from sources
                mode = "forward"
                source_pat = source_pattern or default_sources
                sink_pat = sink_pattern or default_sinks
                
                # Build source selector
                if has_source_loc:
                    source_selector = f'cpg.call.where(_.file.name(".*{source_file}$")).lineNumber({source_line})'
                else:
                    source_selector = f'cpg.call.name("{source_pat}"){file_filter}'

                if max_depth == 0:
                    # Intra-procedural: sources and sinks in same function
                    query = f'''{{
  val sources = {source_selector}.l.take({max_results})
  val flows = sources.flatMap {{ src =>
    val method = src.method
    val sinks = method.call.name("{sink_pat}").l
    
    sinks.flatMap {{ snk =>
      // Check if there's data flow from source to sink
      val srcAssigns = src.inAssignment.l
      if (srcAssigns.nonEmpty) {{
        val varName = srcAssigns.head.target.code
        val sinkArgs = snk.argument.code.l
        if (sinkArgs.contains(varName)) {{
          Some(Map(
            "source" -> Map("code" -> src.code, "file" -> src.file.name.headOption.getOrElse("?"), "line" -> src.lineNumber.getOrElse(-1)),
            "sink" -> Map("code" -> snk.code, "file" -> snk.file.name.headOption.getOrElse("?"), "line" -> snk.lineNumber.getOrElse(-1)),
            "path_length" -> 1
          ))
        }} else None
      }} else None
    }}
  }}.take({max_results})
  flows
}}.toJsonPretty'''

                else:
                    # Inter-procedural: Find bridge functions containing sinks, then check if sources call them
                    query = f'''{{
  // Step 1: Find bridge functions (functions containing sinks)
  val bridgeFunctions = cpg.method
    .where(_.call.name("{sink_pat}"))
    .filterNot(_.name == "<global>")
    .l
    
  // Step 2: Find sources
  val sources = {source_selector}.l.take({max_results * 3})
  
  // Step 3: For each source, find calls to bridge functions
  val flows = sources.flatMap {{ src =>
    val srcMethod = src.method
    
    // Find calls from source's method to bridge functions
    bridgeFunctions.flatMap {{ bridgeFunc =>
      val callsToBridge = srcMethod.call.name(bridgeFunc.name).l
      
      if (callsToBridge.nonEmpty) {{
        // Get the actual sink call inside bridge function
        val sinkInBridge = bridgeFunc.call.name("{sink_pat}").headOption
        
        sinkInBridge.map {{ snk =>
          Map(
            "source" -> Map("code" -> src.code, "file" -> src.file.name.headOption.getOrElse("?"), "line" -> src.lineNumber.getOrElse(-1)),
            "sink" -> Map("code" -> snk.code, "file" -> snk.file.name.headOption.getOrElse("?"), "line" -> snk.lineNumber.getOrElse(-1)),
            "bridge_function" -> bridgeFunc.name,
            "path_length" -> 2
          )
        }}
      }} else None
    }}
  }}.take({max_results})
  
  flows
}}.toJsonPretty'''

            else:
                # BACKWARD MODE: Find sources that reach given sinks
                mode = "backward"
                source_pat = source_pattern or default_sources
                sink_pat = sink_pattern or default_sinks
                
                # Build sink selector
                if has_sink_loc:
                    sink_selector = f'cpg.call.where(_.file.name(".*{sink_file}$")).lineNumber({sink_line})'
                else:
                    sink_selector = f'cpg.call.name("{sink_pat}"){file_filter}'

                if max_depth == 0:
                    # Intra-procedural
                    query = f'''{{
  val sinks = {sink_selector}.l.take({max_results})
  val flows = sinks.flatMap {{ snk =>
    val method = snk.method
    val sources = method.call.name("{source_pat}").l
    
    sources.flatMap {{ src =>
      val srcAssigns = src.inAssignment.l
      if (srcAssigns.nonEmpty) {{
        val varName = srcAssigns.head.target.code
        val sinkArgs = snk.argument.code.l
        if (sinkArgs.contains(varName)) {{
          Some(Map(
            "source" -> Map("code" -> src.code, "file" -> src.file.name.headOption.getOrElse("?"), "line" -> src.lineNumber.getOrElse(-1)),
            "sink" -> Map("code" -> snk.code, "file" -> snk.file.name.headOption.getOrElse("?"), "line" -> snk.lineNumber.getOrElse(-1)),
            "path_length" -> 1
          ))
        }} else None
      }} else None
    }}
  }}.take({max_results})
  flows
}}.toJsonPretty'''

                else:
                    # Inter-procedural: Find which bridge functions contain sinks, then find sources calling them
                    query = f'''{{
  // Step 1: Find sinks
  val sinks = {sink_selector}.l.take({max_results})
  
  // Step 2: Find bridge functions containing these sinks
  val bridgeFunctions = sinks.map(_.method).dedup.filterNot(_.name == "<global>").l
  
  // Step 3: Find calls to bridge functions from methods containing sources
  val flows = bridgeFunctions.flatMap {{ bridgeFunc =>
    // Find who calls this bridge function
    val callers = cpg.call.name(bridgeFunc.name).l
    
    callers.flatMap {{ callSite =>
      val callerMethod = callSite.method
      // Check if caller method has source calls
      val sourceCalls = callerMethod.call.name("{source_pat}").l
      
      if (sourceCalls.nonEmpty) {{
        val src = sourceCalls.head
        val snk = bridgeFunc.call.name("{sink_pat}").headOption.getOrElse(null)
        
        if (snk != null) {{
          Some(Map(
            "source" -> Map("code" -> src.code, "file" -> src.file.name.headOption.getOrElse("?"), "line" -> src.lineNumber.getOrElse(-1)),
            "sink" -> Map("code" -> snk.code, "file" -> snk.file.name.headOption.getOrElse("?"), "line" -> snk.lineNumber.getOrElse(-1)),
            "bridge_function" -> bridgeFunc.name,
            "path_length" -> 2
          ))
        }} else None
      }} else None
    }}
  }}.take({max_results})
  
  flows
}}.toJsonPretty'''

            # Execute query
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

            # Parse result
            import json
            flows = []
            if result.data:
                for item in result.data:
                    if isinstance(item, str):
                        try:
                            parsed = json.loads(item)
                            if isinstance(parsed, list):
                                flows.extend(parsed)
                            else:
                                flows.append(parsed)
                        except json.JSONDecodeError:
                            pass
                    elif isinstance(item, dict):
                        flows.append(item)

            return {
                "success": True,
                "mode": mode,
                "max_depth": max_depth,
                "flows": flows,
                "total": len(flows),
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
        description="""Build a program slice from a specific call node.

Creates a backward program slice showing all code that could affect the
execution at a specific point (dataflow and control dependencies).

Args:
    codebase_hash: The codebase hash.
    node_id: Precise CPG node ID of the target call.
    location: Alternative 'file:line' specifier.
    include_dataflow: Track variable assignments (default True).
    include_control_flow: Track if/while conditions (default True).
    max_depth: limit for backward traversal.

Returns:
    {
        "success": true,
        "slice": {
            "target_call": {...},
            "dataflow": [...],
            "control_dependencies": [...]
        },
        "total_nodes": N
    }

Notes:
    - Use node_id for precision when multiple calls exist on one line.
    - Essential for understanding the context of a potential vulnerability.

Examples:
    get_program_slice(codebase_hash="abc", location="main.c:42")
    get_program_slice(codebase_hash="abc", node_id="100234")"""
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
        """Get backward slice showing all code affecting execution at a specific call."""
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
      .filterNot(_.name == "\u003cglobal\u003e")  // Exclude <global> pseudo-method
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
        description="""Analyze data dependencies for a variable at a specific location.

Finds code locations that influence (backward) or are influenced by (forward)
a variable.

Args:
    codebase_hash: The codebase hash.
    location: "filename:line" (e.g., "parser.c:3393").
    variable: Variable name to analyze.
    direction: "backward" (definitions) or "forward" (usages).

Returns:
    {
        "success": true,
        "target": { "file": "...", "line": 10, "variable": "x" },
        "dependencies": [
            {"line": 5, "code": "int x = 0;", "type": "initialization"}
        ],
        "direction": "backward"
    }

Notes:
    - Backward: Finds initialization, assignment, and modification.
    - Forward: Finds usage as argument and propagation to other vars.

Examples:
    get_variable_flow(codebase_hash="abc", location="main.c:50", variable="len", direction="backward")"""
    )
    def get_variable_flow(
        codebase_hash: str,
        location: str,
        variable: str,
        direction: str = "backward",
    ) -> Dict[str, Any]:
        """Analyze variable data dependencies in backward or forward direction."""
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
    .filterNot(_.name == "\u003cglobal\u003e")  // Exclude <global> pseudo-method
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