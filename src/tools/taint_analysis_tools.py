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
from .queries import QueryLoader

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
    filename: Optional regex to filter by filename (relative to project root).
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
    - filename should be relative to the project root (e.g., 'src/shell.c').

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
    filename: Optional regex to filter by filename (relative to project root).
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
    - filename should be relative to the project root (e.g., 'src/shell.c').

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
    source_location: Alternative: specific source at 'file:line' (file relative to project root).
    sink_location: Alternative: specific sink at 'file:line' (file relative to project root).
    filename_filter: Limit analysis to specific file (relative to project root).
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
    - All file paths should be relative to the project root (e.g., 'src/io.c:100').

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
                    query = QueryLoader.load(
                        "taint_flows_intra_forward",
                        source_selector=source_selector,
                        sink_pattern=sink_pat,
                        max_results=max_results
                    )
                else:
                    # Inter-procedural: Find bridge functions containing sinks, then check if sources call them
                    query = QueryLoader.load(
                        "taint_flows_inter_forward",
                        source_selector=source_selector,
                        sink_pattern=sink_pat,
                        max_results=max_results,
                        max_results_x3=max_results * 3
                    )

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
                    query = QueryLoader.load(
                        "taint_flows_intra_backward",
                        sink_selector=sink_selector,
                        source_pattern=source_pat,
                        max_results=max_results
                    )
                else:
                    # Inter-procedural: Find which bridge functions contain sinks, then find sources calling them
                    query = QueryLoader.load(
                        "taint_flows_inter_backward",
                        sink_selector=sink_selector,
                        source_pattern=source_pat,
                        sink_pattern=sink_pat,
                        max_results=max_results
                    )

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
        description="""Build a bidirectional program slice from a specific call node.

Creates a program slice showing all code that affects (backward) and is affected by (forward)
a specific call, including dataflow and control dependencies. Optimized for static code analysis.

Args:
    codebase_hash: The codebase hash from generate_cpg.
    location: 'filename:line' or 'filename:line:call_name' (file relative to project root).
    node_id: Alternative: Direct CPG node ID of the target call.
    direction: 'backward' (what affects), 'forward' (what is affected), or 'both' (default).
    max_depth: Depth limit for recursive dependency tracking (default 5).
    include_control_flow: Include control dependencies like if/while conditions (default True).
    timeout: Maximum execution time in seconds (default 60).

Returns:
    {
        "success": true,
        "target": {
            "node_id": "12345",
            "name": "memcpy",
            "code": "memcpy(&ret[0], prefix, lenp)",
            "file": "tree.c",
            "line": 195,
            "method": "xmlBuildQName",
            "arguments": ["&ret[0]", "prefix", "lenp"]  
        },
        "backward_slice": {
            "data_dependencies": [
                {"variable": "ret", "line": 189, "code": "ret = xmlMalloc(...)", "depends_on": ["lenn", "lenp"]}
            ],
            "control_dependencies": [
                {"line": 174, "type": "IF", "condition": "(ncname == NULL) || (len < 0)"}
            ],
            "parameters": [{"name": "prefix", "type": "xmlChar*", "position": 2}],
            "locals": [{"name": "ret", "type": "xmlChar*", "line": 172}]
        },
        "forward_slice": {
            "result_variable": "bytes",
            "propagations": [
                {"line": 809, "code": "ret += bytes", "type": "usage"}
            ],
            "control_affected": [
                {"line": 798, "type": "IF", "condition": "bytes < 0"}
            ]
        },
        "summary": {"backward_nodes": 5, "forward_nodes": 3, "direction": "both"}
    }

Notes:
    - Use 'both' direction for complete vulnerability context analysis.
    - Backward slice shows data origins and control conditions.
    - Forward slice shows how results propagate and affect control flow.
    - Depth limits prevent excessive traversal in complex code.

Examples:
    get_program_slice(codebase_hash="abc", location="main.c:42", direction="both")
    get_program_slice(codebase_hash="abc", location="parser.c:500:memcpy", direction="backward", max_depth=3)
    get_program_slice(codebase_hash="abc", node_id="100234", direction="forward")"""
    )
    def get_program_slice(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        location: Annotated[Optional[str], Field(description="'filename:line' or 'filename:line:call_name'. Example: 'main.c:42' or 'main.c:42:memcpy'")] = None,
        node_id: Annotated[Optional[str], Field(description="Direct CPG node ID of the target call. Example: '12345'")] = None,
        direction: Annotated[str, Field(description="Slice direction: 'backward', 'forward', or 'both'")] = "both",
        max_depth: Annotated[int, Field(description="Maximum depth for recursive dependency tracking")] = 5,
        include_control_flow: Annotated[bool, Field(description="Include control dependencies (if/while conditions)")] = True,
        timeout: Annotated[int, Field(description="Maximum execution time in seconds")] = 60,
    ) -> Dict[str, Any]:
        """Get bidirectional program slice showing code affecting and affected by a specific call."""
        try:
            validate_codebase_hash(codebase_hash)

            # Validate inputs
            if not node_id and not location:
                raise ValidationError("Either node_id or location must be provided")
            
            if direction not in ["backward", "forward", "both"]:
                raise ValidationError("direction must be 'backward', 'forward', or 'both'")

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Parse location if provided
            filename = ""
            line_num = 0
            call_name = ""
            
            if location:
                parts = location.split(":")
                if len(parts) < 2:
                    raise ValidationError("location must be 'filename:line' or 'filename:line:callname'")
                filename = parts[0]
                try:
                    line_num = int(parts[1])
                except ValueError:
                    raise ValidationError(f"Invalid line number in location: {parts[1]}")
                call_name = parts[2] if len(parts) > 2 else ""

            # Build comprehensive Scala query for bidirectional slicing
            include_backward = direction in ["backward", "both"]
            include_forward = direction in ["forward", "both"]
            
            # Load query from external file
            query = QueryLoader.load(
                "program_slice",
                filename=filename,
                line_num=line_num,
                use_node_id=str(node_id is not None).lower(),
                node_id=node_id if node_id else "",
                call_name=call_name,
                max_depth=max_depth,
                include_backward=str(include_backward).lower(),
                include_forward=str(include_forward).lower(),
                include_control_flow=str(include_control_flow).lower(),
                direction=direction
            )

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

            # Parse JSON result
            import json

            if isinstance(result.data, list) and len(result.data) > 0:
                result_data = result.data[0]
                if isinstance(result_data, str):
                    return json.loads(result_data)
                return result_data
            
            return {
                "success": False,
                "error": {"code": "NO_RESULT", "message": "Query returned no results"},
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
    location: "filename:line" (e.g., "parser.c:3393"), filename relative to project root.
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
    - location filename should be relative to the project root (e.g., 'src/main.c:50').

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

            # Load query from external file
            query = QueryLoader.load(
                "variable_flow",
                filename=filename,
                line_num=line_num,
                variable=variable,
                direction=direction
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