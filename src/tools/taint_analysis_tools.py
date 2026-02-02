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

# Default taint sources by language (used when config is empty)
DEFAULT_SOURCES = {
    "c": [
        "getenv", "fgets", "scanf", "read", "recv", "fread", "gets", "getchar",
        "fscanf", "recvfrom", "recvmsg", "getopt", "getpass", "socket", "accept",
        "fopen", "getline", "realpath", "getaddrinfo", "gethostbyname",
    ],
    "cpp": [
        "getenv", "fgets", "scanf", "read", "recv", "fread", "gets", "getchar",
        "fscanf", "recvfrom", "recvmsg", "cin", "getline", "getopt",
    ],
    "java": [
        "getParameter", "getQueryString", "getHeader", "getCookie", "getReader",
        "getInputStream", "readLine", "readObject", "System.getenv", "System.getProperty",
        "Scanner.next", "Scanner.nextLine",
    ],
    "python": [
        "input", "raw_input", "sys.argv", "os.environ", "os.getenv",
        "request.args", "request.form", "request.json", "request.data", "request.cookies",
        "request.headers", "request.files",
    ],
    "javascript": [
        "req.body", "req.query", "req.params", "req.headers", "req.cookies",
        "process.env", "process.argv", "fs.readFile", "fetch", "prompt", "readline",
    ],
    "go": [
        "os.Args", "os.Getenv", "os.Environ", "flag.String", "flag.Int",
        "net/http.Request.FormValue", "net/http.Request.Form", "net/http.Request.Header",
        "net/http.Request.Body", "net/http.Request.Cookies", "io/ioutil.ReadAll",
        "fmt.Scan", "fmt.Scanf",
    ],
    "csharp": [
        "Console.ReadLine", "Console.Read", "System.Environment.GetEnvironmentVariable",
        "Request.QueryString", "Request.Form", "Request.Cookies", "Request.Headers",
        "Request.Params", "System.IO.File.ReadAllText", "System.Net.Sockets.Socket.Receive",
    ],
    "php": [
        "$_GET", "$_POST", "$_COOKIE", "$_REQUEST", "$_FILES", "$_SERVER", "$_ENV",
        "getenv", "file_get_contents", "fread", "fgets", "socket_read", "socket_recv",
    ],
    "ruby": [
        "gets", "read", "params", "ENV", "ARGV", "cookies", "request.body",
        "request.query_string", "request.headers",
    ],
    "swift": [
        "CommandLine.arguments", "ProcessInfo.processInfo.environment",
        "String(contentsOf:)", "Data(contentsOf:)", "URL(string:)",
    ],
    "kotlin": [
        "readLine", "Scanner.next", "System.getenv", "System.getProperty",
        "request.getParameter", "request.getHeader",
    ],
    "jimple": [
        "getParameter", "getQueryString", "getHeader", "getCookie", "getReader",
        "getInputStream", "readLine", "System.getenv",
    ],
    "ghidra": [
        "getenv", "fgets", "scanf", "read", "recv", "fread", "gets",
        "GetCommandLine", "GetEnvironmentVariable", "ReadFile", "Recv",
    ],
}

# Default taint sinks by language (used when config is empty)
DEFAULT_SINKS = {
    "c": [
        "system", "popen", "execl", "execv", "execve", "execlp", "execvp",
        "sprintf", "fprintf", "snprintf", "vsprintf", "strcpy", "strcat",
        "gets", "memcpy", "memmove", "strncpy", "strncat", "free", "malloc",
        "printf", "syslog", "open", "fopen", "write", "send", "sendto",
    ],
    "cpp": [
        "system", "popen", "execl", "execv", "execve", "sprintf", "fprintf",
        "snprintf", "strcpy", "strcat", "memcpy", "memmove", "free", "malloc",
        "cout", "cerr",
    ],
    "java": [
        "Runtime.exec", "ProcessBuilder.start", "executeQuery", "executeUpdate",
        "sendRedirect", "forward", "include", "print", "write",
    ],
    "python": [
        "eval", "exec", "os.system", "os.popen", "subprocess.call",
        "subprocess.Popen", "subprocess.run", "pickle.load", "yaml.load",
        "sqlite3.execute",
    ],
    "javascript": [
        "eval", "setTimeout", "setInterval", "child_process.exec",
        "child_process.spawn", "fs.writeFile", "res.send", "res.render",
        "document.write", "innerHTML",
    ],
    "go": [
        "os/exec.Command", "syscall.Exec", "net/http.ResponseWriter.Write",
        "fmt.Printf", "fmt.Fprintf", "log.Fatal", "database/sql.DB.Query",
        "os.Create", "io/ioutil.WriteFile",
    ],
    "csharp": [
        "System.Diagnostics.Process.Start", "System.Data.SqlClient.SqlCommand.ExecuteReader",
        "System.Data.SqlClient.SqlCommand.ExecuteNonQuery", "Response.Write",
        "System.IO.File.WriteAllText", "System.Console.WriteLine",
    ],
    "php": [
        "exec", "shell_exec", "system", "passthru", "popen", "proc_open",
        "eval", "assert", "preg_replace", "echo", "print", "printf",
        "file_put_contents", "fwrite", "header", "setcookie", "mysql_query",
    ],
    "ruby": [
        "eval", "system", "exec", "syscall", "render", "send_file", "redirect_to",
        "print", "puts", "File.write", "ActiveRecord::Base.connection.execute",
    ],
    "swift": [
        "Process.launch", "Process()", "String(format:)", "print",
        "FileManager.default.createFile",
    ],
    "kotlin": [
        "Runtime.exec", "ProcessBuilder.start", "print", "println",
        "File.writeText", "rawQuery", "execSQL",
    ],
    "jimple": [
        "Runtime.exec", "ProcessBuilder.start", "executeQuery", "executeUpdate",
        "sendRedirect", "print", "write",
    ],
    "ghidra": [
        "system", "popen", "execl", "execv", "strcpy", "memcpy", "sprintf",
        "WinExec", "ShellExecute", "CreateProcess", "system", "strcpy", "memcpy",
    ],
}



def register_taint_analysis_tools(mcp, services: dict):
    """Register taint analysis MCP tools with the FastMCP server"""

    @mcp.tool(
        description="""Locate likely external input points (taint sources).

Search for function calls that could be entry points for untrusted data,
such as user input, environment variables, or network data.

Args:
    codebase_hash: The codebase hash from generate_cpg.
    language: Programming language (c, cpp, java, python, javascript, go, csharp, php, ruby, swift, kotlin, etc). Default: uses CPG language.
    source_patterns: Optional list of patterns for source functions (e.g., ['getenv', 'read']).
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
    - Built-in default patterns for all supported languages.
    - Sources are the starting points for taint analysis.
    - Use node_id from results with find_taint_flows.

Examples:
    find_taint_sources(codebase_hash="abc", language="c")
    find_taint_sources(codebase_hash="abc", source_patterns=["read_from_socket"])"""
    )
    def find_taint_sources(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        language: Annotated[Optional[str], Field(description="Programming language (c, cpp, java, python, javascript). If not provided, uses the CPG's language")] = None,
        source_patterns: Annotated[Optional[list], Field(description="Optional list of patterns to match source function names. If not provided, uses built-in defaults")] = None,
        filename: Annotated[Optional[str], Field(description="Optional filename to filter results (e.g., 'shell.c'). Uses regex matching")] = None,
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
            
            # Try config first, then fall back to built-in defaults
            cfg = services["config"]
            taint_cfg = (
                getattr(cfg.cpg, "taint_sources", {})
                if hasattr(cfg.cpg, "taint_sources")
                else {}
            )

            # Priority: 1) user-provided, 2) config, 3) built-in defaults
            patterns = source_patterns or taint_cfg.get(lang, []) or DEFAULT_SOURCES.get(lang.lower(), [])
            if not patterns:
                return {"success": True, "sources": [], "total": 0, "message": f"No taint sources configured for language {lang}. Supported: {', '.join(DEFAULT_SOURCES.keys())}"}

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
                    "error": result.error,
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
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Unexpected error finding taint sources: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }

    @mcp.tool(
        description="""Locate dangerous sinks where tainted data could cause vulnerabilities.

Search for function calls that could be security-sensitive destinations
for data, such as system execution, file operations, or format strings.

Args:
    codebase_hash: The codebase hash from generate_cpg.
    language: Programming language (c, cpp, java, python, javascript, go, csharp, php, ruby, swift, kotlin, etc). Default: uses CPG language.
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
    - Built-in default patterns for all supported languages.
    - Sinks are the destinations where tainted data causes harm.
    - Use node_id from results with find_taint_flows.

Examples:
    find_taint_sinks(codebase_hash="abc", language="c")
    find_taint_sinks(codebase_hash="abc", sink_patterns=["custom_exec"])"""
    )
    def find_taint_sinks(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        language: Annotated[Optional[str], Field(description="Programming language (c, cpp, java, python, javascript, etc). If not provided, uses the CPG's language")] = None,
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
            
            # Try config first, then fall back to built-in defaults
            cfg = services["config"]
            taint_cfg = (
                getattr(cfg.cpg, "taint_sinks", {})
                if hasattr(cfg.cpg, "taint_sinks")
                else {}
            )

            # Priority: 1) user-provided, 2) config, 3) built-in defaults
            patterns = sink_patterns or taint_cfg.get(lang, []) or DEFAULT_SINKS.get(lang.lower(), [])
            if not patterns:
                return {"success": True, "sinks": [], "total": 0, "message": f"No taint sinks configured for language {lang}. Supported: {', '.join(DEFAULT_SINKS.keys())}"}

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
                    "error": result.error,
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
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Unexpected error finding taint sinks: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }

    @mcp.tool(
        description="""Find taint flows from a source to a sink using Joern's native dataflow analysis.

Detects data flow from a specific source node to a specific sink node.
Uses Joern's reachableByFlows() for accurate taint tracking including pointer aliasing,
array propagation, and struct fields.

DO:
- Use `find_taint_sources` first to get source locations/IDs.
- Use `find_taint_sinks` first to get sink locations/IDs.
- Provide BOTH source AND sink for every query.

DON'T:
- Do NOT provide "patterns" here (use source_location or source_node_id).
- Do NOT use old arguments like `source_pattern` or `sink_pattern`.
- Do NOT guess file:line locations.

Args:
    codebase_hash: The codebase hash from generate_cpg.
    source_location: Source at 'file:line' (e.g., 'xsltproc/xsltproc.c:818').
    sink_location: Sink at 'file:line' (e.g., 'libxslt/numbers.c:229').
    source_node_id: Alternative: node ID from find_taint_sources output.
    sink_node_id: Alternative: node ID from find_taint_sinks output.
    max_results: Maximum flows to return (default 20).
    timeout: Query timeout in seconds (default 60).

Returns:
    Human-readable text showing:
    - Source and sink matched
    - Detailed flow path showing each intermediate step
    - Path length

Notes:
    - BOTH source AND sink are required.
    - Use either location (file:line) OR node_id for each.
    - Node IDs come from find_taint_sources/find_taint_sinks output.
    - Inter-procedural flows are tracked automatically.

Examples:
    # 1. Using locations (Recommended for human workflow)
    find_taint_flows(codebase_hash="...", source_location="main.c:42", sink_location="utils.c:100")
    
    # 2. Using node IDs (Recommended for automated/LLM workflow)
    # First: output = find_taint_sources(...)
    # Then: output = find_taint_sinks(...)
    # Finally:
    find_taint_flows(codebase_hash="...", source_node_id=12345, sink_node_id=67890)"""
    )
    def find_taint_flows(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        source_location: Annotated[Optional[str], Field(description="Source at 'file:line' (e.g., 'parser.c:782')")] = None,
        sink_location: Annotated[Optional[str], Field(description="Sink at 'file:line' (e.g., 'parser.c:800')")] = None,
        source_node_id: Annotated[Optional[int], Field(description="Node ID from find_taint_sources output")] = None,
        sink_node_id: Annotated[Optional[int], Field(description="Node ID from find_taint_sinks output")] = None,
        max_results: Annotated[int, Field(description="Maximum flows to return")] = 20,
        timeout: Annotated[int, Field(description="Query timeout in seconds")] = 60,
        # Legacy/Deprecated arguments - included to provide helpful error messages
        source_pattern: Annotated[Optional[str], Field(description="DEPRECATED: Do not use")] = None,
        sink_pattern: Annotated[Optional[str], Field(description="DEPRECATED: Do not use")] = None,
        mode: Annotated[Optional[str], Field(description="DEPRECATED: Do not use")] = None,
        depth: Annotated[Optional[int], Field(description="DEPRECATED: Do not use")] = None,
    ) -> str:
        """Find data flow paths between source and sink using Joern's native taint analysis."""
        try:
            # Check for legacy arguments that LLMs might hallucinate
            legacy_args = []
            if source_pattern: legacy_args.append("source_pattern")
            if sink_pattern: legacy_args.append("sink_pattern")
            if mode: legacy_args.append("mode")
            if depth: legacy_args.append("depth")

            if legacy_args:
                raise ValidationError(
                    f"Unexpected arguments: {legacy_args}. "
                    "These arguments are deprecated. "
                    "Use 'find_taint_sources' to find sources by pattern, then use the resulting 'node_id' here."
                )

            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first.")

            # Validate input - BOTH source AND sink are required
            has_source_loc = bool(source_location)
            has_sink_loc = bool(sink_location)
            has_source_id = source_node_id is not None and source_node_id > 0
            has_sink_id = sink_node_id is not None and sink_node_id > 0

            # Parse what was provided for clearer error messages
            provided_args = []
            if has_source_loc: provided_args.append(f"source_location='{source_location}'")
            if has_source_id: provided_args.append(f"source_node_id={source_node_id}")
            if has_sink_loc: provided_args.append(f"sink_location='{sink_location}'")
            if has_sink_id: provided_args.append(f"sink_node_id={sink_node_id}")
            provided_str = ", ".join(provided_args) if provided_args else "None"

            # Must have source (either location or node_id)
            if not has_source_loc and not has_source_id:
                raise ValidationError(
                    f"\n\n"
                    f"================================================================================\n"
                    f"CRITICAL ERROR: MISSING SOURCE\n"
                    f"================================================================================\n\n"
                    f"The `find_taint_flows` tool requires TWO endpoints: a Source AND a Sink.\n"
                    f"You provided: [{provided_str}]\n"
                    f"You MISSING:  [source_location OR source_node_id]\n\n"
                    f"CORRECT USAGE WORKFLOW:\n"
                    f"1. Call `find_taint_sources(...)` first to find valid sources.\n"
                    f"2. Pick a source, note its `node_id` or `filename:line`.\n"
                    f"3. Call `find_taint_flows` again providing that source.\n\n"
                    f"EXAMPLE:\n"
                    f"find_taint_flows(\n"
                    f"    codebase_hash='...',\n"
                    f"    source_node_id=12345,  <-- YOU MUST PROVIDE THIS\n"
                    f"    sink_node_id=67890\n"
                    f")\n"
                    f"================================================================================"
                )
            
            # Must have sink (either location or node_id)
            if not has_sink_loc and not has_sink_id:
                raise ValidationError(
                    f"\n\n"
                    f"================================================================================\n"
                    f"CRITICAL ERROR: MISSING SINK\n"
                    f"================================================================================\n\n"
                    f"The `find_taint_flows` tool requires TWO endpoints: a Source AND a Sink.\n"
                    f"You provided: [{provided_str}]\n"
                    f"You MISSING:  [sink_location OR sink_node_id]\n\n"
                    f"CORRECT USAGE WORKFLOW:\n"
                    f"1. Call `find_taint_sinks(...)` first to find valid sinks.\n"
                    f"2. Pick a sink, note its `node_id` or `filename:line`.\n"
                    f"3. Call `find_taint_flows` again providing that sink.\n\n"
                    f"EXAMPLE:\n"
                    f"find_taint_flows(\n"
                    f"    codebase_hash='...',\n"
                    f"    source_node_id=12345,\n"
                    f"    sink_node_id=67890     <-- YOU MUST PROVIDE THIS\n"
                    f")\n"
                    f"================================================================================"
                )

            # Parse locations
            source_file, source_line = "", -1
            sink_file, sink_line = "", -1
            
            if has_source_loc:
                parts = source_location.split(":")
                if len(parts) < 2:
                    raise ValidationError(f"source_location must be 'file:line', got: {source_location}")
                source_file = parts[0]
                try:
                    source_line = int(parts[1])
                except ValueError:
                    raise ValidationError(f"Invalid line number in source_location: {source_location}")
            
            if has_sink_loc:
                parts = sink_location.split(":")
                if len(parts) < 2:
                    raise ValidationError(f"sink_location must be 'file:line', got: {sink_location}")
                sink_file = parts[0]
                try:
                    sink_line = int(parts[1])
                except ValueError:
                    raise ValidationError(f"Invalid line number in sink_location: {sink_location}")

            # Build query
            query = QueryLoader.load(
                "taint_flows",
                source_file=source_file,
                source_line=source_line,
                sink_file=sink_file,
                sink_line=sink_line,
                source_node_id=source_node_id if has_source_id else -1,
                sink_node_id=sink_node_id if has_sink_id else -1,
                max_results=max_results,
            )

            # Execute query
            result = query_executor.execute_query(
                codebase_hash=codebase_hash,
                cpg_path=codebase_info.cpg_path,
                query=query,
                timeout=timeout,
            )

            if not result.success:
                return f"Error: {result.error}"

            # Query returns human-readable text directly
            if isinstance(result.data, str):
                return result.data.strip()
            elif isinstance(result.data, list) and len(result.data) > 0:
                output = result.data[0] if isinstance(result.data[0], str) else str(result.data[0])
                return output.strip()
            else:
                return f"Query returned unexpected format: {type(result.data)}"

        except ValidationError as e:
            logger.error(f"Error finding taint flows: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error finding taint flows: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"

    @mcp.tool(
        description="""Build a program slice from a specific call location.

Creates a program slice showing code that affects (backward) or is affected by (forward)
a specific call, including dataflow and control dependencies. Optimized for static code analysis.

Args:
    codebase_hash: The codebase hash from generate_cpg.
    location: 'filename:line' or 'filename:line:call_name' (file relative to project root).
    direction: 'backward' (default, what affects the call) or 'forward' (what is affected by the call).
    max_depth: Depth limit for recursive dependency tracking (default 5).
    include_control_flow: Include control dependencies like if/while conditions (default True).
    timeout: Maximum execution time in seconds (default 60).

Returns:
    Human-readable text summary showing:
    - Target call info (name, code, location)
    - Backward slice: data dependencies, control dependencies, parameters
    - Forward slice: propagations, affected control flow

Notes:
    - Backward slice shows data origins and control conditions.
    - Forward slice shows how results propagate and affect control flow.
    - Use relative file paths like 'libxslt/numbers.c' not absolute paths.

Examples:
    get_program_slice(codebase_hash="abc", location="main.c:42")
    get_program_slice(codebase_hash="abc", location="parser.c:500:memcpy", direction="backward", max_depth=3)
    get_program_slice(codebase_hash="abc", location="module/file.c:100", direction="forward")"""
    )
    def get_program_slice(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        location: Annotated[str, Field(description="'filename:line' or 'filename:line:call_name'. Example: 'main.c:42' or 'main.c:42:memcpy'")],
        direction: Annotated[str, Field(description="Slice direction: 'backward' or 'forward'")] = "backward",
        max_depth: Annotated[int, Field(description="Maximum depth for recursive dependency tracking")] = 5,
        include_control_flow: Annotated[bool, Field(description="Include control dependencies (if/while conditions)")] = True,
        timeout: Annotated[int, Field(description="Maximum execution time in seconds")] = 60,
    ) -> str:
        """Get program slice showing code affecting (backward) or affected by (forward) a specific call."""
        try:
            validate_codebase_hash(codebase_hash)

            # Validate inputs
            if direction not in ["backward", "forward"]:
                raise ValidationError("direction must be 'backward' or 'forward'")

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            # Parse location
            parts = location.split(":")
            if len(parts) < 2:
                raise ValidationError("location must be 'filename:line' or 'filename:line:callname'")
            filename = parts[0]
            try:
                line_num = int(parts[1])
            except ValueError:
                raise ValidationError(f"Invalid line number in location: {parts[1]}")
            call_name = parts[2] if len(parts) > 2 else ""

            # Build comprehensive Scala query
            include_backward = direction == "backward"
            include_forward = direction == "forward"
            
            # Load query from external file
            query = QueryLoader.load(
                "program_slice",
                filename=filename,
                line_num=line_num,
                use_node_id="false",
                node_id="",
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
                return f"Error: {result.error}"

            # Query now returns human-readable text directly
            if isinstance(result.data, str):
                return result.data.strip()
            elif isinstance(result.data, list) and len(result.data) > 0:
                # Extract string from list wrapper
                output = result.data[0] if isinstance(result.data[0], str) else str(result.data[0])
                return output.strip()
            else:
                return f"Query returned unexpected format: {type(result.data)}"

        except ValidationError as e:
            logger.error(f"Error getting program slice: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error getting program slice: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"


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
                    "error": result.error,
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
                    "error": "Query returned no results",
                }

        except ValidationError as e:
            logger.error(f"Error getting data dependencies: {e}")
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