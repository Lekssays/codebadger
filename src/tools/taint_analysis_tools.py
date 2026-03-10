"""
Taint Analysis MCP Tools for CodeBadger Server
Security-focused tools for analyzing data flows and vulnerabilities
"""

import logging
import re
from typing import Any, Callable, Dict, Optional, Union, Annotated
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

# Default sanitizer/barrier functions by language
# Flows through these functions are considered "cleaned" and filtered out
DEFAULT_SANITIZERS = {
    "c": [
        "strlcpy", "strlcat",
        "snprintf", "vsnprintf",
        "strtol", "strtoul", "strtoll", "strtoull", "strtod",
        "atoi", "atol", "atof",
        "xmlEncodeEntities", "xmlEncodeSpecialChars",
        "htmlEncodeEntities",
    ],
    "cpp": [
        "strlcpy", "strlcat", "snprintf", "vsnprintf",
        "stoi", "stol", "stoul", "stod",
        "atoi", "atol", "atof",
    ],
    "java": [
        "escapeHtml", "escapeXml", "escapeSql", "escapeJavaScript",
        "encode", "parseInt", "parseLong", "parseDouble",
        "setString", "setInt", "setLong",
        "trim", "strip",
    ],
    "python": [
        "escape", "quote", "clean",
        "int", "float", "str",
    ],
    "javascript": [
        "encodeURIComponent", "encodeURI",
        "escapeHtml", "sanitize",
        "parseInt", "parseFloat", "Number",
    ],
    "go": [
        "EscapeString", "QueryEscape",
        "Atoi", "ParseInt", "ParseFloat",
        "Clean", "Base",
        "HTMLEscapeString",
    ],
    "php": [
        "htmlspecialchars", "htmlentities", "strip_tags",
        "addslashes", "mysqli_real_escape_string",
        "intval", "floatval",
        "filter_var", "filter_input",
        "urlencode", "rawurlencode",
    ],
    "ruby": [
        "sanitize", "h", "html_escape",
        "Integer", "Float",
    ],
    "csharp": [
        "HtmlEncode", "UrlEncode",
        "Escape", "TryParse", "ToInt32",
    ],
    "swift": [
        "addingPercentEncoding",
    ],
    "kotlin": [
        "escapeHtml", "encode",
        "toInt", "toLong", "toDouble",
    ],
}


def _build_file_filter_regex(filename: str) -> str:
    """Build a Joern-compatible regex for path-boundary anchored file filtering.

    Anchors the match to path boundaries (/ or start of string) so that
    'parser.c' matches '/path/to/parser.c' but NOT '/path/to/myparser.c'.

    The returned string is ready for embedding in Scala string literals
    (backslashes are doubled for Scala escaping).
    """
    # Escape regex-special chars with re.escape, then double backslashes
    # for Scala string literal embedding (Scala \\\\ → Java regex \\)
    py_escaped = re.escape(filename)
    scala_escaped = py_escaped.replace("\\", "\\\\")
    # Anchor to path boundary at start, allow trailing content for partial names
    return f"(^|.*/){scala_escaped}.*"


def _build_joern_name_pattern(patterns: list) -> str:
    """Build a Joern .name() regex pattern from a list of function names.

    Handles qualified names (e.g., 'os.system' -> 'system') since Joern's
    .name() matches short function names, not fully qualified names.
    """
    short_names = []
    for p in patterns:
        p = p.rstrip("(")
        # Extract short name from qualified patterns
        # e.g., 'os.system' -> 'system', 'net/http.Request.FormValue' -> 'FormValue'
        if "." in p:
            short_names.append(p.rsplit(".", 1)[-1])
        else:
            short_names.append(p)
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for name in short_names:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    return "|".join(re.escape(name) for name in unique)


def _cached_taint_query(
    services: dict,
    tool_name: str,
    codebase_hash: str,
    cache_params: Dict[str, Any],
    query_func: Callable[[], Union[Dict[str, Any], str]],
) -> Union[Dict[str, Any], str]:
    """Check cache, execute query on miss, cache successful results.

    Works for both dict-returning tools (sources/sinks) and
    str-returning tools (taint flows, slices, variable flow).
    """
    db_manager = services.get("db_manager")

    # Try cache first
    if db_manager:
        try:
            cached = db_manager.get_cached_tool_output(tool_name, codebase_hash, cache_params)
            if cached is not None:
                logger.debug(f"Cache hit for {tool_name}")
                return cached
        except Exception:
            pass  # cache lookup failure is non-fatal

    # Cache miss — execute the query
    result = query_func()

    # Cache successful results
    if db_manager:
        try:
            should_cache = False
            if isinstance(result, dict) and result.get("success", False):
                should_cache = True
            elif isinstance(result, str) and not result.startswith(("Error:", "Validation Error:", "Internal Error:")):
                should_cache = True

            if should_cache:
                db_manager.cache_tool_output(tool_name, codebase_hash, cache_params, result)
        except Exception:
            pass  # cache write failure is non-fatal

    return result


def _find_taint_flows_auto(
    services: dict,
    codebase_hash: str,
    codebase_info,
    query_executor,
    language: Optional[str],
    source_patterns: Optional[list],
    sink_patterns: Optional[list],
    sanitizer_patterns: Optional[list],
    filename: Optional[str],
    max_results: int,
    timeout: int,
) -> str:
    """Run batch taint analysis: all sources against all sinks in one query.

    Uses language-specific default patterns (or user overrides) to find all
    source and sink nodes, then runs reachableByFlows() once.
    Flows through sanitizer functions are filtered out.
    """
    # Resolve language
    lang = language or codebase_info.language or "c"

    # Resolve source patterns: user-provided -> config -> built-in defaults
    cfg = services["config"]
    taint_src_cfg = (
        getattr(cfg.cpg, "taint_sources", {})
        if hasattr(cfg.cpg, "taint_sources")
        else {}
    )
    src_patterns = source_patterns or taint_src_cfg.get(lang, []) or DEFAULT_SOURCES.get(lang.lower(), [])
    if not src_patterns:
        return f"No taint source patterns available for language '{lang}'. Supported: {', '.join(DEFAULT_SOURCES.keys())}"

    # Resolve sink patterns: user-provided -> config -> built-in defaults
    taint_snk_cfg = (
        getattr(cfg.cpg, "taint_sinks", {})
        if hasattr(cfg.cpg, "taint_sinks")
        else {}
    )
    snk_patterns = sink_patterns or taint_snk_cfg.get(lang, []) or DEFAULT_SINKS.get(lang.lower(), [])
    if not snk_patterns:
        return f"No taint sink patterns available for language '{lang}'. Supported: {', '.join(DEFAULT_SINKS.keys())}"

    # Resolve sanitizer patterns: user-provided -> config -> built-in defaults
    taint_san_cfg = (
        getattr(cfg.cpg, "taint_sanitizers", {})
        if hasattr(cfg.cpg, "taint_sanitizers")
        else {}
    )
    san_patterns = sanitizer_patterns or taint_san_cfg.get(lang, []) or DEFAULT_SANITIZERS.get(lang.lower(), [])

    # Build Joern regex patterns
    source_regex = _build_joern_name_pattern(src_patterns)
    sink_regex = _build_joern_name_pattern(snk_patterns)
    sanitizer_regex = _build_joern_name_pattern(san_patterns) if san_patterns else ""

    # Build file filter regex with path-boundary anchoring
    file_filter_regex = _build_file_filter_regex(filename) if filename else ""

    cache_params = {
        "mode": "auto",
        "lang": lang,
        "source_patterns": sorted(set(src_patterns)),
        "sink_patterns": sorted(set(snk_patterns)),
        "sanitizer_patterns": sorted(set(san_patterns)) if san_patterns else [],
        "filename": filename,
        "max_results": max_results,
    }

    def _execute():
        query = QueryLoader.load(
            "taint_flows_auto",
            source_pattern=source_regex,
            sink_pattern=sink_regex,
            sanitizer_pattern=sanitizer_regex,
            file_filter=file_filter_regex,
            max_results=max_results,
        )

        result = query_executor.execute_query(
            codebase_hash=codebase_hash,
            cpg_path=codebase_info.cpg_path,
            query=query,
            timeout=timeout,
        )

        if not result.success:
            return f"Error: {result.error}"

        if isinstance(result.data, str):
            return result.data.strip()
        elif isinstance(result.data, list) and len(result.data) > 0:
            output = result.data[0] if isinstance(result.data[0], str) else str(result.data[0])
            return output.strip()
        else:
            return f"Query returned unexpected format: {type(result.data)}"

    return _cached_taint_query(services, "find_taint_flows_auto", codebase_hash, cache_params, _execute)


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
    find_taint_sources(codebase_hash="abc", source_patterns=["read_from_socket"])""",
        timeout=120,
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

            # Build Joern .name() regex from patterns, extracting short names
            # from qualified patterns (e.g., 'os.system' -> 'system')
            joined = _build_joern_name_pattern(patterns)

            cache_params = {"lang": lang, "patterns": sorted(set(patterns)), "filename": filename, "limit": limit}

            def _execute():
                # Build query with optional file filter
                if filename:
                    file_regex = _build_file_filter_regex(filename)
                    query = f'cpg.call.name("{joined}").where(_.file.name("{file_regex}")).map(c => (c.id, c.name, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName)).take({limit})'
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
                    return {"success": False, "error": result.error}

                sources = []
                for item in result.data:
                    if isinstance(item, dict):
                        sources.append({
                            "node_id": item.get("_1"),
                            "name": item.get("_2"),
                            "code": item.get("_3"),
                            "filename": item.get("_4"),
                            "lineNumber": item.get("_5"),
                            "method": item.get("_6"),
                        })

                return {
                    "success": True,
                    "sources": sources,
                    "total": len(sources),
                    "limit": limit,
                    "has_more": len(sources) >= limit,
                }

            return _cached_taint_query(services, "find_taint_sources", codebase_hash, cache_params, _execute)

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
    find_taint_sinks(codebase_hash="abc", sink_patterns=["custom_exec"])""",
        timeout=120,
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

            # Build Joern .name() regex from patterns, extracting short names
            # from qualified patterns (e.g., 'os.system' -> 'system')
            joined = _build_joern_name_pattern(patterns)

            cache_params = {"lang": lang, "patterns": sorted(set(patterns)), "filename": filename, "limit": limit}

            def _execute():
                # Build query with optional file filter
                if filename:
                    file_regex = _build_file_filter_regex(filename)
                    query = f'cpg.call.name("{joined}").where(_.file.name("{file_regex}")).map(c => (c.id, c.name, c.code, c.file.name.headOption.getOrElse("unknown"), c.lineNumber.getOrElse(-1), c.method.fullName)).take({limit})'
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
                    return {"success": False, "error": result.error}

                sinks = []
                for item in result.data:
                    if isinstance(item, dict):
                        sinks.append({
                            "node_id": item.get("_1"),
                            "name": item.get("_2"),
                            "code": item.get("_3"),
                            "filename": item.get("_4"),
                            "lineNumber": item.get("_5"),
                            "method": item.get("_6"),
                        })

                return {
                    "success": True,
                    "sinks": sinks,
                    "total": len(sinks),
                    "limit": limit,
                    "has_more": len(sinks) >= limit,
                }

            return _cached_taint_query(services, "find_taint_sinks", codebase_hash, cache_params, _execute)

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

Supports two modes:

MODE 1 - Manual (default): Provide a specific source and sink.
  - Use `find_taint_sources` first to get source locations/IDs.
  - Use `find_taint_sinks` first to get sink locations/IDs.
  - Provide BOTH source AND sink for every query.

MODE 2 - Auto (mode="auto"): Batch-test ALL default sources against ALL default sinks.
  - Runs `sinks.reachableByFlows(sources)` once for all default patterns.
  - Returns ONLY confirmed flows — no manual source/sink picking needed.
  - Ideal for security audits: one call covers hundreds of source-sink pairs.
  - Optionally filter by language, filename, or custom source/sink patterns.

Args:
    codebase_hash: The codebase hash from generate_cpg.
    mode: Set to "auto" to run batch analysis with all default sources/sinks. Omit for manual mode.
    source_location: (Manual mode) Source at 'file:line' (e.g., 'xsltproc/xsltproc.c:818').
    sink_location: (Manual mode) Sink at 'file:line' (e.g., 'libxslt/numbers.c:229').
    source_node_id: (Manual mode) Alternative: node ID from find_taint_sources output.
    sink_node_id: (Manual mode) Alternative: node ID from find_taint_sinks output.
    language: (Auto mode) Programming language for default patterns (c, cpp, java, python, etc). Auto-detected if omitted.
    source_patterns: (Auto mode) Optional list of source function names to override defaults (e.g., ['getenv', 'read']).
    sink_patterns: (Auto mode) Optional list of sink function names to override defaults (e.g., ['system', 'strcpy']).
    filename: (Auto mode) Optional regex to filter sources/sinks by filename.
    max_results: Maximum flows to return (default 20).
    timeout: Query timeout in seconds (default 120 for manual, 300 for auto).

Returns:
    Human-readable text showing:
    - Source and sink matched
    - Detailed flow path showing each intermediate step
    - Path length

Notes:
    - Manual mode: BOTH source AND sink are required.
    - Auto mode: No source/sink needed — uses language-specific default patterns.
    - Inter-procedural flows are tracked automatically.

Examples:
    # Auto mode — one call finds all confirmed flows
    find_taint_flows(codebase_hash="...", mode="auto")
    find_taint_flows(codebase_hash="...", mode="auto", language="c", filename="main.c")
    find_taint_flows(codebase_hash="...", mode="auto", source_patterns=["getenv"], sink_patterns=["system", "strcpy"])

    # Manual mode — specific source and sink
    find_taint_flows(codebase_hash="...", source_location="main.c:42", sink_location="utils.c:100")
    find_taint_flows(codebase_hash="...", source_node_id=12345, sink_node_id=67890)""",
        timeout=300,
    )
    def find_taint_flows(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        source_location: Annotated[Optional[str], Field(description="(Manual mode) Source at 'file:line' (e.g., 'parser.c:782')")] = None,
        sink_location: Annotated[Optional[str], Field(description="(Manual mode) Sink at 'file:line' (e.g., 'parser.c:800')")] = None,
        source_node_id: Annotated[Optional[int], Field(description="(Manual mode) Node ID from find_taint_sources output")] = None,
        sink_node_id: Annotated[Optional[int], Field(description="(Manual mode) Node ID from find_taint_sinks output")] = None,
        max_results: Annotated[int, Field(description="Maximum flows to return")] = 20,
        timeout: Annotated[int, Field(description="Query timeout in seconds (default 120 for manual, 300 for auto)")] = 120,
        mode: Annotated[Optional[str], Field(description="Set to 'auto' for batch analysis with all default sources/sinks. Omit for manual mode.")] = None,
        language: Annotated[Optional[str], Field(description="(Auto mode) Programming language for default patterns. Auto-detected if omitted.")] = None,
        source_patterns: Annotated[Optional[list], Field(description="(Auto mode) Override default source function names (e.g., ['getenv', 'read'])")] = None,
        sink_patterns: Annotated[Optional[list], Field(description="(Auto mode) Override default sink function names (e.g., ['system', 'strcpy'])")] = None,
        filename: Annotated[Optional[str], Field(description="(Auto mode) Regex to filter sources/sinks by filename")] = None,
        sanitizer_patterns: Annotated[Optional[list], Field(description="(Auto mode) Override default sanitizer function names. Flows through sanitizers are filtered out.")] = None,
        # Legacy/Deprecated arguments - included to provide helpful error messages
        source_pattern: Annotated[Optional[str], Field(description="DEPRECATED: Do not use")] = None,
        sink_pattern: Annotated[Optional[str], Field(description="DEPRECATED: Do not use")] = None,
        depth: Annotated[Optional[int], Field(description="DEPRECATED: Do not use")] = None,
    ) -> str:
        """Find data flow paths between source and sink using Joern's native taint analysis."""
        try:
            # Check for legacy arguments that LLMs might hallucinate
            legacy_args = []
            if source_pattern: legacy_args.append("source_pattern")
            if sink_pattern: legacy_args.append("sink_pattern")
            if depth: legacy_args.append("depth")

            if legacy_args:
                raise ValidationError(
                    f"Unexpected arguments: {legacy_args}. "
                    "These arguments are deprecated. "
                    "Use 'find_taint_sources' to find sources by pattern, then use the resulting 'node_id' here. "
                    "Or use mode='auto' for batch analysis."
                )

            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first.")

            # --- AUTO MODE ---
            if mode == "auto":
                return _find_taint_flows_auto(
                    services=services,
                    codebase_hash=codebase_hash,
                    codebase_info=codebase_info,
                    query_executor=query_executor,
                    language=language,
                    source_patterns=source_patterns,
                    sink_patterns=sink_patterns,
                    sanitizer_patterns=sanitizer_patterns,
                    filename=filename,
                    max_results=max_results,
                    timeout=timeout if timeout != 120 else 300,  # default to 300s for auto mode (large codebases need more time)
                )

            # --- MANUAL MODE ---
            if mode is not None:
                raise ValidationError(
                    f"Invalid mode: '{mode}'. Use mode='auto' for batch analysis, "
                    "or omit mode for manual source/sink analysis."
                )

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
                    f"Option A — Manual mode:\n"
                    f"  1. Call `find_taint_sources(...)` first to find valid sources.\n"
                    f"  2. Pick a source, note its `node_id` or `filename:line`.\n"
                    f"  3. Call `find_taint_flows` again providing that source.\n\n"
                    f"Option B — Auto mode (recommended for audits):\n"
                    f"  find_taint_flows(codebase_hash='...', mode='auto')\n\n"
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
                    f"Option A — Manual mode:\n"
                    f"  1. Call `find_taint_sinks(...)` first to find valid sinks.\n"
                    f"  2. Pick a sink, note its `node_id` or `filename:line`.\n"
                    f"  3. Call `find_taint_flows` again providing that sink.\n\n"
                    f"Option B — Auto mode (recommended for audits):\n"
                    f"  find_taint_flows(codebase_hash='...', mode='auto')\n\n"
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

            cache_params = {
                "source_location": source_location,
                "sink_location": sink_location,
                "source_node_id": source_node_id if has_source_id else None,
                "sink_node_id": sink_node_id if has_sink_id else None,
                "max_results": max_results,
            }

            def _execute():
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

                result = query_executor.execute_query(
                    codebase_hash=codebase_hash,
                    cpg_path=codebase_info.cpg_path,
                    query=query,
                    timeout=timeout,
                )

                if not result.success:
                    return f"Error: {result.error}"

                if isinstance(result.data, str):
                    return result.data.strip()
                elif isinstance(result.data, list) and len(result.data) > 0:
                    output = result.data[0] if isinstance(result.data[0], str) else str(result.data[0])
                    return output.strip()
                else:
                    return f"Query returned unexpected format: {type(result.data)}"

            return _cached_taint_query(services, "find_taint_flows", codebase_hash, cache_params, _execute)

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
    get_program_slice(codebase_hash="abc", location="module/file.c:100", direction="forward")""",
        timeout=300,
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

            include_backward = direction == "backward"
            include_forward = direction == "forward"

            cache_params = {
                "location": location,
                "direction": direction,
                "max_depth": max_depth,
                "include_control_flow": include_control_flow,
            }

            def _execute():
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

                result = query_executor.execute_query(
                    codebase_hash=codebase_hash,
                    cpg_path=codebase_info.cpg_path,
                    query=query,
                    timeout=timeout,
                )

                if not result.success:
                    return f"Error: {result.error}"

                if isinstance(result.data, str):
                    return result.data.strip()
                elif isinstance(result.data, list) and len(result.data) > 0:
                    output = result.data[0] if isinstance(result.data[0], str) else str(result.data[0])
                    return output.strip()
                else:
                    return f"Query returned unexpected format: {type(result.data)}"

            return _cached_taint_query(services, "get_program_slice", codebase_hash, cache_params, _execute)

        except ValidationError as e:
            logger.error(f"Error getting program slice: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error getting program slice: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"


    @mcp.tool(
        description="""Analyze data dependencies for a variable at a specific location.

Finds code locations that influence (backward) or are influenced by (forward)
a variable, with support for pointer aliasing.

Args:
    codebase_hash: The codebase hash.
    location: "filename:line" (e.g., "parser.c:3393"), filename relative to project root.
    variable: Variable name to analyze.
    direction: "backward" (definitions) or "forward" (usages).

Returns:
    Human-readable text showing:
    - Target variable and method
    - Aliases detected
    - List of dependencies

Notes:
    - Backward: Finds initialization, assignment, modification, and pointer assignment.
    - Forward: Finds usage, propagation, and modification.
    - location filename should be relative to the project root.

Examples:
    get_variable_flow(codebase_hash="abc", location="main.c:50", variable="len", direction="backward")""",
        timeout=120,
    )
    def get_variable_flow(
        codebase_hash: str,
        location: str,
        variable: str,
        direction: str = "backward",
    ) -> str:
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

            cache_params = {
                "location": location,
                "variable": variable,
                "direction": direction,
            }

            def _execute():
                query = QueryLoader.load(
                    "variable_flow",
                    filename=filename,
                    line_num=line_num,
                    variable=variable,
                    direction=direction
                )

                result = query_executor.execute_query(
                    codebase_hash=codebase_hash,
                    cpg_path=codebase_info.cpg_path,
                    query=query,
                    timeout=60,
                )

                if not result.success:
                    return f"Error: {result.error}"

                if isinstance(result.data, str):
                    return result.data.strip()
                elif isinstance(result.data, list) and len(result.data) > 0:
                    output = result.data[0] if isinstance(result.data[0], str) else str(result.data[0])
                    return output.strip()
                else:
                    return f"Query returned unexpected format: {type(result.data)}"

            return _cached_taint_query(services, "get_variable_flow", codebase_hash, cache_params, _execute)

        except ValidationError as e:
            logger.error(f"Error getting data dependencies: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"

    @mcp.tool(
        description="""Detect Use-After-Free vulnerabilities by finding free(ptr) calls where ptr is used afterward.

Analyzes the codebase for potential UAF issues using three-phase detection:
1. **Intraprocedural**: Finds usages of freed pointers within the same function
2. **Pointer Aliasing**: Tracks p2 = ptr; free(ptr); use(p2) patterns  
3. **Deep Interprocedural**: Uses Joern's reachableByFlows() to track freed pointers
   across MULTIPLE function call levels (e.g., main -> func1 -> func2 -> usage)

Filters out false positives:
- Frees/usages in different if/else branches
- Frees with early returns before usage
- Usage that is itself a reassignment (e.g., ptr = NULL)
- Pointer reassignments between free and usage

Supports free() variants: free, cfree, g_free, xmlFree, xsltFree*

Args:
    codebase_hash: The codebase hash from generate_cpg.
    filename: Optional filename regex to filter results (e.g., 'runtest.c').
    limit: Maximum results to return (default 100).
    timeout: Query timeout in seconds (default 300, higher due to dataflow analysis).

Returns:
    Human-readable text showing:
    - Each potential UAF issue with free site location [file:line]
    - The freed pointer name
    - List of post-free usages with [file:line] and flow type tags
    - For interprocedural flows: the call path (e.g., "main -> func1 -> func2")

Notes:
    - Deep interprocedural analysis can be slow (~2 min for large codebases).
    - Use get_program_slice to understand control flow around specific locations.
    - Use find_taint_flows for alternative dataflow analysis approach.""",
        timeout=300,
    )
    def find_use_after_free(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        filename: Annotated[Optional[str], Field(description="Optional filename regex to filter results")] = None,
        limit: Annotated[int, Field(description="Maximum results to return")] = 100,
        timeout: Annotated[int, Field(description="Query timeout in seconds")] = 300,
    ) -> str:
        """Detect potential Use-After-Free vulnerabilities in the codebase."""
        try:
            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            cache_params = {
                "filename": filename,
                "limit": limit,
            }

            def _execute():
                query = QueryLoader.load(
                    "use_after_free",
                    filename=filename or "",
                    limit=limit,
                )

                result = query_executor.execute_query(
                    codebase_hash=codebase_hash,
                    cpg_path=codebase_info.cpg_path,
                    query=query,
                    timeout=timeout,
                )

                if not result.success:
                    return f"Error: {result.error}"

                if isinstance(result.data, str):
                    return result.data.strip()
                elif isinstance(result.data, list) and len(result.data) > 0:
                    output = result.data[0] if isinstance(result.data[0], str) else str(result.data[0])
                    return output.strip()
                else:
                    return f"Query returned unexpected format: {type(result.data)}"

            return _cached_taint_query(services, "find_use_after_free", codebase_hash, cache_params, _execute)

        except ValidationError as e:
            logger.error(f"Error detecting use-after-free: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error detecting use-after-free: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"

    @mcp.tool(
        description="""Detect Double-Free vulnerabilities by finding multiple free() calls on the same pointer.

Analyzes the codebase for potential double-free issues using:
1. **Intraprocedural**: Multiple free() on the same pointer in the same function
2. **Pointer Aliasing**: Tracks p2 = ptr; free(ptr); free(p2) patterns
3. **Interprocedural**: Detects when freed pointer is passed to a function that also frees it

Filters out false positives:
- Frees in different if/else branches
- Frees with early returns between them
- Intervening reallocations (malloc, realloc, strdup)
- Pointer reassignments between frees

Supports free() variants: free, cfree, g_free, xmlFree, xsltFree*

Args:
    codebase_hash: The codebase hash from generate_cpg.
    filename: Optional filename regex to filter results (e.g., 'parser.c').
    limit: Maximum results to return (default 100).
    timeout: Query timeout in seconds (default 300).

Returns:
    Human-readable text showing:
    - Each potential double-free issue with pointer name
    - First and second free locations with [file:line]
    - Flow type (same-ptr, alias, or [CROSS-FUNC])""",
        timeout=300,
    )
    def find_double_free(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        filename: Annotated[Optional[str], Field(description="Optional filename regex to filter results")] = None,
        limit: Annotated[int, Field(description="Maximum results to return")] = 100,
        timeout: Annotated[int, Field(description="Query timeout in seconds")] = 300,
    ) -> str:
        """Detect potential Double-Free vulnerabilities in the codebase."""
        try:
            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            cache_params = {
                "filename": filename,
                "limit": limit,
            }

            def _execute():
                query = QueryLoader.load(
                    "double_free",
                    filename=filename or "",
                    limit=limit,
                )

                result = query_executor.execute_query(
                    codebase_hash=codebase_hash,
                    cpg_path=codebase_info.cpg_path,
                    query=query,
                    timeout=timeout,
                )

                if not result.success:
                    return f"Error: {result.error}"

                if isinstance(result.data, str):
                    return result.data.strip()
                elif isinstance(result.data, list) and len(result.data) > 0:
                    output = result.data[0] if isinstance(result.data[0], str) else str(result.data[0])
                    return output.strip()
                else:
                    return f"Query returned unexpected format: {type(result.data)}"

            return _cached_taint_query(services, "find_double_free", codebase_hash, cache_params, _execute)

        except ValidationError as e:
            logger.error(f"Error detecting double-free: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error detecting double-free: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"

    @mcp.tool(
        description="""Detect Null Pointer Dereference vulnerabilities (CWE-476) by finding unchecked return values from allocation functions.

Analyzes the codebase for cases where:
1. **Unchecked malloc/calloc/realloc**: ptr = malloc(n); ptr->field = value; without NULL check
2. **Unchecked fopen/strdup/mmap**: Functions that can return NULL on failure
3. **Missing NULL guards**: Pointer dereference without prior if(ptr != NULL) check
4. **Deep Interprocedural**: Uses Joern's reachableByFlows() to track allocated pointers
   across MULTIPLE function call levels (e.g., main -> func1 -> func2 -> dereference)

Filters out false positives:
- Dereferences guarded by if(ptr != NULL) or if(!ptr) checks
- Dereferences after early return/exit/abort on NULL
- Pointer reassignments between allocation and use
- Safe wrapper allocators (xmalloc, g_malloc, etc.) that guarantee non-NULL
- Cross-function dereferences with NULL checks in callee

Allocation functions checked: malloc, calloc, realloc, strdup, strndup, aligned_alloc,
reallocarray, fopen, fdopen, freopen, tmpfile, popen, dlopen, mmap,
xmlMalloc, xmlMallocAtomic, xmlRealloc, xmlStrdup, xmlStrndup

Args:
    codebase_hash: The codebase hash from generate_cpg.
    filename: Optional filename regex to filter results (e.g., 'parser.c').
    limit: Maximum results to return (default 100).
    timeout: Query timeout in seconds (default 300).

Returns:
    Human-readable text showing:
    - Each potential null pointer dereference with allocation site [file:line]
    - The assigned pointer name
    - List of unchecked dereferences with [file:line] and type tags
    - For interprocedural flows: the call path (e.g., "main -> func1 -> func2")

Notes:
    - Includes deep interprocedural analysis using Joern's dataflow engine.
    - Use get_program_slice for deeper control-flow context around specific locations.
    - Use find_taint_flows to check if allocation arguments come from external input.""",
        timeout=300,
    )
    def find_null_pointer_deref(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        filename: Annotated[Optional[str], Field(description="Optional filename regex to filter results")] = None,
        limit: Annotated[int, Field(description="Maximum results to return")] = 100,
        timeout: Annotated[int, Field(description="Query timeout in seconds")] = 300,
    ) -> str:
        """Detect potential Null Pointer Dereference vulnerabilities in the codebase."""
        try:
            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            cache_params = {
                "filename": filename,
                "limit": limit,
            }

            def _execute():
                query = QueryLoader.load(
                    "null_pointer_deref",
                    filename=filename or "",
                    limit=limit,
                )

                result = query_executor.execute_query(
                    codebase_hash=codebase_hash,
                    cpg_path=codebase_info.cpg_path,
                    query=query,
                    timeout=timeout,
                )

                if not result.success:
                    return f"Error: {result.error}"

                if isinstance(result.data, str):
                    return result.data.strip()
                elif isinstance(result.data, list) and len(result.data) > 0:
                    output = result.data[0] if isinstance(result.data[0], str) else str(result.data[0])
                    return output.strip()
                else:
                    return f"Query returned unexpected format: {type(result.data)}"

            return _cached_taint_query(services, "find_null_pointer_deref", codebase_hash, cache_params, _execute)

        except ValidationError as e:
            logger.error(f"Error detecting null pointer dereference: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error detecting null pointer dereference: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"

    @mcp.tool(
        description="""Detect Integer Overflow/Underflow vulnerabilities (CWE-190) before allocation or array indexing.

Analyzes the codebase for cases where arithmetic operations (multiplication, left-shift,
addition, subtraction) could overflow/underflow before being used as:
1. **Allocation size**: malloc(count * elem_size) where the multiplication can wrap around
2. **Array index**: buffer[offset * stride] where the multiplication can wrap around

Detection phases:
1. **Direct arithmetic in allocation size**: Finds malloc/realloc calls where the size
   argument contains unchecked multiplication or left-shift
2. **Indirect arithmetic via variable**: Tracks size = a * b; malloc(size) patterns
3. **Array index arithmetic**: Finds array indexing with unchecked multiplication/left-shift
4. **Deep interprocedural**: Uses Joern's reachableByFlows() to track arithmetic results
   flowing across function boundaries into allocation size arguments

Filters out false positives:
- Constant expressions (sizeof * literal, compile-time constants)
- Arithmetic guarded by overflow checks (SIZE_MAX, __builtin_*_overflow, etc.)
- calloc/reallocarray (handle multiplication overflow internally)
- Single-variable + constant additions (e.g., len + 1)
- Array indices with preceding bounds checks

Args:
    codebase_hash: The codebase hash from generate_cpg.
    filename: Optional filename regex to filter results (e.g., 'parser.c').
    limit: Maximum results to return (default 100).
    timeout: Query timeout in seconds (default 300).

Returns:
    Human-readable text showing:
    - Each potential overflow issue with location [file:line]
    - The arithmetic expression and operation type
    - Risk level (HIGH for mult/shift in alloc, MEDIUM for add/sub or array index)
    - [CROSS-FUNC] tag for interprocedural flows

Notes:
    - Includes deep interprocedural analysis using Joern's dataflow engine.
    - Use get_program_slice for deeper control-flow context around specific locations.
    - Use find_taint_flows to check if arithmetic operands come from external input.""",
        timeout=300,
    )
    def find_integer_overflow(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        filename: Annotated[Optional[str], Field(description="Optional filename regex to filter results")] = None,
        limit: Annotated[int, Field(description="Maximum results to return")] = 100,
        timeout: Annotated[int, Field(description="Query timeout in seconds")] = 300,
    ) -> str:
        """Detect potential Integer Overflow/Underflow vulnerabilities in the codebase."""
        try:
            validate_codebase_hash(codebase_hash)

            codebase_tracker = services["codebase_tracker"]
            query_executor = services["query_executor"]

            # Verify CPG exists
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            if not codebase_info or not codebase_info.cpg_path:
                raise ValidationError(f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg.")

            cache_params = {
                "filename": filename,
                "limit": limit,
            }

            def _execute():
                query = QueryLoader.load(
                    "integer_overflow",
                    filename=filename or "",
                    limit=limit,
                )

                result = query_executor.execute_query(
                    codebase_hash=codebase_hash,
                    cpg_path=codebase_info.cpg_path,
                    query=query,
                    timeout=timeout,
                )

                if not result.success:
                    return f"Error: {result.error}"

                if isinstance(result.data, str):
                    return result.data.strip()
                elif isinstance(result.data, list) and len(result.data) > 0:
                    output = result.data[0] if isinstance(result.data[0], str) else str(result.data[0])
                    return output.strip()
                else:
                    return f"Query returned unexpected format: {type(result.data)}"

            return _cached_taint_query(services, "find_integer_overflow", codebase_hash, cache_params, _execute)

        except ValidationError as e:
            logger.error(f"Error detecting integer overflow: {e}")
            return f"Validation Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error detecting integer overflow: {e}", exc_info=True)
            return f"Internal Error: {str(e)}"