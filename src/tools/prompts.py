"""
MCP Prompt Templates for CodeBadger Server

Pre-built security analysis workflows that guide LLMs through
CodeBadger's tools for systematic vulnerability discovery and
code security assessment.
"""

from typing import Optional
from fastmcp.prompts import Message

CONFIDENCE_POLICY = """
## Confidence & False-Positive Policy
**Only report findings where you are at least 80% confident they represent a real issue.**
- After gathering tool results, critically evaluate each potential finding before including it.
- Cross-reference: verify a finding with at least two signals (e.g. confirmed taint flow + dangerous sink without sanitization, or CFG shows reachable path + no bounds check).
- Discard findings that are likely false positives: dead code paths, safely wrapped calls, test-only code, or sinks that are unreachable from external input.
- If a finding is borderline (50-80% confidence), include it in a separate "Needs Manual Review" section with an explanation of why it is uncertain.
- Never pad the report with low-confidence noise. A short report with 3 real findings is far more valuable than a long report with 20 speculative ones.
""".strip()


def register_prompts(mcp):
    """Register all MCP prompts with the FastMCP server"""

    @mcp.prompt(
        name="security_audit",
        description="Comprehensive security audit — maps attack surface and discovers vulnerabilities across a codebase.",
        tags={"security", "audit"},
    )
    def security_audit(
        codebase_hash: str,
        language: Optional[str] = None,
        focus_area: Optional[str] = None,
    ) -> list[Message]:
        """Run a full security audit on a codebase."""

        lang_clause = ""
        if language:
            lang_clause = f' Use language="{language}" for all language-specific tool calls.'

        focus_instructions = ""
        if focus_area and focus_area != "all":
            focus_map = {
                "injection": (
                    "Focus specifically on injection vulnerabilities: SQL injection, "
                    "command injection, code injection, XSS, and path traversal. "
                    "Pay close attention to taint flows reaching exec/eval/query sinks."
                ),
                "memory": (
                    "Focus specifically on memory safety: use-after-free, double-free, "
                    "buffer overflows, and missing bounds checks. Run find_use_after_free, "
                    "find_double_free, and find_bounds_checks."
                ),
                "authentication": (
                    "Focus specifically on authentication and authorization: look for "
                    "methods matching patterns like auth, login, password, session, token, "
                    "permission, role. Check if these handle user input safely."
                ),
                "crypto": (
                    "Focus specifically on cryptographic issues: look for calls to weak "
                    "algorithms (MD5, SHA1, DES, RC4, ECB mode), hardcoded keys, insecure "
                    "random number generators (rand, srand, Math.random)."
                ),
            }
            focus_instructions = focus_map.get(focus_area, "")

        memory_instructions = ""
        if not focus_area or focus_area in ("memory", "all"):
            memory_instructions = """

## Phase 3b: Memory Safety (if C/C++)
If the codebase language is C or C++, also run:
7. `find_use_after_free(codebase_hash="{hash}")` — detect use-after-free vulnerabilities
8. `find_double_free(codebase_hash="{hash}")` — detect double-free vulnerabilities
9. `find_bounds_checks(codebase_hash="{hash}")` — find buffer accesses missing bounds checks""".format(hash=codebase_hash)

        analysis_text = f"""You are performing a comprehensive security audit on codebase `{codebase_hash}`.{lang_clause}
{f"**Focus**: {focus_instructions}" if focus_instructions else ""}

{CONFIDENCE_POLICY}

Follow this systematic workflow:

## Phase 1: Reconnaissance
1. Call `get_codebase_summary(codebase_hash="{codebase_hash}")` to understand scope (language, files, methods, calls)
2. Call `list_source_files(codebase_hash="{codebase_hash}")` to understand the project structure
3. Call `discover_fixed_vulnerabilities(codebase_hash="{codebase_hash}")` to find historical vulnerability hints from git history

## Phase 2: Attack Surface Mapping
4. Call `find_taint_sources(codebase_hash="{codebase_hash}"{f', language="{language}"' if language else ''})` to enumerate all external input points
5. Call `find_taint_sinks(codebase_hash="{codebase_hash}"{f', language="{language}"' if language else ''})` to enumerate all dangerous operations

## Phase 3: Automated Taint Analysis
6. Call `find_taint_flows(codebase_hash="{codebase_hash}", mode="auto"{f', language="{language}"' if language else ''})` to discover all confirmed source-to-sink data flows
{memory_instructions}

## Phase 4: Deep Investigation
For each confirmed vulnerability or taint flow:
- Call `get_file_content(codebase_hash="{codebase_hash}", method_name="<vulnerable_function>")` to view the full source
- Call `get_program_slice(codebase_hash="{codebase_hash}", ...)` to trace data origins backward
- Call `get_variable_flow(codebase_hash="{codebase_hash}", ...)` for specific variable tracking

## Phase 5: Report
Produce a structured security audit report with:
- **Executive Summary**: Overall risk level and key findings count
- **Findings Table**: Each vulnerability with severity (Critical/High/Medium/Low), CWE ID, affected file:line, and description
- **Detailed Findings**: For each finding — vulnerable code snippet, data flow path, exploitability assessment, and remediation recommendation
- **Attack Surface Summary**: Count of input points, dangerous sinks, and confirmed flow paths"""

        return [
            Message(analysis_text),
            Message(
                "I'll perform a systematic security audit following the phased workflow. "
                "Let me start with reconnaissance.",
                role="assistant",
            ),
        ]

    @mcp.prompt(
        name="memory_safety_check",
        description="C/C++ memory safety analysis — detects use-after-free, double-free, and buffer overflow vulnerabilities.",
        tags={"security", "memory"},
    )
    def memory_safety_check(
        codebase_hash: str,
        filename: Optional[str] = None,
    ) -> str:
        """Focused memory safety analysis for C/C++ codebases."""

        file_filter = ""
        if filename:
            file_filter = f', filename="{filename}"'

        return f"""You are performing a memory safety analysis on codebase `{codebase_hash}`.
{f"**Scope**: Focused on file `{filename}`" if filename else "**Scope**: Entire codebase"}

{CONFIDENCE_POLICY}

Follow this workflow:

## Step 1: Verify Language
Call `get_codebase_summary(codebase_hash="{codebase_hash}")` to confirm this is a C or C++ codebase.
If not C/C++, inform the user that memory safety checks are primarily relevant for C/C++ but offer to check for language-appropriate issues.

## Step 2: Use-After-Free Detection
Call `find_use_after_free(codebase_hash="{codebase_hash}"{file_filter})` to find cases where memory is accessed after being freed.
- CWE-416: Use After Free
- For each finding, note the free() call location and the subsequent use location

## Step 3: Double-Free Detection
Call `find_double_free(codebase_hash="{codebase_hash}"{file_filter})` to find cases where the same pointer is freed twice.
- CWE-415: Double Free
- For each finding, note both free() locations and the pointer involved

## Step 4: Buffer Overflow Detection
Call `find_taint_sinks(codebase_hash="{codebase_hash}", language="c", sink_patterns=["memcpy", "strcpy", "strcat", "sprintf", "gets", "memmove", "strncpy", "strncat", "vsprintf", "sscanf"])` to find buffer-writing operations.
For each dangerous buffer operation found, call `find_bounds_checks(codebase_hash="{codebase_hash}", buffer_access_location="<file>:<line>")` to check if bounds validation exists nearby.
- CWE-120: Buffer Copy without Checking Size
- CWE-787: Out-of-bounds Write

## Step 5: Trace Data Origins
For each confirmed vulnerability, call `get_program_slice(codebase_hash="{codebase_hash}", ...)` with direction="backward" to trace where the data or pointer originated.
Call `get_file_content(codebase_hash="{codebase_hash}", method_name="<function>")` to view the full function context.

## Step 6: Report
Produce a memory safety report grouped by category:

### Use-After-Free (CWE-416)
For each: file:line, pointer name, free location, use location, exploitability, fix

### Double-Free (CWE-415)
For each: file:line, pointer name, first free, second free, fix

### Buffer Overflows (CWE-120/CWE-787)
For each: file:line, function called, buffer size (if determinable), bounds check present (yes/no), fix

Rate each finding: Critical / High / Medium / Low based on exploitability and impact."""

    @mcp.prompt(
        name="taint_flow_investigation",
        description="Investigate data flow from untrusted source to dangerous sink — trace how attacker-controlled data reaches vulnerable code.",
        tags={"security", "taint-analysis"},
    )
    def taint_flow_investigation(
        codebase_hash: str,
        source_location: Optional[str] = None,
        sink_location: Optional[str] = None,
        language: Optional[str] = None,
    ) -> str:
        """Trace tainted data flows between sources and sinks."""

        if source_location and sink_location:
            return f"""You are investigating a specific taint flow in codebase `{codebase_hash}`.

**Source**: `{source_location}` (where untrusted data enters)
**Sink**: `{sink_location}` (where dangerous operation occurs)

{CONFIDENCE_POLICY}

Follow this workflow:

## Step 1: Examine Source Context
Call `get_code_snippet(codebase_hash="{codebase_hash}", filename="{source_location.split(':')[0]}", start_line={max(1, int(source_location.split(':')[1]) - 10)}, end_line={int(source_location.split(':')[1]) + 10})` to see the code around the source.

## Step 2: Examine Sink Context
Call `get_code_snippet(codebase_hash="{codebase_hash}", filename="{sink_location.split(':')[0]}", start_line={max(1, int(sink_location.split(':')[1]) - 10)}, end_line={int(sink_location.split(':')[1]) + 10})` to see the code around the sink.

## Step 3: Check for Taint Flow
Call `find_taint_flows(codebase_hash="{codebase_hash}", source_location="{source_location}", sink_location="{sink_location}")` to confirm whether a data flow path exists.

## Step 4: Trace the Path
Call `get_program_slice(codebase_hash="{codebase_hash}", location="{sink_location}", direction="backward")` to understand all data dependencies reaching the sink.
Call `get_variable_flow(codebase_hash="{codebase_hash}", ...)` to trace specific variables along the path.

## Step 5: Analyze Control Flow
Call `get_cfg(codebase_hash="{codebase_hash}", ...)` for the function containing the sink to understand branching and conditions that must be met.

## Step 6: Assessment
Produce a taint flow report:
- **Source**: What untrusted data enters and how (user input, file, network, env var)
- **Sink**: What dangerous operation is reached (exec, query, write, memcpy, etc.)
- **Path**: Complete data flow path with intermediate transformations
- **Sanitization**: Is the input validated, sanitized, or escaped anywhere along the path?
- **Exploitability**: Can an attacker control the data sufficiently to exploit this?
- **Severity**: Critical / High / Medium / Low
- **CWE**: Applicable CWE identifier
- **Remediation**: Specific fix recommendation with code example"""
        else:
            lang_param = f', language="{language}"' if language else ''
            return f"""You are investigating taint flows in codebase `{codebase_hash}`.

No specific source/sink locations were provided, so you will discover and investigate flows automatically.

{CONFIDENCE_POLICY}

## Step 1: Discover All Taint Flows
Call `find_taint_flows(codebase_hash="{codebase_hash}", mode="auto"{lang_param})` to automatically discover all data flow paths from untrusted sources to dangerous sinks.

## Step 2: Prioritize Findings
Review the discovered flows and prioritize by:
1. Command/code injection flows (source -> exec/eval/system) — Critical
2. SQL injection flows (source -> query/execute) — Critical
3. Path traversal flows (source -> file operations) — High
4. XSS flows (source -> response/render/innerHTML) — High
5. Deserialization flows (source -> deserialize/unpickle) — High
6. Other flows — Medium

## Step 3: Deep Dive (Top 3 Most Critical Flows)
For each of the top 3 flows:
1. Call `get_code_snippet(codebase_hash="{codebase_hash}", ...)` to see source and sink code in context
2. Call `get_program_slice(codebase_hash="{codebase_hash}", ...)` with direction="backward" from the sink
3. Call `get_variable_flow(codebase_hash="{codebase_hash}", ...)` to trace the specific tainted variable
4. Call `get_cfg(codebase_hash="{codebase_hash}", ...)` to understand conditions and branches

## Step 4: Report
For each investigated flow, produce:
- **Source -> Sink**: One-line summary
- **Data Flow Path**: Complete trace through functions
- **Sanitization Status**: Whether input is validated/escaped
- **Exploitability**: Assessment of attacker control
- **Severity**: Critical / High / Medium / Low
- **CWE ID**: Applicable weakness
- **Remediation**: Specific fix"""

    @mcp.prompt(
        name="attack_surface_map",
        description="Map the complete attack surface — all entry points, trust boundaries, dangerous operations, and data flow paths.",
        tags={"security", "attack-surface"},
    )
    def attack_surface_map(
        codebase_hash: str,
        language: Optional[str] = None,
    ) -> list[Message]:
        """Map the full attack surface of a codebase."""

        lang_param = f', language="{language}"' if language else ''

        analysis_text = f"""You are mapping the complete attack surface of codebase `{codebase_hash}`.

{CONFIDENCE_POLICY}

## Step 1: Codebase Overview
Call `get_codebase_summary(codebase_hash="{codebase_hash}")` to understand the scale and language.

## Step 2: Enumerate Entry Points
Call `find_taint_sources(codebase_hash="{codebase_hash}"{lang_param})` to discover ALL external input points.
Categorize each source by type:
- **Network Input**: socket recv, HTTP request params/headers/body, WebSocket
- **File Input**: file reads, config parsing, deserialization
- **Environment**: environment variables, command-line arguments
- **User Input**: stdin, console input, GUI input
- **IPC**: shared memory, pipes, message queues

## Step 3: Enumerate Dangerous Operations
Call `find_taint_sinks(codebase_hash="{codebase_hash}"{lang_param})` to discover ALL dangerous operations.
Categorize each sink by impact:
- **Command Execution**: system, exec, popen, Process.Start (Critical)
- **Code Execution**: eval, Function constructor, deserialization (Critical)
- **Database**: SQL queries, NoSQL operations (High)
- **File System**: file write, delete, chmod, path operations (High)
- **Memory**: memcpy, strcpy, buffer writes (High - C/C++ only)
- **Network Output**: HTTP response, redirect, header injection (Medium)
- **Logging**: log functions with unsanitized input (Low)

## Step 4: Discover Confirmed Flow Paths
Call `find_taint_flows(codebase_hash="{codebase_hash}", mode="auto"{lang_param})` to find all confirmed paths where untrusted data reaches dangerous operations.

## Step 5: Map Call Reachability
For each major entry point function (functions containing taint sources), call `get_call_graph(codebase_hash="{codebase_hash}", method_name="<entry_function>", direction="outgoing", depth=3)` to map what code is reachable from each entry point.

## Step 6: Historical Context
Call `discover_fixed_vulnerabilities(codebase_hash="{codebase_hash}")` to find any previously fixed vulnerabilities in git history.

## Step 7: Attack Surface Report
Produce a structured report:

### Entry Point Inventory
Table: entry point, type (network/file/env/user), file:line, function name

### Dangerous Operation Inventory
Table: sink, impact category, severity, file:line, function name

### Confirmed Data Flow Paths
Table: source -> sink, vulnerability type, severity, CWE

### Trust Boundary Diagram
Text description of where trusted/untrusted boundaries exist in the codebase

### Risk-Ranked Priority List
Top 10 highest-risk areas ranked by: (1) number of reachable sinks, (2) severity of sinks, (3) lack of sanitization"""

        return [
            Message(analysis_text),
            Message(
                "I'll systematically map the attack surface. Starting with the codebase overview "
                "to understand what we're working with.",
                role="assistant",
            ),
        ]

    @mcp.prompt(
        name="investigate_code",
        description="Security-focused investigation of a specific function or file area — analyzes attack surface, data flow, and potential vulnerabilities.",
        tags={"security", "investigation"},
    )
    def investigate_code(
        codebase_hash: str,
        function_name: Optional[str] = None,
        filename: Optional[str] = None,
        line_number: Optional[int] = None,
    ) -> list[Message]:
        """Deep security investigation of a specific function or file area."""

        if function_name:
            file_param = f', filename="{filename}"' if filename else ''
            analysis_text = f"""You are performing a security-focused investigation of function `{function_name}` in codebase `{codebase_hash}`.

{CONFIDENCE_POLICY}

## Step 1: View Source Code
Call `get_file_content(codebase_hash="{codebase_hash}", method_name="{function_name}"{file_param})` to retrieve the full function source.

## Step 2: Understand Signature
Call `list_parameters(codebase_hash="{codebase_hash}", method_name="{function_name}")` to understand all parameters and their types.

## Step 3: Map Call Relationships
Call `get_call_graph(codebase_hash="{codebase_hash}", method_name="{function_name}", direction="incoming", depth=2)` to see who calls this function (attack entry points).
Call `get_call_graph(codebase_hash="{codebase_hash}", method_name="{function_name}", direction="outgoing", depth=3)` to see what dangerous operations this function can reach.

## Step 4: Analyze Control Flow
Call `get_cfg(codebase_hash="{codebase_hash}", method_name="{function_name}")` to understand branching, loops, and error handling paths.

## Step 5: Check for Taint
Call `find_taint_sources(codebase_hash="{codebase_hash}")` and check if any sources exist within this function or its callers.
Call `find_taint_sinks(codebase_hash="{codebase_hash}")` and check if any sinks exist within this function or its callees.
If both sources and sinks are found in the call chain, call `find_taint_flows(codebase_hash="{codebase_hash}", mode="auto")` and filter for flows involving this function.

## Step 6: Trace Parameter Data Flow
For each parameter, call `get_variable_flow(codebase_hash="{codebase_hash}", ...)` to understand where parameter values come from (backward) and where they flow to (forward).

## Step 7: Security Assessment
Produce a report:
- **Function Purpose**: What does this function do?
- **Callers**: Who invokes it? Can attackers reach it?
- **Parameters**: Are any parameters attacker-controllable?
- **Dangerous Operations**: Does it call any dangerous functions?
- **Data Flow**: How does data flow from parameters to sinks?
- **Vulnerabilities Found**: Specific issues with CWE IDs
- **Risk Level**: Critical / High / Medium / Low
- **Remediation**: Specific recommendations"""

        elif filename:
            line_context = ""
            snippet_call = ""
            if line_number:
                line_context = f" around line {line_number}"
                start = max(1, line_number - 25)
                end = line_number + 25
                snippet_call = f"""
Call `get_code_snippet(codebase_hash="{codebase_hash}", filename="{filename}", start_line={start}, end_line={end})` to see the code around line {line_number}."""
            else:
                snippet_call = f"""
Call `list_methods(codebase_hash="{codebase_hash}", file_pattern="{filename}")` to enumerate all functions in this file."""

            analysis_text = f"""You are performing a security investigation of file `{filename}`{line_context} in codebase `{codebase_hash}`.

{CONFIDENCE_POLICY}

## Step 1: Examine Code
{snippet_call}

## Step 2: Identify Functions
Call `list_methods(codebase_hash="{codebase_hash}", file_pattern="{filename}")` to see all methods defined in this file.

## Step 3: Find Input Points
Call `find_taint_sources(codebase_hash="{codebase_hash}")` and filter results for sources in `{filename}`.

## Step 4: Find Dangerous Operations
Call `find_taint_sinks(codebase_hash="{codebase_hash}")` and filter results for sinks in `{filename}`.

## Step 5: Check Data Flows
Call `find_taint_flows(codebase_hash="{codebase_hash}", mode="auto")` and filter for flows involving `{filename}`.

## Step 6: Memory Safety (if C/C++)
If the codebase is C/C++:
- Call `find_use_after_free(codebase_hash="{codebase_hash}", filename="{filename}")`
- Call `find_double_free(codebase_hash="{codebase_hash}", filename="{filename}")`

## Step 7: Trace Vulnerabilities
For each vulnerability found{f" near line {line_number}" if line_number else ""}:
- Call `get_program_slice(codebase_hash="{codebase_hash}", ...)` with direction="backward" to trace data origins
- Call `get_call_graph(codebase_hash="{codebase_hash}", method_name="<function>", direction="incoming")` to understand who can trigger the vulnerable code

## Step 8: Assessment
Produce an investigation report:
- **Risk Level**: Critical / High / Medium / Low
- **Vulnerabilities Found**: Each with CWE ID, file:line, description
- **Attack Vectors**: How an attacker could trigger each vulnerability
- **Blast Radius**: What functions/data are affected
- **Remediation**: Specific steps to fix each issue"""

        else:
            analysis_text = f"""You are performing a security investigation on codebase `{codebase_hash}`.

No specific function or file was provided. Please ask the user to specify either:
- A `function_name` to investigate a specific function
- A `filename` (and optionally `line_number`) to investigate a specific file area

Alternatively, consider using one of these more targeted prompts:
- `security_audit` for a comprehensive codebase-wide audit
- `attack_surface_map` to map all entry points and dangerous operations
- `taint_flow_investigation` to trace specific data flows"""

        return [
            Message(analysis_text),
            Message(
                "I'll investigate this code for security issues. Let me start by examining the code.",
                role="assistant",
            ),
        ]

    @mcp.prompt(
        name="code_review",
        description="Security-focused code review — analyzes code structure, identifies dangerous patterns, checks data handling, and flags vulnerabilities.",
        tags={"security", "review"},
    )
    def code_review(
        codebase_hash: str,
        filename: Optional[str] = None,
        function_name: Optional[str] = None,
    ) -> list[Message]:
        """Security-focused code review of a codebase, file, or function."""

        if function_name:
            file_param = f', filename="{filename}"' if filename else ''
            scope = f"function `{function_name}`"
            scope_detail = f"Reviewing function `{function_name}`{f' in `{filename}`' if filename else ''}."
        elif filename:
            scope = f"file `{filename}`"
            scope_detail = f"Reviewing file `{filename}`."
        else:
            scope = "the entire codebase"
            scope_detail = "Reviewing the full codebase."

        # Build the step-by-step workflow depending on scope
        if function_name:
            file_param = f', filename="{filename}"' if filename else ''
            gather_steps = f"""## Step 1: Retrieve Code
Call `get_file_content(codebase_hash="{codebase_hash}", method_name="{function_name}"{file_param})` to get the full function source.
Call `list_parameters(codebase_hash="{codebase_hash}", method_name="{function_name}")` to understand the function signature.

## Step 2: Understand Context
Call `get_call_graph(codebase_hash="{codebase_hash}", method_name="{function_name}", direction="incoming", depth=2)` to see callers.
Call `get_call_graph(codebase_hash="{codebase_hash}", method_name="{function_name}", direction="outgoing", depth=2)` to see callees.
Call `get_cfg(codebase_hash="{codebase_hash}", method_name="{function_name}")` to understand control flow."""
        elif filename:
            gather_steps = f"""## Step 1: Retrieve Code
Call `list_methods(codebase_hash="{codebase_hash}", file_pattern="{filename}")` to enumerate all functions in the file.
For each significant function, call `get_file_content(codebase_hash="{codebase_hash}", method_name="<name>", filename="{filename}")` to get its source.

## Step 2: Understand Context
Call `list_calls(codebase_hash="{codebase_hash}", caller_pattern=".*", file_pattern="{filename}")` to see all calls made from this file.
For key functions, call `get_cfg(codebase_hash="{codebase_hash}", method_name="<name>")` to understand control flow."""
        else:
            gather_steps = f"""## Step 1: Codebase Overview
Call `get_codebase_summary(codebase_hash="{codebase_hash}")` to understand size and language.
Call `list_source_files(codebase_hash="{codebase_hash}")` to see the project structure.
Call `list_methods(codebase_hash="{codebase_hash}")` to enumerate all functions.

## Step 2: Identify Critical Code
Focus the review on functions that:
- Handle external input (check `find_taint_sources(codebase_hash="{codebase_hash}")`)
- Perform dangerous operations (check `find_taint_sinks(codebase_hash="{codebase_hash}")`)
- Are heavily called (use `list_calls(codebase_hash="{codebase_hash}")` to find high fan-in functions)
For each critical function, call `get_file_content(codebase_hash="{codebase_hash}", method_name="<name>")` and `get_cfg(codebase_hash="{codebase_hash}", method_name="<name>")` to review."""

        analysis_text = f"""You are performing a security-focused code review on {scope} in codebase `{codebase_hash}`.
{scope_detail}

{CONFIDENCE_POLICY}

{gather_steps}

## Step 3: Security Analysis
Check the code for these security concerns (only report issues you are at least 80% confident about):

### Input Validation & Sanitization
- Are external inputs validated before use? Check types, ranges, formats, and allowed values.
- Are inputs sanitized or escaped before passing to sinks (SQL, shell, HTML, file paths)?
- Call `find_taint_sources(codebase_hash="{codebase_hash}")` and `find_taint_sinks(codebase_hash="{codebase_hash}")` to identify input/output points in scope.

### Injection Risks
- Call `find_taint_flows(codebase_hash="{codebase_hash}", mode="auto")` and filter for flows in scope.
- For each confirmed flow, call `get_program_slice(codebase_hash="{codebase_hash}", ...)` to verify there is no sanitization along the path.

### Error Handling
- Are errors caught and handled properly, or do they leak sensitive information (stack traces, paths, credentials)?
- Are there bare except/catch blocks that silently swallow errors?
- Do error paths leave resources in an inconsistent state?

### Resource Management
- Are file handles, connections, and locks properly closed/released?
- Are there potential resource leaks in error paths?

### Data Exposure
- Is sensitive data (passwords, tokens, keys, PII) logged, cached, or included in error messages?
- Are secrets hardcoded in the source code?

### Authentication & Authorization (if applicable)
- Are authentication checks present where expected?
- Can authorization be bypassed through unexpected code paths?

## Step 4: Code Review Report
Produce a structured review:

### Summary
One paragraph: overall code quality assessment and key risk areas.

### Findings
For each issue found (only 80%+ confidence):
| Severity | Category | Location | Description |
|----------|----------|----------|-------------|
| Critical/High/Medium/Low | Input Validation / Injection / Error Handling / etc. | file:line | What the issue is |

### Needs Manual Review (50-80% confidence)
Issues that warrant human attention but could not be confirmed automatically.

### Positive Observations
Note well-implemented security patterns (proper input validation, parameterized queries, safe error handling) to acknowledge good practices."""

        return [
            Message(analysis_text),
            Message(
                "I'll perform a security-focused code review. Let me start by retrieving "
                "and understanding the code.",
                role="assistant",
            ),
        ]
