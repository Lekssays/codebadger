"""
Export Tools for CodeBadger - SARIF Export Functionality

Provides tools to parse vulnerability findings and export them
in SARIF format for GitHub Code Scanning, VS Code, etc.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Annotated
from pydantic import Field

from ..exceptions import ValidationError
from ..models import Finding
from ..utils.validators import validate_codebase_hash

logger = logging.getLogger(__name__)

# CWE ID mappings for vulnerability types
CWE_MAP = {
    "command_injection": 78,
    "sql_injection": 89,
    "path_traversal": 22,
    "xss": 79,
    "code_injection": 94,
    "use_after_free": 416,
    "double_free": 415,
    "buffer_overflow": 120,
    "null_pointer_deref": 476,
}

# Severity ordering for filtering
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}


class FindingsParser:
    """Parser for extracting findings from tool output text"""

    @staticmethod
    def parse_taint_flow_text(text: str, codebase_hash: str) -> List[Dict[str, Any]]:
        """Parse taint flow analysis output.

        Extracts vulnerability findings from the text output of find_taint_flows tool.

        Args:
            text: Raw text output from find_taint_flows
            codebase_hash: The codebase hash

        Returns:
            List of finding dictionaries
        """
        findings = []

        # Split by flow markers
        flow_pattern = r"--- Flow (\d+) ---"
        flow_blocks = re.split(flow_pattern, text)

        # Process each flow block
        for i in range(1, len(flow_blocks), 2):
            flow_text = flow_blocks[i + 1] if i + 1 < len(flow_blocks) else ""

            try:
                # Extract source information
                source_match = re.search(r"Source:.*?\n.*?Location: ([^:]+):(\d+)", flow_text)
                if not source_match:
                    continue

                source_file = source_match.group(1)
                source_line = int(source_match.group(2))

                # Extract sink information
                sink_match = re.search(r"Sink:.*?\n.*?Location: ([^:]+):(\d+)", flow_text)
                if not sink_match:
                    continue

                sink_file = sink_match.group(1)
                sink_line = int(sink_match.group(2))

                # Determine vulnerability type and severity based on sink pattern
                severity, vuln_type = FindingsParser._determine_severity_from_flow(flow_text, sink_file)

                # Extract intermediate steps for flow_data
                steps_match = re.findall(r"\[L\d+\]\s*(.+?)(?:\n|$)", flow_text)
                flow_data = {
                    "source": {"file": source_file, "line": source_line},
                    "sink": {"file": sink_file, "line": sink_line},
                    "path_length": len(steps_match) + 2 if steps_match else 2,
                    "steps": steps_match[:5],  # Include first 5 steps
                }

                # Create finding
                finding = {
                    "codebase_hash": codebase_hash,
                    "finding_type": "taint_flow",
                    "severity": severity,
                    "confidence": "high",  # Confirmed flows are high confidence
                    "filename": sink_file,
                    "line_number": sink_line,
                    "message": f"Confirmed taint flow from {source_file}:{source_line} to {sink_file}:{sink_line} ({vuln_type})",
                    "description": f"Untrusted data flows from {source_file} to a dangerous sink at {sink_file}:{sink_line}",
                    "cwe_id": CWE_MAP.get(vuln_type, None),
                    "rule_id": vuln_type,
                    "flow_data": flow_data,
                }
                findings.append(finding)

            except (ValueError, AttributeError) as e:
                logger.debug(f"Failed to parse flow block: {e}")
                continue

        return findings

    @staticmethod
    def parse_uaf_text(text: str, codebase_hash: str) -> List[Dict[str, Any]]:
        """Parse use-after-free analysis output.

        Args:
            text: Raw text output from find_use_after_free
            codebase_hash: The codebase hash

        Returns:
            List of finding dictionaries
        """
        findings = []

        # Split by issue markers
        issue_pattern = r"--- Issue (\d+) ---"
        issue_blocks = re.split(issue_pattern, text)

        for i in range(1, len(issue_blocks), 2):
            issue_text = issue_blocks[i + 1] if i + 1 < len(issue_blocks) else ""

            try:
                # Extract free site location
                free_match = re.search(r"Free Site:.*?\n.*?Location: ([^:]+):(\d+)", issue_text)
                if not free_match:
                    continue

                free_file = free_match.group(1)
                free_line = int(free_match.group(2))

                # Extract use location (first one)
                use_match = re.search(r"Post-Free Usage.*?\n\s*\[([^:]+):(\d+)\]", issue_text)
                if not use_match:
                    use_file = free_file
                    use_line = free_line + 1
                else:
                    use_file = use_match.group(1)
                    use_line = int(use_match.group(2))

                # Create finding
                finding = {
                    "codebase_hash": codebase_hash,
                    "finding_type": "use_after_free",
                    "severity": "high",
                    "confidence": "high",  # UAF findings are high confidence
                    "filename": use_file,
                    "line_number": use_line,
                    "message": f"Use-after-free: pointer freed at {free_file}:{free_line}, used at {use_file}:{use_line}",
                    "description": f"Memory is accessed after being freed. Free location: {free_file}:{free_line}",
                    "cwe_id": CWE_MAP["use_after_free"],
                    "rule_id": "use_after_free",
                    "flow_data": {
                        "free_location": {"file": free_file, "line": free_line},
                        "use_location": {"file": use_file, "line": use_line},
                    },
                }
                findings.append(finding)

            except (ValueError, AttributeError) as e:
                logger.debug(f"Failed to parse UAF issue: {e}")
                continue

        return findings

    @staticmethod
    def parse_double_free_text(text: str, codebase_hash: str) -> List[Dict[str, Any]]:
        """Parse double-free analysis output.

        Args:
            text: Raw text output from find_double_free
            codebase_hash: The codebase hash

        Returns:
            List of finding dictionaries
        """
        findings = []

        # Split by issue markers
        issue_pattern = r"--- Issue (\d+) ---"
        issue_blocks = re.split(issue_pattern, text)

        for i in range(1, len(issue_blocks), 2):
            issue_text = issue_blocks[i + 1] if i + 1 < len(issue_blocks) else ""

            try:
                # Extract first free location
                first_free_match = re.search(r"First Free:\s*\[([^:]+):(\d+)\]", issue_text)
                if not first_free_match:
                    continue

                first_file = first_free_match.group(1)
                first_line = int(first_free_match.group(2))

                # Extract second free location
                second_free_match = re.search(r"Second Free:\s*\[([^:]+):(\d+)\]", issue_text)
                if not second_free_match:
                    second_file = first_file
                    second_line = first_line + 1
                else:
                    second_file = second_free_match.group(1)
                    second_line = int(second_free_match.group(2))

                # Create finding
                finding = {
                    "codebase_hash": codebase_hash,
                    "finding_type": "double_free",
                    "severity": "high",
                    "confidence": "high",  # Double-free findings are high confidence
                    "filename": second_file,
                    "line_number": second_line,
                    "message": f"Double-free: freed at {first_file}:{first_line}, freed again at {second_file}:{second_line}",
                    "description": f"Same pointer is freed twice. First free: {first_file}:{first_line}",
                    "cwe_id": CWE_MAP["double_free"],
                    "rule_id": "double_free",
                    "flow_data": {
                        "first_free": {"file": first_file, "line": first_line},
                        "second_free": {"file": second_file, "line": second_line},
                    },
                }
                findings.append(finding)

            except (ValueError, AttributeError) as e:
                logger.debug(f"Failed to parse double-free issue: {e}")
                continue

        return findings

    @staticmethod
    def parse_null_pointer_deref_text(text: str, codebase_hash: str) -> List[Dict[str, Any]]:
        """Parse null pointer dereference analysis output.

        Args:
            text: Raw text output from find_null_pointer_deref
            codebase_hash: The codebase hash

        Returns:
            List of finding dictionaries
        """
        findings = []

        # Split by issue markers
        issue_pattern = r"--- Issue (\d+) ---"
        issue_blocks = re.split(issue_pattern, text)

        for i in range(1, len(issue_blocks), 2):
            issue_text = issue_blocks[i + 1] if i + 1 < len(issue_blocks) else ""

            try:
                # Extract allocation site location
                alloc_match = re.search(r"Allocation Site:.*?\n.*?Location: ([^:]+):(\d+)", issue_text)
                if not alloc_match:
                    continue

                alloc_file = alloc_match.group(1)
                alloc_line = int(alloc_match.group(2))

                # Extract first dereference location
                deref_match = re.search(r"Unchecked Dereference.*?\n\s*\[([^:]+):(\d+)\]", issue_text)
                if not deref_match:
                    deref_file = alloc_file
                    deref_line = alloc_line + 1
                else:
                    deref_file = deref_match.group(1)
                    deref_line = int(deref_match.group(2))

                # Create finding
                finding = {
                    "codebase_hash": codebase_hash,
                    "finding_type": "null_pointer_deref",
                    "severity": "high",
                    "confidence": "high",
                    "filename": deref_file,
                    "line_number": deref_line,
                    "message": f"Null pointer dereference: allocated at {alloc_file}:{alloc_line}, dereferenced unchecked at {deref_file}:{deref_line}",
                    "description": f"Pointer from allocation at {alloc_file}:{alloc_line} is dereferenced without NULL check",
                    "cwe_id": CWE_MAP["null_pointer_deref"],
                    "rule_id": "null_pointer_deref",
                    "flow_data": {
                        "allocation_location": {"file": alloc_file, "line": alloc_line},
                        "dereference_location": {"file": deref_file, "line": deref_line},
                    },
                }
                findings.append(finding)

            except (ValueError, AttributeError) as e:
                logger.debug(f"Failed to parse null pointer deref issue: {e}")
                continue

        return findings

    @staticmethod
    def _determine_severity_from_flow(flow_text: str, sink_file: str) -> tuple[str, str]:
        """Determine vulnerability type and severity from flow characteristics.

        Args:
            flow_text: The flow description text
            sink_file: The file containing the sink

        Returns:
            Tuple of (severity, vulnerability_type)
        """
        # Check for specific sink patterns
        if re.search(r"\b(system|popen|exec|execv|fork)\s*\(", flow_text):
            return "critical", "command_injection"
        if re.search(r"\b(eval|exec|Function)\s*\(", flow_text):
            return "critical", "code_injection"
        if re.search(r"\b(executeQuery|executeUpdate|query|execute)\s*\(", flow_text):
            return "critical", "sql_injection"
        if re.search(r"\.load\(|\.unserialize\(|pickle|yaml", flow_text, re.IGNORECASE):
            return "high", "deserialization"
        if re.search(r"\b(open|read|write|mkdir|rmdir)\s*\(", flow_text):
            return "high", "path_traversal"
        if re.search(r"\b(innerHTML|innerText|textContent|write|render)\s*\(", flow_text):
            return "medium", "xss"
        if re.search(r"\b(memcpy|strcpy|strcat|sprintf)\s*\(", flow_text):
            return "high", "buffer_overflow"

        # Default to medium severity
        return "medium", "injection"


class SARIFBuilder:
    """Builder for creating SARIF documents"""

    @staticmethod
    def build_sarif(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build a SARIF v2.1.0 document from findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            SARIF document dictionary
        """
        # Build rules from unique CWE IDs
        rules = SARIFBuilder._build_rules(findings)

        # Build results from findings
        results = []
        for finding in findings:
            result = {
                "ruleId": finding.get("rule_id", "unknown"),
                "message": {
                    "text": finding.get("message", "Security issue detected"),
                    "markdown": f"**{finding.get('finding_type', 'Unknown')}** at {finding.get('filename')}:{finding.get('line_number')}\n\n{finding.get('description', '')}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "address": {
                                "relativeUrl": finding.get("filename", ""),
                                "offsetFromStartOfFile": 0,
                            },
                            "region": {
                                "startLine": finding.get("line_number", 1),
                                "startColumn": 1,
                                "kind": "line",
                            },
                        },
                        "logicalLocations": [
                            {
                                "name": finding.get("filename", "unknown"),
                                "kind": "module",
                            }
                        ],
                    }
                ],
                "level": SARIFBuilder._map_severity_to_level(finding.get("severity", "medium")),
                "properties": {
                    "finding_type": finding.get("finding_type", "unknown"),
                    "confidence": finding.get("confidence", "medium"),
                    "cwe_id": finding.get("cwe_id"),
                },
            }

            # Add code flow if available
            if finding.get("flow_data"):
                result["codeFlows"] = [
                    {
                        "message": {"text": "Data flow path"},
                        "threadFlows": [
                            {
                                "locations": SARIFBuilder._build_flow_locations(finding.get("flow_data", {}))
                            }
                        ],
                    }
                ]

            results.append(result)

        # Build SARIF document
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeBadger",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/codebadger/codebadger",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "columnKind": "utf16CodeUnits",
                }
            ],
        }

        return sarif

    @staticmethod
    def _build_rules(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build SARIF rules from findings."""
        rules_map = {}

        for finding in findings:
            rule_id = finding.get("rule_id", "unknown")
            if rule_id not in rules_map:
                cwe_id = finding.get("cwe_id")
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": finding.get("finding_type", "Unknown").replace("_", " ").title(),
                    "shortDescription": {
                        "text": finding.get("message", "Security issue detected"),
                    },
                    "fullDescription": {
                        "text": finding.get("description", "A security vulnerability was detected."),
                        "markdown": f"**Type**: {finding.get('finding_type', 'Unknown')}\n**Confidence**: {finding.get('confidence', 'Unknown')}\n\n{finding.get('description', '')}",
                    },
                    "help": {
                        "text": SARIFBuilder._get_remediation_text(rule_id),
                        "markdown": f"## Remediation\n\n{SARIFBuilder._get_remediation_text(rule_id)}",
                    },
                    "properties": {
                        "security-severity": SARIFBuilder._map_severity_to_score(finding.get("severity", "medium")),
                    },
                }

                # Add CWE reference if available
                if cwe_id:
                    rules_map[rule_id]["relatedLocations"] = [
                        {
                            "id": f"cwe-{cwe_id}",
                            "message": {
                                "text": f"CWE-{cwe_id}",
                            },
                            "physicalLocation": {
                                "address": {
                                    "relativeUrl": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
                                },
                            },
                        }
                    ]

        return list(rules_map.values())

    @staticmethod
    def _build_flow_locations(flow_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build SARIF flow locations from flow data."""
        locations = []

        # Add source location if available
        if flow_data.get("source"):
            source = flow_data["source"]
            locations.append(
                {
                    "location": {
                        "message": {"text": "Source"},
                        "physicalLocation": {
                            "address": {
                                "relativeUrl": source.get("file", ""),
                            },
                            "region": {
                                "startLine": source.get("line", 1),
                                "startColumn": 1,
                            },
                        },
                    },
                    "kinds": ["acquire"],
                }
            )

        # Add intermediate steps if available
        for step in flow_data.get("steps", []):
            locations.append(
                {
                    "location": {
                        "message": {"text": step},
                        "physicalLocation": {
                            "address": {
                                "relativeUrl": "",
                            },
                        },
                    },
                    "kinds": ["call"],
                }
            )

        # Add sink location if available
        if flow_data.get("sink"):
            sink = flow_data["sink"]
            locations.append(
                {
                    "location": {
                        "message": {"text": "Sink"},
                        "physicalLocation": {
                            "address": {
                                "relativeUrl": sink.get("file", ""),
                            },
                            "region": {
                                "startLine": sink.get("line", 1),
                                "startColumn": 1,
                            },
                        },
                    },
                    "kinds": ["release"],
                }
            )

        return locations

    @staticmethod
    def _map_severity_to_level(severity: str) -> str:
        """Map CodeBadger severity to SARIF level."""
        level_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
        }
        return level_map.get(severity, "warning")

    @staticmethod
    def _map_severity_to_score(severity: str) -> str:
        """Map severity to CVSS score string."""
        score_map = {
            "critical": "9.9",
            "high": "7.5",
            "medium": "5.0",
            "low": "2.5",
        }
        return score_map.get(severity, "5.0")

    @staticmethod
    def _get_remediation_text(rule_id: str) -> str:
        """Get remediation guidance for a rule."""
        remediation_map = {
            "command_injection": "Validate and sanitize all user inputs before passing to system commands. Use parameterized APIs when available.",
            "sql_injection": "Use prepared statements or parameterized queries. Never concatenate user input into SQL queries.",
            "xss": "Escape or sanitize all user input before rendering in HTML. Use context-appropriate encoding.",
            "path_traversal": "Validate file paths and ensure they stay within allowed directories. Use canonical paths.",
            "code_injection": "Avoid eval() and dynamic code execution. Use safer alternatives like AST parsing or libraries.",
            "use_after_free": "Ensure memory is not accessed after being freed. Use memory-safe patterns and tools.",
            "double_free": "Track object lifetimes carefully. Use smart pointers and RAII patterns to prevent double-free.",
            "buffer_overflow": "Use bounds-checking functions and safe string operations. Avoid strcpy, sprintf, etc.",
            "null_pointer_deref": "Always check return values of malloc/calloc/realloc/fopen for NULL before dereferencing. Use wrapper functions that abort on allocation failure, or handle the error path explicitly.",
        }
        return remediation_map.get(rule_id, "Review and fix the identified security issue.")


def register_export_tools(mcp, services: dict):
    """Register export tools with the FastMCP server"""

    @mcp.tool(
        description="""Parse and store vulnerability findings in database.

Parses raw output from CodeBadger analysis tools (find_taint_flows,
find_use_after_free, find_double_free, find_null_pointer_deref) and stores structured findings
in the database for later export or querying.

Args:
    codebase_hash: The codebase hash from generate_cpg.
    findings_json: JSON string containing raw tool outputs.
                   Format: {
                       "taint_flows": "<text from find_taint_flows>",
                       "use_after_free": "<text from find_use_after_free>",
                       "double_free": "<text from find_double_free>",
                       "null_pointer_deref": "<text from find_null_pointer_deref>"
                   }
    replace_existing: If true, delete existing findings for this codebase first.
                      Default: false (append mode)

Returns:
    {
        "success": true,
        "stored": 15,
        "skipped": 2,
        "errors": []
    }

Notes:
    - Parses text outputs into structured data
    - Assigns HIGH confidence to confirmed vulnerabilities
    - Maps findings to CWE IDs
    - Determines severity based on vulnerability type"""
    )
    def store_findings(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        findings_json: Annotated[
            str,
            Field(
                description="JSON string containing raw findings from analysis tools"
            ),
        ],
        replace_existing: Annotated[
            bool,
            Field(
                description="If true, replace existing findings; if false, append to existing"
            ),
        ] = False,
    ) -> Dict[str, Any]:
        """Parse findings from tool outputs and store in database."""
        try:
            validate_codebase_hash(codebase_hash)

            # Parse input JSON
            try:
                findings_data = json.loads(findings_json)
            except json.JSONDecodeError as e:
                return {"success": False, "error": f"Invalid JSON: {str(e)}"}

            db_manager = services.get("db_manager")
            if not db_manager:
                return {"success": False, "error": "Database manager not available"}

            # Delete existing findings if requested
            if replace_existing:
                db_manager.delete_findings_for_codebase(codebase_hash)

            # Parse findings from each tool output
            findings_to_store = []
            errors = []

            # Parse taint flows
            if findings_data.get("taint_flows"):
                try:
                    flows = FindingsParser.parse_taint_flow_text(
                        findings_data["taint_flows"], codebase_hash
                    )
                    findings_to_store.extend(flows)
                    logger.info(f"Parsed {len(flows)} taint flow findings")
                except Exception as e:
                    errors.append(f"Taint flow parsing error: {str(e)}")
                    logger.error(f"Error parsing taint flows: {e}")

            # Parse use-after-free
            if findings_data.get("use_after_free"):
                try:
                    uaf = FindingsParser.parse_uaf_text(
                        findings_data["use_after_free"], codebase_hash
                    )
                    findings_to_store.extend(uaf)
                    logger.info(f"Parsed {len(uaf)} use-after-free findings")
                except Exception as e:
                    errors.append(f"UAF parsing error: {str(e)}")
                    logger.error(f"Error parsing UAF: {e}")

            # Parse double-free
            if findings_data.get("double_free"):
                try:
                    df = FindingsParser.parse_double_free_text(
                        findings_data["double_free"], codebase_hash
                    )
                    findings_to_store.extend(df)
                    logger.info(f"Parsed {len(df)} double-free findings")
                except Exception as e:
                    errors.append(f"Double-free parsing error: {str(e)}")
                    logger.error(f"Error parsing double-free: {e}")

            # Parse null pointer dereferences
            if findings_data.get("null_pointer_deref"):
                try:
                    npd = FindingsParser.parse_null_pointer_deref_text(
                        findings_data["null_pointer_deref"], codebase_hash
                    )
                    findings_to_store.extend(npd)
                    logger.info(f"Parsed {len(npd)} null pointer dereference findings")
                except Exception as e:
                    errors.append(f"Null pointer deref parsing error: {str(e)}")
                    logger.error(f"Error parsing null pointer deref: {e}")

            # Save findings to database
            if findings_to_store:
                try:
                    stored_count = db_manager.save_findings_batch(findings_to_store)
                    logger.info(f"Stored {stored_count} findings for codebase {codebase_hash}")
                    return {
                        "success": True,
                        "stored": stored_count,
                        "skipped": 0,
                        "errors": errors,
                    }
                except Exception as e:
                    logger.error(f"Error saving findings: {e}")
                    return {
                        "success": False,
                        "error": f"Failed to save findings: {str(e)}",
                        "stored": 0,
                        "errors": errors,
                    }
            else:
                return {
                    "success": True,
                    "stored": 0,
                    "skipped": 0,
                    "errors": errors,
                }

        except ValidationError as e:
            logger.error(f"Validation error in store_findings: {e}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error in store_findings: {e}", exc_info=True)
            return {"success": False, "error": f"Internal error: {str(e)}"}

    @mcp.tool(
        description="""Export HIGH CONFIDENCE vulnerability findings in SARIF format.

Retrieves stored findings from database and exports them in SARIF
(Static Analysis Results Interchange Format) v2.1.0 for integration with
GitHub Code Scanning, VS Code SARIF Viewer, and other security tools.

Args:
    codebase_hash: The codebase hash from generate_cpg.
    min_severity: Minimum severity filter (critical, high, medium, low).
                  Default: "high"
    min_confidence: Minimum confidence filter (high, medium, low).
                    Default: "high"
    include_types: Optional JSON array of finding types to include.
                   Default: all types

Returns:
    {
        "success": true,
        "sarif": {...},
        "total_findings": 20,
        "exported_findings": 10
    }

Notes:
    - Only exports findings matching severity/confidence filters
    - Includes code flow paths for taint flows
    - Maps findings to CWE IDs
    - Compatible with GitHub Code Scanning upload"""
    )
    def export_sarif(
        codebase_hash: Annotated[str, Field(description="The codebase hash from generate_cpg")],
        min_severity: Annotated[
            str, Field(description="Minimum severity level (critical, high, medium, low)")
        ] = "high",
        min_confidence: Annotated[
            str,
            Field(description="Minimum confidence level (high, medium, low)"),
        ] = "high",
        include_types: Annotated[
            Optional[str],
            Field(
                description="Optional JSON array of finding types to include (e.g., '[\"taint_flow\", \"use_after_free\"]')"
            ),
        ] = None,
    ) -> Dict[str, Any]:
        """Export findings to SARIF format."""
        try:
            validate_codebase_hash(codebase_hash)

            db_manager = services.get("db_manager")
            if not db_manager:
                return {"success": False, "error": "Database manager not available"}

            # Parse include_types if provided
            types_filter = None
            if include_types:
                try:
                    types_filter = json.loads(include_types)
                    if not isinstance(types_filter, list):
                        types_filter = [types_filter]
                except json.JSONDecodeError:
                    return {"success": False, "error": "Invalid include_types JSON"}

            # Get all findings for codebase
            all_findings = db_manager.get_findings(codebase_hash)
            total_findings = len(all_findings)

            # Filter findings by severity and confidence
            filtered_findings = []
            for finding in all_findings:
                # Check severity filter
                if min_severity in SEVERITY_ORDER:
                    min_sev_val = SEVERITY_ORDER[min_severity]
                    finding_sev_val = SEVERITY_ORDER.get(finding.get("severity", "low"), 0)
                    if finding_sev_val < min_sev_val:
                        continue

                # Check confidence filter
                if min_confidence in CONFIDENCE_ORDER:
                    min_conf_val = CONFIDENCE_ORDER[min_confidence]
                    finding_conf_val = CONFIDENCE_ORDER.get(finding.get("confidence", "low"), 0)
                    if finding_conf_val < min_conf_val:
                        continue

                # Check type filter
                if types_filter and finding.get("finding_type") not in types_filter:
                    continue

                filtered_findings.append(finding)

            # Build SARIF document
            sarif = SARIFBuilder.build_sarif(filtered_findings)

            logger.info(
                f"Exported {len(filtered_findings)} findings out of {total_findings} for codebase {codebase_hash}"
            )

            return {
                "success": True,
                "sarif": sarif,
                "total_findings": total_findings,
                "exported_findings": len(filtered_findings),
            }

        except ValidationError as e:
            logger.error(f"Validation error in export_sarif: {e}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error in export_sarif: {e}", exc_info=True)
            return {"success": False, "error": f"Internal error: {str(e)}"}
