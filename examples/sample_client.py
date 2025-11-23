#!/usr/bin/env python3
"""
Sample Client for CodeBadger Server

This client demonstrates basic usage of the CodeBadger MCP server:
1. Generate a CPG for a local codebase
2. List methods in the codebase
3. Run a simple CPGQL query
"""

import asyncio
import logging
import sys
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from fastmcp import Client
except ImportError:
    logger.error("FastMCP not found. Install with: pip install fastmcp")
    sys.exit(1)


def extract_tool_result(result):
    """Extract dictionary data from CallToolResult"""
    if hasattr(result, 'content') and result.content:
        content_text = result.content[0].text
        try:
            import json
            parsed = json.loads(content_text)

            # Handle complex results that return Scala output with embedded JSON
            if isinstance(parsed, dict) and 'value' in parsed:
                value = parsed['value']
                if isinstance(value, str):
                    # Look for embedded JSON in the Scala output
                    import re
                    # Match the escaped JSON string between quotes
                    json_match = re.search(r'val res\d+: String = ("\{.*\}")', value)
                    if json_match:
                        try:
                            # Extract the escaped JSON string and unescape it
                            escaped_json = json_match.group(1)
                            # Remove the surrounding quotes and unescape
                            json_str = escaped_json[1:-1]  # Remove quotes
                            json_str = json_str.replace('\\"', '"')  # Unescape quotes
                            json_str = json_str.replace('\\\\', '\\')  # Unescape backslashes
                            return json.loads(json_str)
                        except json.JSONDecodeError:
                            pass
                    # If no embedded JSON found, return the original parsed result
                    return parsed
                else:
                    return parsed
            else:
                return parsed
        except json.JSONDecodeError:
            return {"error": content_text}
    return {}


async def main():
    """Main client function"""
    # Server URL - adjust if running on different host/port
    server_url = "http://localhost:4242/mcp"

    # Path to the codebase - use container path since server runs in Docker
    # Host path: playground/codebases/core -> Container path: /app/playground/codebases/core
    codebase_path = "/app/playground/codebases/core"

    logger.info("="*60)
    logger.info("CODEBADGER SAMPLE CLIENT")
    logger.info("="*60)
    logger.info(f"Server URL: {server_url}")
    logger.info(f"Codebase: {codebase_path}")

    try:
        async with Client(server_url) as client:
            logger.info("\n[1] Testing server connectivity...")
            await client.ping()
            logger.info("✓ Server is responding")

            # ===== GENERATE CPG =====
            logger.info("\n[2] Generating CPG for codebase...")
            cpg_result = await client.call_tool("generate_cpg", {
                "source_type": "local",
                "source_path": codebase_path,
                "language": "c"
            })

            cpg_dict = extract_tool_result(cpg_result)
            logger.info(f"CPG generation result: {cpg_dict}")

            if "codebase_hash" not in cpg_dict:
                logger.error("❌ No codebase_hash returned")
                return

            codebase_hash = cpg_dict["codebase_hash"]
            logger.info(f"✓ CPG generation initiated. Hash: {codebase_hash}")

            # ===== WAIT FOR CPG TO BE READY =====
            logger.info("\n[3] Waiting for CPG to be ready...")
            cpg_ready = False
            max_attempts = 30

            for attempt in range(max_attempts):
                await asyncio.sleep(2)  # Wait 2 seconds between checks

                status_result = await client.call_tool("get_cpg_status", {
                    "codebase_hash": codebase_hash
                })

                status_dict = extract_tool_result(status_result)
                status = status_dict.get("status")
                exists = status_dict.get("exists", False)

                logger.info(f"  Attempt {attempt + 1}/{max_attempts}: status={status}, exists={exists}")

                if status in ["ready", "cached"] and exists:
                    cpg_ready = True
                    logger.info("✓ CPG is ready!")
                    break

            if not cpg_ready:
                logger.error("❌ CPG not ready after waiting")
                return

            # ===== LIST METHODS =====
            logger.info("\n[4] Listing methods in the codebase...")
            methods_result = await client.call_tool("list_methods", {
                "codebase_hash": codebase_hash,
                "limit": 20
            })

            methods_dict = extract_tool_result(methods_result)

            if methods_dict.get("success"):
                methods = methods_dict.get("methods", [])
                total = methods_dict.get("total", 0)
                logger.info(f"✓ Found {total} methods total, showing up to 20:")

                for method in methods[:10]:  # Show first 10
                    logger.info(f"  - {method.get('name', 'unknown')} in {method.get('filename', 'unknown')}")

                if len(methods) > 10:
                    logger.info(f"  ... and {len(methods) - 10} more methods")
            else:
                logger.error(f"❌ Failed to list methods: {methods_dict}")

                        # ===== RUN SIMPLE QUERY - GET CODEBASE SUMMARY =====
            logger.info("\n[5] Getting codebase summary...")

            summary_result = await client.call_tool("get_codebase_summary", {
                "codebase_hash": codebase_hash
            })

            summary_dict = extract_tool_result(summary_result)

            if summary_dict.get("success"):
                summary = summary_dict.get("summary", {})
                logger.info("✓ Codebase summary retrieved:")
                logger.info(f"  Language: {summary.get('language')}")
                logger.info(f"  Files: {summary.get('total_files')}")
                logger.info(f"  Methods: {summary.get('total_methods')}")
                logger.info(f"  Calls: {summary.get('total_calls')}")
            else:
                logger.error(f"❌ Failed to get summary: {summary_dict}")

            # ===== RUN ANOTHER QUERY - LIST CALLS =====
            logger.info("\n[6] Listing function calls...")

            calls_result = await client.call_tool("list_calls", {
                "codebase_hash": codebase_hash,
                "limit": 10
            })

            calls_dict = extract_tool_result(calls_result)

            if calls_dict.get("success"):
                calls = calls_dict.get("calls", [])
                total = calls_dict.get("total", 0)
                logger.info(f"✓ Found {total} calls total, showing up to 10:")

                for call in calls[:5]:  # Show first 5
                    logger.info(f"  - {call.get('caller', 'unknown')} -> {call.get('callee', 'unknown')}")

                if len(calls) > 5:
                    logger.info(f"  ... and {len(calls) - 5} more calls")
            else:
                logger.error(f"❌ Failed to list calls: {calls_dict}")

            logger.info("\n" + "="*60)
            logger.info("SAMPLE CLIENT COMPLETED SUCCESSFULLY!")
            logger.info("="*60)

    except Exception as e:
        logger.error(f"❌ Client error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\n🛑 Client interrupted by user")
        sys.exit(1)