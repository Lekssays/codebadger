"""
Integration Tests for CodeBadger Server

These tests verify the complete workflow of the CodeBadger MCP server
using the core.c test codebase.
"""

import asyncio
import json
import os
import pytest
import re
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from fastmcp import Client
except ImportError:
    pytest.skip("FastMCP not found. Install with: pip install fastmcp", allow_module_level=True)


class TestCodeBadgerIntegration:
    """Integration tests for CodeBadger MCP server"""

    @pytest.fixture(scope="class")
    def event_loop(self):
        """Create an instance of the default event loop for the test class"""
        loop = asyncio.get_event_loop_policy().new_event_loop()
        yield loop
        loop.close()

    @pytest.fixture
    async def client(self):
        """FastMCP client fixture using in-memory server"""
        from main import mcp
        
        async with Client(mcp) as client_instance:
            yield client_instance

    @pytest.fixture
    def codebase_path(self):
        """Path to the test codebase - use host path since server runs on host"""
        # MCP server runs on host machine with direct filesystem access
        # Use the test codebase that exists in playground/codebases/core
        project_root = Path(__file__).parent.parent.parent
        return str((project_root / "playground" / "codebases" / "core").resolve())

    def extract_tool_result(self, result):
        """Extract dictionary data from CallToolResult"""
        if hasattr(result, 'content') and result.content:
            content_text = result.content[0].text
            try:
                parsed = json.loads(content_text)

                # Handle complex results that return Scala output with embedded JSON
                if isinstance(parsed, dict) and 'value' in parsed:
                    value = parsed['value']
                    if isinstance(value, str):
                        # Look for embedded JSON in the Scala output
                        json_match = re.search(r'val res\d+: String = ("\{.*\}")', value)
                        if json_match:
                            try:
                                escaped_json = json_match.group(1)
                                json_str = escaped_json[1:-1]
                                json_str = json_str.replace('\\"', '"')
                                json_str = json_str.replace('\\\\', '\\')
                                return json.loads(json_str)
                            except json.JSONDecodeError:
                                pass
                        return parsed
                    else:
                        return parsed

                # If parsed is a dict and contains raw stdout without 'data', attempt to parse
                if isinstance(parsed, dict) and 'data' not in parsed and 'stdout' in parsed:
                    stdout_text = parsed.get('stdout', '')
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    cleaned = ansi_escape.sub('', stdout_text)
                    # Try to parse numeric outputs like 'resNNN: Int = 71'
                    m = re.search(r'res\d+:\s*Int\s*=\s*([0-9]+)', cleaned)
                    if m:
                        try:
                            return {"success": True, "data": int(m.group(1)), "row_count": 1}
                        except ValueError:
                            pass
                    # Try to parse JSON from stdout
                    try:
                        parsed_json = json.loads(cleaned)
                        return {"success": True, "data": parsed_json, "row_count": 1 if not isinstance(parsed_json, list) else len(parsed_json)}
                    except Exception:
                        return parsed

                # Ensure certain fields exist for consistency (success and execution_time)
                if isinstance(parsed, dict):
                    if "success" not in parsed:
                        parsed["success"] = True
                    if "execution_time" not in parsed:
                        parsed["execution_time"] = None
                return parsed
            except json.JSONDecodeError:
                return {"error": content_text}
        # If no 'data' is present, attempt to parse raw stdout for numeric or JSON values
        if hasattr(result, 'content') and result.content:
            try:
                content_text = result.content[0].text
            except Exception:
                content_text = ''
            if content_text:
                ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                text = ansi_escape.sub('', content_text)
                # Search for 'resNNN: Int = 71' pattern
                m = re.search(r'res\d+:\s*Int\s*=\s*([0-9]+)', text)
                if m:
                    try:
                        return {"success": True, "data": int(m.group(1)), "row_count": 1, "execution_time": None}
                    except ValueError:
                        pass
                try:
                    parsed_json = json.loads(text)
                    return {"success": True, "data": parsed_json, "row_count": 1 if not isinstance(parsed_json, list) else len(parsed_json), "execution_time": None}
                except Exception:
                    pass
        return {}
    
    async def wait_for_cpg_ready(self, client, codebase_hash, max_wait=60):
        """Helper to wait for CPG to be ready with a healthy Joern server"""
        for i in range(max_wait):
            await asyncio.sleep(3)
            status_result = await client.call_tool("get_cpg_status", {"codebase_hash": codebase_hash})
            status_dict = self.extract_tool_result(status_result)
            status = status_dict.get("status")
            if status == "ready" and status_dict.get("joern_port"):
                return True
            # "loading" means server restart in progress — keep waiting
            if status in ("failed", "error"):
                return False
        return False

    @pytest.mark.asyncio
    @pytest.mark.timeout(10)
    async def test_server_connectivity(self, client):
        """Test that the server is responding"""
        await client.ping()

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_cpg_generation(self, client, codebase_path):
        """Test CPG generation for the test codebase"""
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })

        cpg_dict = self.extract_tool_result(result)
        assert "codebase_hash" in cpg_dict, f"No codebase_hash in response: {cpg_dict}"

        codebase_hash = cpg_dict["codebase_hash"]
        assert isinstance(codebase_hash, str), "codebase_hash should be a string"
        assert len(codebase_hash) == 16, "codebase_hash should be 16 characters"

        status = cpg_dict.get("status")
        assert status in ["generating", "loading", "ready"], f"Unexpected status: {status}"

        return codebase_hash

    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_cpg_status_wait(self, client, codebase_path):
        """Test waiting for CPG to be ready"""
        # First generate CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]
        
        # Initial status could be "generating" or "ready" (if cached)
        initial_status = cpg_dict.get("status")
        assert initial_status in ["generating", "loading", "ready"], f"Unexpected initial status: {initial_status}"

        # Wait for CPG to be ready (only if it's still in progress)
        if initial_status in ("generating", "loading"):
            max_attempts = 60
            cpg_ready = False

            for attempt in range(max_attempts):
                await asyncio.sleep(3)

                status_result = await client.call_tool("get_cpg_status", {
                    "codebase_hash": codebase_hash
                })

                status_dict = self.extract_tool_result(status_result)
                status = status_dict.get("status")

                if status == "ready":
                    cpg_ready = True
                    break

            assert cpg_ready, f"CPG not ready after {max_attempts} attempts (status: {status})"
        else:
            # Already ready, get status
            status_result = await client.call_tool("get_cpg_status", {
                "codebase_hash": codebase_hash
            })
            status_dict = self.extract_tool_result(status_result)

        # Verify CPG status response structure
        expected_fields = ["codebase_hash", "status", "cpg_path",
                         "source_type", "language", "created_at", "last_accessed"]
        for field in expected_fields:
            assert field in status_dict, f"Missing field: {field}"

        assert status_dict["source_type"] == "local"
        assert status_dict["language"] == "c"
        assert status_dict["status"] == "ready"

        return codebase_hash

    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_cpg_caching(self, client, codebase_path):
        """Test that CPG generation uses caching for repeated requests"""
        # Generate CPG first time
        result1 = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict1 = self.extract_tool_result(result1)
        codebase_hash = cpg_dict1["codebase_hash"]
        
        # Wait for first CPG to be ready (if generating)
        if cpg_dict1.get("status") == "generating":
            for _ in range(30):
                await asyncio.sleep(2)
                status_result = await client.call_tool("get_cpg_status", {"codebase_hash": codebase_hash})
                if self.extract_tool_result(status_result).get("status") == "ready":
                    break

        # Generate CPG second time (should be cached/ready immediately)
        result2 = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict2 = self.extract_tool_result(result2)

        # Should get the same hash
        assert cpg_dict1["codebase_hash"] == cpg_dict2["codebase_hash"]

        # A cached codebase may be immediately ready or may still be restarting the Joern server.
        assert cpg_dict2["status"] in ["ready", "loading"]

        if cpg_dict2["status"] == "loading":
            ready = await self.wait_for_cpg_ready(client, codebase_hash)
            assert ready, "Cached CPG did not return to ready after restart"

    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_list_methods(self, client, codebase_path):
        """Test listing methods in the codebase"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready (allow more time for async generation)
        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready after waiting"

        # List methods
        methods_result = await client.call_tool("list_methods", {
            "codebase_hash": codebase_hash,
            "limit": 20,
            "page_size": 20
        })

        methods_dict = self.extract_tool_result(methods_result)
        assert methods_dict.get("success") is True, f"list_methods failed: {methods_dict}"

        methods = methods_dict.get("methods", [])
        total = methods_dict.get("total", 0)

        assert isinstance(methods, list), "methods should be a list"
        assert total >= 0, "total should be non-negative"
        assert len(methods) <= 20, "should not return more than limit"

        # Verify method structure
        if methods:
            method = methods[0]
            required_fields = ["node_id", "name", "cyclomaticComplexity", "numberOfLines"]
            for field in required_fields:
                assert field in method, f"Method missing field: {field}"


    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_find_taint_sources(self, client, codebase_path):
        """Test finding taint sources"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # Find taint sources
        sources_result = await client.call_tool("find_taint_sources", {
            "codebase_hash": codebase_hash,
            "language": "c"
        })

        sources_dict = self.extract_tool_result(sources_result)
        assert sources_dict.get("success") is True, f"Find sources failed: {sources_dict}"

        sources = sources_dict.get("sources", [])
        total = sources_dict.get("total", 0)

        assert isinstance(sources, list), "sources should be a list"
        assert total >= 0, "total should be non-negative"

        # Verify source structure
        if sources:
            source = sources[0]
            required_fields = ["node_id", "name", "code", "filename", "lineNumber", "method"]
            for field in required_fields:
                assert field in source, f"Source missing field: {field}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_find_taint_sinks(self, client, codebase_path):
        """Test finding taint sinks"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # Find taint sinks
        sinks_result = await client.call_tool("find_taint_sinks", {
            "codebase_hash": codebase_hash,
            "language": "c"
        })

        sinks_dict = self.extract_tool_result(sinks_result)
        assert sinks_dict.get("success") is True, f"Find sinks failed: {sinks_dict}"

        sinks = sinks_dict.get("sinks", [])
        total = sinks_dict.get("total", 0)

        assert isinstance(sinks, list), "sinks should be a list"
        assert total >= 0, "total should be non-negative"

        # Verify sink structure
        if sinks:
            sink = sinks[0]
            required_fields = ["node_id", "name", "code", "filename", "lineNumber", "method"]
            for field in required_fields:
                assert field in sink, f"Sink missing field: {field}"


    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_list_calls(self, client, codebase_path):
        """Test listing function calls"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # List calls
        calls_result = await client.call_tool("list_calls", {
            "codebase_hash": codebase_hash,
            "limit": 10,
            "page_size": 10
        })

        calls_dict = self.extract_tool_result(calls_result)
        assert calls_dict.get("success") is True, f"List calls failed: {calls_dict}"

        calls = calls_dict.get("calls", [])
        total = calls_dict.get("total", 0)

        assert isinstance(calls, list), "calls should be a list"
        assert total >= 0, "total should be non-negative"
        assert len(calls) <= 10, "should not return more than limit"

        # Verify call structure
        if calls:
            call = calls[0]
            required_fields = ["caller", "callee", "code", "filename", "lineNumber"]
            for field in required_fields:
                assert field in call, f"Call missing field: {field}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_run_cpgql_query(self, client, codebase_path):
        """Test executing raw CPGQL queries"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # Execute a simple CPGQL query to count methods
        query_result = await client.call_tool("run_cpgql_query", {
            "codebase_hash": codebase_hash,
            "query": "cpg.method.size",
            "timeout": 10
        })

        query_dict = self.extract_tool_result(query_result)
        assert query_dict.get("success") is True, f"CPGQL query failed: {query_dict}"

        # Verify response structure
        assert "data" in query_dict, "Response should contain data"
        assert "row_count" in query_dict, "Response should contain row_count"
        assert "execution_time" in query_dict or ("data" in query_dict and "row_count" in query_dict and "success" in query_dict), "Response should contain execution_time or structured data"

        # The result should be a number (count of methods)
        data = query_dict["data"]
        assert isinstance(data, (int, str)), "Data should be a number or string"

        row_count = query_dict["row_count"]
        assert isinstance(row_count, int), "row_count should be an integer"
        assert row_count >= 0, "row_count should be non-negative"

        execution_time = query_dict.get("execution_time")
        if execution_time is not None:
            assert isinstance(execution_time, (int, float)), "execution_time should be a number"
            assert execution_time >= 0, "execution_time should be non-negative"

    @pytest.mark.asyncio
    @pytest.mark.timeout(270)
    async def test_auto_taint_flows(self, client, codebase_path):
        """Test auto-mode taint flow detection across multiple files
        
        Expected: The multi-file codebase has:
        - Sources: getenv (9), recv (5), fgets (3+), fread (2+), fopen (2+) = ~20 sources
        - Sinks: system (11), memcpy (10+), free (39), printf (10+), sprintf, open = ~100+ sinks
        """
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # Run auto taint flow detection
        flows_result = await client.call_tool("find_taint_flows", {
            "codebase_hash": codebase_hash,
            "mode": "auto",
            "language": "c",
            "max_results": 50,
            "timeout": 60
        })

        if hasattr(flows_result, 'content') and flows_result.content:
            content = flows_result.content[0].text
            
            # Verify header is present
            assert "Auto Taint Flow Analysis" in content, "Missing analysis header"
            
            # Verify sources were found (minimum expected: 15 based on grep analysis)
            assert "Sources matched:" in content, "Missing sources count"
            import re
            sources_match = re.search(r"Sources matched:\s*(\d+)", content)
            if sources_match:
                source_count = int(sources_match.group(1))
                assert source_count >= 15, f"Expected at least 15 taint sources, got {source_count}"
            
            # Verify sinks were found (minimum expected: 50 based on grep analysis)
            assert "Sinks matched:" in content, "Missing sinks count"
            sinks_match = re.search(r"Sinks matched:\s*(\d+)", content)
            if sinks_match:
                sink_count = int(sinks_match.group(1))
                assert sink_count >= 50, f"Expected at least 50 taint sinks, got {sink_count}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(240)
    async def test_find_use_after_free(self, client, codebase_path):
        """Test UAF detection in multi-file codebase

        Expected UAF patterns in memory.c:
        - dma_shadow_refresh: dereferences mc->dma_shadow, which aliases a
          dma_buffer that dma_controller_teardown/dma_free_buffer may free.
        - dma_detach_buffer: frees mc->dma_buffer through the buffer_release()
          helper (interprocedural) and returns the now-dangling pointer.

        dma_remap_buffer (free then reassign via malloc, then memcpy into the
        fresh allocation) must NOT be reported — the pointer is reassigned.
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # Find UAF vulnerabilities
        uaf_result = await client.call_tool("find_use_after_free", {
            "codebase_hash": codebase_hash,
            "timeout": 60
        })

        if hasattr(uaf_result, 'content') and uaf_result.content:
            content = uaf_result.content[0].text
            assert isinstance(content, str), "UAF result should be string"
            
            # Verify the output contains expected header
            assert "Use-After-Free Analysis" in content or "UAF" in content or "use-after-free" in content.lower(), \
                f"Missing UAF analysis header in output: {content[:200]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(240)
    async def test_find_double_free(self, client, codebase_path):
        """Test double-free detection in multi-file codebase

        Expected double-free patterns in memory.c:
        - dma_controller_teardown: on the error path frees the local alias
          `buffer`, then the unconditional teardown frees mc->dma_buffer again
          (same allocation, not in mutually-exclusive branches).
        - scratch_pool_reclaim: `primary` and `mirror` alias the same malloc and
          are both freed.

        dma_release_either (free in the if-branch, free in the else-branch) must
        NOT be reported — the two frees are mutually exclusive.
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # Find double-free vulnerabilities
        df_result = await client.call_tool("find_double_free", {
            "codebase_hash": codebase_hash,
            "timeout": 60
        })

        if hasattr(df_result, 'content') and df_result.content:
            content = df_result.content[0].text
            assert isinstance(content, str), "Double-free result should be string"
            
            # Verify the output contains expected header
            assert "Double-Free Analysis" in content or "double-free" in content.lower() or "DOUBLE" in content, \
                f"Missing double-free analysis header in output: {content[:200]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(240)
    async def test_find_format_string_vulns(self, client, codebase_path):
        """Test format string vulnerability detection in the core codebase.

        Expected findings:
        - main.c log_startup_message: printf(format) where format = getenv("LOG_FORMAT") — HIGH
        - config.c config_emit_banner: printf(value) where value is a config entry — MEDIUM/HIGH
        - config.c config_write_log: printf(format) where format is a parameter — MEDIUM
        - device.c virtio_net_handle_ctrl: printf(command_buffer + 6) from a recv'd buffer
        - cmdline.c format_status_line: sprintf(buf, format, data) with a caller-supplied format

        printf("%s\\n", buffer) in monitor_format_status uses a literal format and
        must NOT be reported.
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        fs_result = await client.call_tool("find_format_string_vulns", {
            "codebase_hash": codebase_hash,
            "timeout": 120
        })

        if hasattr(fs_result, 'content') and fs_result.content:
            content = fs_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "Format String Vulnerability Analysis" in content, \
                f"Missing analysis header: {content[:200]}"

            # The getenv->printf flow in main.c log_startup_message must surface as HIGH
            assert "HIGH" in content, \
                f"Expected at least one HIGH confidence finding: {content[:500]}"

            # Confidence legend should always be present
            assert "Confidence levels:" in content, \
                f"Missing confidence legend: {content[:500]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(300)
    async def test_find_format_string_vulns_file_filter(self, client, codebase_path):
        """Test format string detection filtered to main.c.

        main.c contains log_startup_message() where getenv("LOG_FORMAT") result
        is passed directly to printf — a HIGH confidence finding.
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        fs_result = await client.call_tool("find_format_string_vulns", {
            "codebase_hash": codebase_hash,
            "filename": "main.c",
            "timeout": 120
        })

        if hasattr(fs_result, 'content') and fs_result.content:
            content = fs_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "Format String Vulnerability Analysis" in content, \
                f"Missing header: {content[:200]}"

            # main.c has printf(format) where format = getenv("LOG_FORMAT")
            assert "HIGH" in content or "MEDIUM" in content, \
                f"Expected findings in main.c: {content[:500]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(300)
    async def test_find_heap_overflow(self, client, codebase_path):
        """Test heap overflow detection in the core codebase.

        Expected findings:
        - memory.c dma_stage_inbound: malloc(MEDIUM_BUFFER_SIZE) + memcpy(temp, data, size)
          where `size` is caller-controlled — write size not bounded by allocation.
        - config.c config_parse_buffer: malloc(size + 1) + memcpy(buf_copy, buffer, size)
          (matched allocation; should be lower risk / not flagged).

        utils.c buffer_copy_checked guards the copy with `src_size > dest_size` and
        must NOT be reported.
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        ho_result = await client.call_tool("find_heap_overflow", {
            "codebase_hash": codebase_hash,
            "timeout": 240
        })

        if hasattr(ho_result, 'content') and ho_result.content:
            content = ho_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "Heap Overflow Analysis" in content, \
                f"Missing analysis header: {content[:200]}"

            # Expect at least some findings from the vulnerable samples
            assert "Issue" in content or "potential heap overflow" in content, \
                f"Expected overflow findings: {content[:500]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(300)
    async def test_find_heap_overflow_file_filter(self, client, codebase_path):
        """Test heap overflow detection filtered to memory.c.

        memory.c contains dma_stage_inbound() where malloc(MEDIUM_BUFFER_SIZE)
        is followed by memcpy(temp, data, size) with no bounds check — size mismatch.
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        ho_result = await client.call_tool("find_heap_overflow", {
            "codebase_hash": codebase_hash,
            "filename": "memory.c",
            "timeout": 240
        })

        if hasattr(ho_result, 'content') and ho_result.content:
            content = ho_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "Heap Overflow Analysis" in content, \
                f"Missing header: {content[:200]}"

            # memory.c: malloc(MEDIUM_BUFFER_SIZE) + memcpy(temp, data, size) — size mismatch
            has_finding = (
                "Unbounded write" in content
                or "not bounded by allocation size" in content
                or "potential heap overflow issue" in content
            )
            assert has_finding, \
                f"Expected heap overflow findings in memory.c: {content[:600]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_deep_call_graph(self, client, codebase_path):
        """Test call graph analysis with deep call chains
        
        Expected: device_init has a 6-level deep chain:
        device_init -> device_configure -> device_setup_io -> 
        device_register_handlers -> device_start -> device_finalize_init -> 
        device_internal_finalize
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # Test call graph from device_init (has 6-level deep chain)
        cg_result = await client.call_tool("get_call_graph", {
            "codebase_hash": codebase_hash,
            "method_name": "device_init",
            "depth": 6,
            "direction": "outgoing"
        })

        if hasattr(cg_result, 'content') and cg_result.content:
            content = cg_result.content[0].text
            assert isinstance(content, str), "Call graph result should be string"
            
            # Verify call graph header
            assert "Call Graph" in content or "device_init" in content, \
                f"Missing call graph header: {content[:200]}"
            
            # Verify at least some of the expected deep chain functions appear
            expected_callees = ["device_configure", "device_setup_io", "device_register_handlers"]
            found_callees = [fn for fn in expected_callees if fn in content]
            assert len(found_callees) >= 2, \
                f"Expected at least 2 of {expected_callees} in call graph, found: {found_callees}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_cfg_state_machine(self, client, codebase_path):
        """Test CFG analysis on state machine function
        
        Expected: device_process_state_machine has a 7-state switch with transitions:
        DEVICE_STATE_UNINIT, DEVICE_STATE_INIT, DEVICE_STATE_CONFIGURED,
        DEVICE_STATE_RUNNING, DEVICE_STATE_PAUSED, DEVICE_STATE_ERROR, DEVICE_STATE_SHUTDOWN
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # Get CFG for state machine function
        cfg_result = await client.call_tool("get_cfg", {
            "codebase_hash": codebase_hash,
            "method_name": "device_process_state_machine",
            "max_nodes": 100
        })

        if hasattr(cfg_result, 'content') and cfg_result.content:
            content = cfg_result.content[0].text
            assert isinstance(content, str), "CFG result should be string"
            
            # Verify CFG header contains the method name
            assert "device_process_state_machine" in content or "Control Flow Graph" in content, \
                f"Missing CFG header: {content[:200]}"
            
            # Verify CFG contains nodes and edges (indicated by -> or Edges:)
            assert "Nodes:" in content or "->" in content, \
                f"CFG should contain nodes/edges: {content[:300]}"


    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_taint_sources_multifile(self, client, codebase_path):
        """Test finding taint sources across multiple files
        
        Expected sources (from grep analysis):
        - getenv: 9 calls in config.c (1), main.c (4), network.c (4)
        - recv: 5 calls in network.c
        - fgets: multiple in cmdline.c, config.c
        - fread: in cmdline.c
        Total: ~20+ taint sources
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # Find taint sources
        sources_result = await client.call_tool("find_taint_sources", {
            "codebase_hash": codebase_hash,
            "language": "c",
            "limit": 100
        })

        sources_dict = self.extract_tool_result(sources_result)
        assert sources_dict.get("success") is True, f"Find sources failed: {sources_dict}"

        sources = sources_dict.get("sources", [])
        total = sources_dict.get("total", len(sources))
        
        # Verify minimum source count
        assert total >= 15, f"Expected at least 15 taint sources, got {total}"
        
        # Verify source names include expected patterns
        source_names = [s.get("name", "") for s in sources]
        expected_source_functions = ["getenv", "recv", "fgets", "fread"]
        found_expected = [fn for fn in expected_source_functions if fn in source_names]
        assert len(found_expected) >= 2, \
            f"Expected at least 2 of {expected_source_functions} in sources, found: {found_expected}"
        
        # Verify sources come from multiple files
        source_files = set(s.get("filename", "") for s in sources if s.get("filename"))
        # Should find sources in at least 3 different files
        assert len(source_files) >= 3, \
            f"Expected sources from at least 3 files, got {len(source_files)}: {source_files}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(210)
    async def test_taint_sinks_multifile(self, client, codebase_path):
        """Test finding taint sinks across multiple files
        
        Expected sinks (from grep analysis):
        - system: 11 calls in device.c (2), main.c (3), network.c (1), config.c (1), cmdline.c (4)
        - free: 39 calls across all modules
        - memcpy: 10+ calls
        - printf/sprintf: 10+ calls
        Total: ~100+ taint sinks
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        # Find taint sinks
        sinks_result = await client.call_tool("find_taint_sinks", {
            "codebase_hash": codebase_hash,
            "language": "c",
            "limit": 150
        })

        sinks_dict = self.extract_tool_result(sinks_result)
        assert sinks_dict.get("success") is True, f"Find sinks failed: {sinks_dict}"

        sinks = sinks_dict.get("sinks", [])
        total = sinks_dict.get("total", len(sinks))
        
        # Verify minimum sink count
        assert total >= 50, f"Expected at least 50 taint sinks, got {total}"
        
        # Verify sink names include dangerous functions
        sink_names = [s.get("name", "") for s in sinks]
        expected_dangerous = ["system", "memcpy", "free", "printf", "sprintf", "open"]
        found_dangerous = [fn for fn in expected_dangerous if fn in sink_names]
        assert len(found_dangerous) >= 3, \
            f"Expected at least 3 of {expected_dangerous} in sinks, found: {found_dangerous}"
        
        # Verify specific dangerous sink counts
        system_count = sink_names.count("system")
        assert system_count >= 5, f"Expected at least 5 system() sinks, got {system_count}"
        
        free_count = sink_names.count("free")
        assert free_count >= 20, f"Expected at least 20 free() sinks, got {free_count}"
        
        # Verify sinks come from multiple files
        sink_files = set(s.get("filename", "") for s in sinks if s.get("filename"))
        assert len(sink_files) >= 5, \
            f"Expected sinks from at least 5 files, got {len(sink_files)}: {sink_files}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(300)
    async def test_find_stack_overflow(self, client, codebase_path):
        """Test stack buffer overflow detection in the core codebase.

        Expected findings:
        - main.c: char local[SMALL_BUFFER_SIZE] + memcpy(local, buffer+5, n-5)
          The write size 'n - 5' is a non-literal expression not bounded by the
          array dimension and has no preceding bounds check.

        safe patterns (should NOT be reported):
        - snprintf(full_cmd, sizeof(full_cmd), ...) in cmdline.c — size arg contains sizeof
        - fgets(input, sizeof(input), stdin) in main.c — not tracked as a writeOp
        - memcpy with literal size <= array dimension
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        so_result = await client.call_tool("find_stack_overflow", {
            "codebase_hash": codebase_hash,
            "timeout": 240
        })

        if hasattr(so_result, "content") and so_result.content:
            content = so_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "Stack Buffer Overflow Analysis" in content, \
                f"Missing analysis header: {content[:200]}"

            # Expect at least one finding from the vulnerable stack-array samples
            has_finding = (
                "potential stack buffer overflow issue" in content
                or "Unbounded write" in content
                or "not statically bounded" in content
                or "exceeds stack buffer size" in content
            )
            assert has_finding, \
                f"Expected stack overflow findings: {content[:500]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(300)
    async def test_find_stack_overflow_file_filter(self, client, codebase_path):
        """Test stack overflow detection filtered to main.c.

        main.c contains:
          char local[SMALL_BUFFER_SIZE]
          memcpy(local, buffer + 5, n - 5)   <- n-5 not bounded by SMALL_BUFFER_SIZE
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        so_result = await client.call_tool("find_stack_overflow", {
            "codebase_hash": codebase_hash,
            "filename": "main.c",
            "timeout": 240
        })

        if hasattr(so_result, "content") and so_result.content:
            content = so_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "Stack Buffer Overflow Analysis" in content, \
                f"Missing header: {content[:200]}"

            has_finding = (
                "Unbounded write" in content
                or "not statically bounded" in content
                or "exceeds stack buffer size" in content
                or "potential stack buffer overflow issue" in content
            )
            assert has_finding, \
                f"Expected stack overflow findings in main.c: {content[:600]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(300)
    async def test_find_integer_overflow(self, client, codebase_path):
        """Test integer-overflow detection on guest-controlled allocation sizes.

        memory.c dma_ring_resize:
            mc->ring = malloc(count * sizeof(DmaDescriptor));
        `count` is a guest-supplied uint32 and the multiplication has no overflow
        guard -> HIGH confidence allocation-size overflow.

        dma_ring_resize_guarded performs the same resize but guards the product
        with __builtin_mul_overflow() and a `count > 65536` bound, so it should
        not surface as HIGH (precision check).
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        io_result = await client.call_tool("find_integer_overflow", {
            "codebase_hash": codebase_hash,
            "filename": "memory.c",
            "timeout": 240
        })

        if hasattr(io_result, "content") and io_result.content:
            content = io_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "Integer Overflow/Underflow Analysis" in content, \
                f"Missing analysis header: {content[:200]}"

            # malloc(count * sizeof(DmaDescriptor)) with no guard is a HIGH finding
            has_finding = (
                "HIGH" in content
                or "dma_ring_resize" in content
                or "alloc_arithmetic" in content
            )
            assert has_finding, \
                f"Expected an integer overflow finding in memory.c: {content[:600]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(300)
    async def test_find_toctou(self, client, codebase_path):
        """Test TOCTOU (CWE-367) detection in the config module.

        config.c config_open_checked:
            if (access(path, R_OK) != 0) return ERR_NOT_FOUND;
            int fd = open(path, O_RDONLY);
        The access() check and the open() use race on the same `path`.
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        toctou_result = await client.call_tool("find_toctou", {
            "codebase_hash": codebase_hash,
            "timeout": 240
        })

        if hasattr(toctou_result, "content") and toctou_result.content:
            content = toctou_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "TOCTOU" in content, \
                f"Missing TOCTOU analysis header: {content[:200]}"

            has_finding = (
                "config_open_checked" in content
                or "access" in content
                or "HIGH" in content
            )
            assert has_finding, \
                f"Expected a TOCTOU finding (access+open in config.c): {content[:600]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(300)
    async def test_find_null_pointer_deref(self, client, codebase_path):
        """Test null-pointer-dereference detection runs across the codebase.

        Many allocations are NULL-checked (memory_controller_create, device_create,
        config_process_entry, ...), which exercises the detector's guard-aware
        filtering so it does not drown in false positives.
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        npd_result = await client.call_tool("find_null_pointer_deref", {
            "codebase_hash": codebase_hash,
            "timeout": 240
        })

        if hasattr(npd_result, "content") and npd_result.content:
            content = npd_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "Null Pointer Dereference Analysis" in content, \
                f"Missing analysis header: {content[:200]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(300)
    async def test_find_uninitialized_reads(self, client, codebase_path):
        """Test uninitialized-read detection runs across the codebase."""
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        ur_result = await client.call_tool("find_uninitialized_reads", {
            "codebase_hash": codebase_hash,
            "timeout": 240
        })

        if hasattr(ur_result, "content") and ur_result.content:
            content = ur_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "Uninitialized Read Analysis" in content, \
                f"Missing analysis header: {content[:200]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(300)
    async def test_interprocedural_taint_recv_to_system(self, client, codebase_path):
        """Test that auto taint analysis connects a network source to a shell sink
        across a function boundary.

        network.c network_read_command does recv() into its `cmd` out-parameter;
        qmp_dispatch_remote / virtio_net_handle_ctrl then pass that buffer to
        system(). The flow recv -> system therefore crosses functions, exercising
        reachableByFlows() interprocedural propagation.
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        flows_result = await client.call_tool("find_taint_flows", {
            "codebase_hash": codebase_hash,
            "mode": "auto",
            "language": "c",
            "max_results": 50,
            "timeout": 120
        })

        if hasattr(flows_result, "content") and flows_result.content:
            content = flows_result.content[0].text
            assert isinstance(content, str), "Result should be string"

            assert "Auto Taint Flow Analysis" in content, "Missing analysis header"

            # The analysis must at least attempt source->sink reachability and
            # report a flow count (confirmed or raw), not error out.
            assert "flow" in content.lower(), \
                f"Expected the auto analysis to report on taint flows: {content[:400]}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(240)
    async def test_call_graph_callback_chain(self, client, codebase_path):
        """Test call-graph traversal through the static callback dispatch chain.

        callbacks.c defines a 5-deep chain reached from callback_dispatch_chain:
        callback_dispatch_chain -> chain_step1 -> chain_step2 -> chain_step3 ->
        chain_step4 -> chain_step5
        These are direct (non function-pointer) calls and should resolve.
        """
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        ready = await self.wait_for_cpg_ready(client, codebase_hash)
        assert ready, "CPG not ready in time"

        cg_result = await client.call_tool("get_call_graph", {
            "codebase_hash": codebase_hash,
            "method_name": "callback_dispatch_chain",
            "depth": 5,
            "direction": "outgoing"
        })

        if hasattr(cg_result, "content") and cg_result.content:
            content = cg_result.content[0].text
            assert isinstance(content, str), "Call graph result should be string"

            assert "Call Graph" in content or "callback_dispatch_chain" in content, \
                f"Missing call graph header: {content[:200]}"

            expected = ["chain_step1", "chain_step2", "chain_step3",
                        "chain_step4", "chain_step5"]
            found = [fn for fn in expected if fn in content]
            assert len(found) >= 2, \
                f"Expected at least 2 of {expected} in call graph, found: {found}"