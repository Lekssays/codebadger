"""
Tests for MCP prompt templates
"""

import pytest

from fastmcp import FastMCP, Client
from fastmcp.prompts import Message

from src.tools.prompts import register_prompts, CONFIDENCE_POLICY


@pytest.fixture
def mcp_with_prompts():
    """Create a FastMCP server with prompts registered"""
    mcp = FastMCP("TestPromptServer")
    register_prompts(mcp)
    return mcp


class TestPromptRegistration:
    """Test that all prompts are properly registered"""

    @pytest.mark.asyncio
    async def test_all_prompts_registered(self, mcp_with_prompts):
        """All 6 security prompts should be discoverable via list_prompts"""
        async with Client(mcp_with_prompts) as client:
            prompts = await client.list_prompts()
            prompt_names = {p.name for p in prompts}

            expected = {
                "security_audit",
                "memory_safety_check",
                "taint_flow_investigation",
                "attack_surface_map",
                "investigate_code",
                "code_review",
            }
            assert expected == prompt_names

    @pytest.mark.asyncio
    async def test_prompt_descriptions_present(self, mcp_with_prompts):
        """Each prompt should have a non-empty description"""
        async with Client(mcp_with_prompts) as client:
            prompts = await client.list_prompts()
            for prompt in prompts:
                assert prompt.description, f"Prompt '{prompt.name}' has no description"


class TestSecurityAuditPrompt:
    """Test security_audit prompt"""

    @pytest.mark.asyncio
    async def test_basic_render(self, mcp_with_prompts):
        """Renders with only required codebase_hash"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "security_audit",
                arguments={"codebase_hash": "abc123"},
            )
            assert len(result.messages) == 2
            # First message should be user instructions
            assert result.messages[0].role == "user"
            # Second should be assistant acknowledgment
            assert result.messages[1].role == "assistant"

            content = result.messages[0].content.text
            assert "abc123" in content
            assert "get_codebase_summary" in content
            assert "find_taint_flows" in content

    @pytest.mark.asyncio
    async def test_with_language(self, mcp_with_prompts):
        """Language param should appear in tool call instructions"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "security_audit",
                arguments={"codebase_hash": "abc123", "language": "python"},
            )
            content = result.messages[0].content.text
            assert 'language="python"' in content

    @pytest.mark.asyncio
    async def test_with_focus_area_injection(self, mcp_with_prompts):
        """Focus area should add specific instructions"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "security_audit",
                arguments={"codebase_hash": "abc123", "focus_area": "injection"},
            )
            content = result.messages[0].content.text
            assert "injection" in content.lower()

    @pytest.mark.asyncio
    async def test_with_focus_area_memory(self, mcp_with_prompts):
        """Memory focus should include memory safety tools"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "security_audit",
                arguments={"codebase_hash": "abc123", "focus_area": "memory"},
            )
            content = result.messages[0].content.text
            assert "find_use_after_free" in content
            assert "find_double_free" in content


class TestMemorySafetyCheckPrompt:
    """Test memory_safety_check prompt"""

    @pytest.mark.asyncio
    async def test_basic_render(self, mcp_with_prompts):
        """Renders with only required codebase_hash"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "memory_safety_check",
                arguments={"codebase_hash": "abc123"},
            )
            assert len(result.messages) == 1
            content = result.messages[0].content.text
            assert "abc123" in content
            assert "find_use_after_free" in content
            assert "find_double_free" in content
            assert "find_bounds_checks" in content
            assert "CWE-416" in content
            assert "CWE-415" in content

    @pytest.mark.asyncio
    async def test_with_filename(self, mcp_with_prompts):
        """Filename param should scope the analysis"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "memory_safety_check",
                arguments={"codebase_hash": "abc123", "filename": "main.c"},
            )
            content = result.messages[0].content.text
            assert "main.c" in content
            assert 'filename="main.c"' in content


class TestTaintFlowInvestigationPrompt:
    """Test taint_flow_investigation prompt"""

    @pytest.mark.asyncio
    async def test_discovery_mode(self, mcp_with_prompts):
        """Without locations, should use auto discovery mode"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "taint_flow_investigation",
                arguments={"codebase_hash": "abc123"},
            )
            content = result.messages[0].content.text
            assert 'mode="auto"' in content
            assert "Discover All Taint Flows" in content

    @pytest.mark.asyncio
    async def test_targeted_mode(self, mcp_with_prompts):
        """With source and sink locations, should use targeted mode"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "taint_flow_investigation",
                arguments={
                    "codebase_hash": "abc123",
                    "source_location": "main.c:42",
                    "sink_location": "utils.c:100",
                },
            )
            content = result.messages[0].content.text
            assert "main.c:42" in content
            assert "utils.c:100" in content
            assert "get_program_slice" in content

    @pytest.mark.asyncio
    async def test_with_language(self, mcp_with_prompts):
        """Language param should appear in discovery mode"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "taint_flow_investigation",
                arguments={"codebase_hash": "abc123", "language": "java"},
            )
            content = result.messages[0].content.text
            assert 'language="java"' in content


class TestAttackSurfaceMapPrompt:
    """Test attack_surface_map prompt"""

    @pytest.mark.asyncio
    async def test_basic_render(self, mcp_with_prompts):
        """Renders with required params and returns multi-turn messages"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "attack_surface_map",
                arguments={"codebase_hash": "abc123"},
            )
            assert len(result.messages) == 2
            assert result.messages[0].role == "user"
            assert result.messages[1].role == "assistant"

            content = result.messages[0].content.text
            assert "find_taint_sources" in content
            assert "find_taint_sinks" in content
            assert "get_call_graph" in content
            assert "discover_fixed_vulnerabilities" in content

    @pytest.mark.asyncio
    async def test_with_language(self, mcp_with_prompts):
        """Language param should be passed to taint tools"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "attack_surface_map",
                arguments={"codebase_hash": "abc123", "language": "go"},
            )
            content = result.messages[0].content.text
            assert 'language="go"' in content


class TestInvestigateCodePrompt:
    """Test investigate_code prompt"""

    @pytest.mark.asyncio
    async def test_function_mode(self, mcp_with_prompts):
        """With function_name, should do function-focused investigation"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "investigate_code",
                arguments={
                    "codebase_hash": "abc123",
                    "function_name": "process_input",
                },
            )
            assert len(result.messages) == 2
            content = result.messages[0].content.text
            assert "process_input" in content
            assert "get_file_content" in content
            assert "list_parameters" in content
            assert "get_call_graph" in content
            assert "get_cfg" in content

    @pytest.mark.asyncio
    async def test_file_mode(self, mcp_with_prompts):
        """With filename, should do file-focused investigation"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "investigate_code",
                arguments={
                    "codebase_hash": "abc123",
                    "filename": "auth.py",
                },
            )
            content = result.messages[0].content.text
            assert "auth.py" in content
            assert "list_methods" in content
            assert "find_taint_sources" in content
            assert "find_taint_sinks" in content

    @pytest.mark.asyncio
    async def test_file_mode_with_line_number(self, mcp_with_prompts):
        """With filename and line_number, should focus on that area"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "investigate_code",
                arguments={
                    "codebase_hash": "abc123",
                    "filename": "main.c",
                    "line_number": "50",
                },
            )
            content = result.messages[0].content.text
            assert "main.c" in content
            assert "line 50" in content
            assert "get_code_snippet" in content

    @pytest.mark.asyncio
    async def test_no_target_mode(self, mcp_with_prompts):
        """Without function or file, should ask user to specify"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "investigate_code",
                arguments={"codebase_hash": "abc123"},
            )
            content = result.messages[0].content.text
            assert "function_name" in content
            assert "filename" in content

    @pytest.mark.asyncio
    async def test_function_with_filename(self, mcp_with_prompts):
        """Function mode with filename should pass filename for disambiguation"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "investigate_code",
                arguments={
                    "codebase_hash": "abc123",
                    "function_name": "main",
                    "filename": "app.c",
                },
            )
            content = result.messages[0].content.text
            assert 'filename="app.c"' in content


class TestCodeReviewPrompt:
    """Test code_review prompt"""

    @pytest.mark.asyncio
    async def test_codebase_wide_review(self, mcp_with_prompts):
        """Without filename or function, should review entire codebase"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "code_review",
                arguments={"codebase_hash": "abc123"},
            )
            assert len(result.messages) == 2
            assert result.messages[0].role == "user"
            assert result.messages[1].role == "assistant"

            content = result.messages[0].content.text
            assert "abc123" in content
            assert "get_codebase_summary" in content
            assert "list_source_files" in content
            assert "Input Validation" in content
            assert "Injection Risks" in content
            assert "Error Handling" in content

    @pytest.mark.asyncio
    async def test_file_review(self, mcp_with_prompts):
        """With filename, should scope review to that file"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "code_review",
                arguments={"codebase_hash": "abc123", "filename": "handler.py"},
            )
            content = result.messages[0].content.text
            assert "handler.py" in content
            assert "list_methods" in content
            assert "list_calls" in content

    @pytest.mark.asyncio
    async def test_function_review(self, mcp_with_prompts):
        """With function_name, should scope review to that function"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "code_review",
                arguments={
                    "codebase_hash": "abc123",
                    "function_name": "handle_request",
                },
            )
            content = result.messages[0].content.text
            assert "handle_request" in content
            assert "get_file_content" in content
            assert "list_parameters" in content
            assert "get_call_graph" in content
            assert "get_cfg" in content

    @pytest.mark.asyncio
    async def test_function_review_with_filename(self, mcp_with_prompts):
        """Function review with filename should include both"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "code_review",
                arguments={
                    "codebase_hash": "abc123",
                    "function_name": "parse",
                    "filename": "parser.c",
                },
            )
            content = result.messages[0].content.text
            assert "parse" in content
            assert 'filename="parser.c"' in content

    @pytest.mark.asyncio
    async def test_positive_observations_section(self, mcp_with_prompts):
        """Review should include a section for good practices"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(
                "code_review",
                arguments={"codebase_hash": "abc123"},
            )
            content = result.messages[0].content.text
            assert "Positive Observations" in content


class TestConfidencePolicy:
    """Test that confidence policy is present in all prompts"""

    PROMPTS_WITH_CONFIDENCE = [
        ("security_audit", {"codebase_hash": "abc123"}),
        ("memory_safety_check", {"codebase_hash": "abc123"}),
        ("taint_flow_investigation", {"codebase_hash": "abc123"}),
        (
            "taint_flow_investigation",
            {
                "codebase_hash": "abc123",
                "source_location": "a.c:1",
                "sink_location": "b.c:2",
            },
        ),
        ("attack_surface_map", {"codebase_hash": "abc123"}),
        ("investigate_code", {"codebase_hash": "abc123", "function_name": "fn"}),
        ("investigate_code", {"codebase_hash": "abc123", "filename": "f.c"}),
        ("code_review", {"codebase_hash": "abc123"}),
    ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("prompt_name,args", PROMPTS_WITH_CONFIDENCE)
    async def test_confidence_policy_present(
        self, mcp_with_prompts, prompt_name, args
    ):
        """Every prompt should include the confidence policy"""
        async with Client(mcp_with_prompts) as client:
            result = await client.get_prompt(prompt_name, arguments=args)
            # Check first user message for confidence text
            content = result.messages[0].content.text
            assert "Confidence" in content
            assert "false positive" in content.lower()
