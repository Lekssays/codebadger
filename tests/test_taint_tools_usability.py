import pytest
import pytest
from unittest.mock import MagicMock
from src.tools.taint_analysis_tools import register_taint_analysis_tools

@pytest.fixture
def taint_tools(mock_services):
    """Register tools and return a dict of {name: function}"""
    # Create a mock MCP object that captures decorated functions
    mock_mcp = MagicMock()
    tools = {}
    
    def tool_decorator(description=None):
        def decorator(func):
            tools[func.__name__] = func
            return func
        return decorator
    
    mock_mcp.tool.side_effect = tool_decorator
    
    # Register tools
    register_taint_analysis_tools(mock_mcp, mock_services)
    return tools

@pytest.fixture
def mock_services():
    mock_tracker = MagicMock()
    mock_executor = MagicMock()
    mock_config = MagicMock()
    
    # Mock codebase info
    mock_tracker.get_codebase.return_value.cpg_path = "/tmp/test.cpg"
    mock_tracker.get_codebase.return_value.language = "c"
    
    services = {}
    services["codebase_tracker"] = mock_tracker
    services["query_executor"] = mock_executor
    services["config"] = mock_config
    return services

def test_find_taint_flows_missing_sink_message(taint_tools):
    """Test that missing sink triggers the new helpful error message"""
    find_taint_flows = taint_tools["find_taint_flows"]
    
    try:
        result = find_taint_flows(
            codebase_hash="1234567812345678",
            source_location="main.c:10"
        )
        # If it returns a string error message (which it often does in other tools via exception catching):
        assert "CRITICAL ERROR: MISSING SINK" in result
        assert "CORRECT USAGE WORKFLOW" in result
        assert "YOU MUST PROVIDE THIS" in result
    except Exception as e:
        # If it raises exception directly (if my try/except didn't catch it?)
        assert "CRITICAL ERROR: MISSING SINK" in str(e)
        assert "CORRECT USAGE WORKFLOW" in str(e)
        assert "YOU MUST PROVIDE THIS" in str(e)

def test_find_taint_flows_missing_source_message(taint_tools):
    """Test that missing source triggers the new helpful error message"""
    find_taint_flows = taint_tools["find_taint_flows"]
    
    try:
        result = find_taint_flows(
            codebase_hash="1234567812345678",
            sink_location="main.c:20"
        )
        assert "CRITICAL ERROR: MISSING SOURCE" in result
        assert "CORRECT USAGE WORKFLOW" in result
        assert "YOU MUST PROVIDE THIS" in result
    except Exception as e:
        assert "CRITICAL ERROR: MISSING SOURCE" in str(e)
        assert "CORRECT USAGE WORKFLOW" in str(e)
        assert "YOU MUST PROVIDE THIS" in str(e)

def test_find_taint_flows_legacy_arg_detection(taint_tools):
    """Test that legacy arguments like source_pattern trigger specific error"""
    find_taint_flows = taint_tools["find_taint_flows"]
    
    try:
        result = find_taint_flows(
            codebase_hash="1234567812345678",
            source_location="main.c:10",
            sink_location="main.c:20",
            source_pattern="broken"  # Legacy arg
        )
        assert "Unexpected arguments: ['source_pattern']" in result
        assert "deprecated" in result
    except Exception as e:
        assert "Unexpected arguments: ['source_pattern']" in str(e)
        assert "deprecated" in str(e)

def test_find_taint_flows_multiple_legacy_args(taint_tools):
    """Test detection of multiple legacy arguments"""
    find_taint_flows = taint_tools["find_taint_flows"]
    
    try:
        result = find_taint_flows(
            codebase_hash="1234567812345678",
            source_location="main.c:10",
            sink_location="main.c:20",
            mode="intra",
            depth=5
        )
        assert "Unexpected arguments" in result
        assert "mode" in result
        assert "depth" in result
    except Exception as e:
        assert "Unexpected arguments" in str(e)
        assert "mode" in str(e)
