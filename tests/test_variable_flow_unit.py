
import sys
import unittest
from unittest.mock import MagicMock, ANY

class TestVariableFlow(unittest.TestCase):
    def test_logic(self):
        # Mock services
        services = {
            "codebase_tracker": MagicMock(),
            "query_executor": MagicMock(),
            "config": MagicMock()
        }
        
        # Mock Config
        services["config"].cpg.taint_sources = {}
        services["config"].cpg.taint_sinks = {}
        
        # Mock CodebaseInfo
        codebase_info = MagicMock()
        codebase_info.cpg_path = "/path/to/cpg"
        codebase_info.language = "c"
        services["codebase_tracker"].get_codebase.return_value = codebase_info
        
        # Mock QueryExecutor result
        query_result = MagicMock()
        query_result.success = True
        query_result.data = ["""Variable Flow Analysis
======================
Target: variable 'x'
Aliases: p
Dependencies: ..."""]
        services["query_executor"].execute_query.return_value = query_result
        
        # Mock MCP
        mcp = MagicMock()
        registered_functions = {}
        
        def tool_decorator(description=None):
            def decorator(func):
                registered_functions[func.__name__] = func
                return func
            return decorator
            
        mcp.tool = tool_decorator
        
        # Import and register
        from src.tools.taint_analysis_tools import register_taint_analysis_tools
        register_taint_analysis_tools(mcp, services)
        
        # Get function
        get_variable_flow = registered_functions["get_variable_flow"]
        
        # Test Call
        result = get_variable_flow(
            codebase_hash="1234567890abcdef",
            location="main.c:10",
            variable="x",
            direction="backward"
        )
        
        # Verify result is string
        self.assertIsInstance(result, str)
        self.assertIn("Variable Flow Analysis", result)
        self.assertIn("Aliases: p", result)

    def test_parameter_detection_output(self):
        # Mock services
        services = {
            "codebase_tracker": MagicMock(),
            "query_executor": MagicMock(),
            "config": MagicMock()
        }
        
        # Mock CodebaseInfo
        codebase_info = MagicMock()
        codebase_info.cpg_path = "/path/to/cpg"
        codebase_info.language = "c"
        services["codebase_tracker"].get_codebase.return_value = codebase_info
        
        # Mock result with parameters
        query_result = MagicMock()
        query_result.success = True
        query_result.data = ["""Variable Flow Analysis
======================
Target: variable 'item'
Method: foo
Direction: backward

Dependencies:
[Line  400] void * item (parameter)
"""]
        services["query_executor"].execute_query.return_value = query_result
        
        # Mock MCP
        mcp = MagicMock()
        registered_functions = {}
        
        def tool_decorator(description=None):
            def decorator(func):
                registered_functions[func.__name__] = func
                return func
            return decorator
            
        mcp.tool = tool_decorator
        
        from src.tools.taint_analysis_tools import register_taint_analysis_tools
        register_taint_analysis_tools(mcp, services)
        get_variable_flow = registered_functions["get_variable_flow"]
        
        result = get_variable_flow(
             codebase_hash="1234567890abcdef",
             location="test.c:10",
             variable="item",
             direction="backward"
        )
        self.assertIn("(parameter)", result)
        
        # Verify query executor called with correct args
        services["query_executor"].execute_query.assert_called()
        call_args = services["query_executor"].execute_query.call_args[1]
        self.assertIn("query", call_args)

    def test_cast_assignment_and_field_access(self):
        # Mock services with relevant response
        services = {
            "codebase_tracker": MagicMock(),
            "query_executor": MagicMock(),
            "config": MagicMock()
        }
        services["config"].cpg.taint_sources = {}
        
        # Mock CodebaseInfo
        codebase_info = MagicMock()
        codebase_info.cpg_path = "/path/to/cpg"
        codebase_info.language = "c"
        services["codebase_tracker"].get_codebase.return_value = codebase_info

        # Mock query response pretending to find a cast and field access
        # This confirms that our tool correctly passes through and formats what the query finds
        query_result = MagicMock()
        query_result.success = True
        query_result.data = ["""Variable Flow Analysis
======================
Target: variable 'list'
Method: test_func
Direction: backward

Dependencies:
[Line   10] list = (Type) ptr; (assignment)
[Line   20] list->field = val; (modification)
"""]
        services["query_executor"].execute_query.return_value = query_result
        
        # Mock MCP
        mcp = MagicMock()
        registered_functions = {}
        def tool_decorator(description=None):
            def decorator(func):
                registered_functions[func.__name__] = func
                return func
            return decorator
        mcp.tool = tool_decorator
        
        from src.tools.taint_analysis_tools import register_taint_analysis_tools
        register_taint_analysis_tools(mcp, services)
        get_variable_flow = registered_functions["get_variable_flow"]
        
        result = get_variable_flow(
            codebase_hash="1234567890abcdef",
            location="file.c:20",
            variable="list",
            direction="backward"
        )
        
        self.assertIn("list = (Type) ptr", result)
        self.assertIn("list->field = val", result)
        
        # Check that query loading logic worked (implicitly verified by execute_query being called)

if __name__ == '__main__':
    unittest.main()
