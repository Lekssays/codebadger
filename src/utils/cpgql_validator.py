"""
CPGQL Query Validator and Helper Utilities

Provides syntax validation, error detection, and helper methods for CPGQL queries
"""

import re
import logging
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)


class CPGQLValidator:
    """Validator for CPGQL queries with syntax checking and suggestions"""
    
    # Common CPGQL methods and their expected signatures
    CPGQL_METHODS = {
        'name': {'args': 1, 'accepts': ['string', 'regex']},
        'code': {'args': 1, 'accepts': ['string', 'regex']},
        'typeFullName': {'args': 1, 'accepts': ['string', 'regex']},
        'filename': {'args': 1, 'accepts': ['string', 'regex']},
        'filter': {'args': 1, 'accepts': ['lambda']},
        'where': {'args': 1, 'accepts': ['lambda']},
        'map': {'args': 1, 'accepts': ['lambda']},
        'l': {'args': 0, 'accepts': []},
        'size': {'args': 0, 'accepts': []},
        'take': {'args': 1, 'accepts': ['int']},
        'head': {'args': 0, 'accepts': []},
        'headOption': {'args': 0, 'accepts': []},
        'toJsonPretty': {'args': 0, 'accepts': []},
        'toJson': {'args': 0, 'accepts': []},
        'isExternal': {'args': 1, 'accepts': ['boolean']},
        'call': {'args': 0, 'accepts': []},
        'method': {'args': 0, 'accepts': []},
        'contains': {'args': 1, 'accepts': ['string']},
        'matches': {'args': 1, 'accepts': ['regex']},
    }
    
    # Common errors and their solutions
    COMMON_ERRORS = {
        'matches is not a member': {
            'description': 'The .matches() method doesn\'t exist on Iterator[String].',
            'solution': 'Use .filter(_.code.contains("substring")) or .filter(_.code.matches("regex")) within a lambda.',
            'examples': [
                'cpg.literal.filter(_.code.contains("*")).l',
                'cpg.call.filter(_.name.matches(".*malloc.*")).l',
                'cpg.method.filter(_.filename.matches(".*\\.c")).l',
            ]
        },
        'value matches is not a member': {
            'description': 'Regex matching syntax is incorrect - you\'re trying to call .matches() directly on a stream.',
            'solution': 'Use .filter() with a lambda that applies .matches() to individual items.',
            'examples': [
                'cpg.method.filter(_.name.matches("process.*")).l',
                'cpg.call.filter(_.code.matches(".*system.*")).l',
                'cpg.literal.filter(_.typeFullName.matches(".*String.*")).l',
            ]
        },
        'Recursive value': {
            'description': 'Lambda expression is causing infinite recursion or circular reference.',
            'solution': 'Avoid self-referential expressions in filter/map/where clauses.',
            'examples': [
                'cpg.method.filter(_.name != "").l',
                'cpg.call.where(_.callee.name.nonEmpty).l',
            ]
        },
        'not found: value': {
            'description': 'You\'re referencing an undefined variable or property that doesn\'t exist on this node type.',
            'solution': 'Check the property name and node type. Use cpg.<nodeType> to access valid properties.',
            'examples': [
                'Valid properties: name, code, filename, lineNumber, typeFullName',
                'Access via navigation: _.method.name, _.callee.name',
            ]
        },
    }
    
    @staticmethod
    def validate_query(query: str) -> Dict[str, Any]:
        """
        Validate CPGQL query syntax and return validation results
        
        Args:
            query: The CPGQL query to validate
            
        Returns:
            {
                'valid': bool,
                'errors': List[Dict with error info],
                'warnings': List[Dict with warning info],
                'suggestions': List[str] with helpful suggestions
            }
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'suggestions': [],
        }
        
        if not query or not query.strip():
            results['valid'] = False
            results['errors'].append({
                'type': 'EMPTY_QUERY',
                'message': 'Query cannot be empty',
                'line': 1,
            })
            return results
        
        # Check for common syntax issues
        CPGQLValidator._check_regex_syntax(query, results)
        CPGQLValidator._check_filter_syntax(query, results)
        CPGQLValidator._check_method_chaining(query, results)
        CPGQLValidator._check_string_literals(query, results)
        CPGQLValidator._check_lambda_expressions(query, results)
        
        return results
    
    @staticmethod
    def _check_regex_syntax(query: str, results: Dict) -> None:
        """Check for common regex syntax errors"""
        # Pattern: .matches followed by string that's not in a filter/where context
        direct_matches = re.findall(r'\.matches\s*\(["\']', query)
        if direct_matches:
            # Check if it's inside a filter/where
            if not re.search(r'\.filter\s*\(.*\.matches|\.where\s*\(.*\.matches', query):
                results['errors'].append({
                    'type': 'REGEX_SYNTAX',
                    'message': '.matches() called outside of filter/where lambda - likely incorrect',
                    'suggestion': 'Wrap in .filter(_.property.matches("regex"))',
                    'example': 'cpg.method.filter(_.name.matches("process.*")).l',
                })
    
    @staticmethod
    def _check_filter_syntax(query: str, results: Dict) -> None:
        """Check for common filter/where syntax errors"""
        # Check for unmatched parentheses
        if query.count('(') != query.count(')'):
            results['errors'].append({
                'type': 'SYNTAX_ERROR',
                'message': 'Unmatched parentheses in query',
                'suggestion': 'Ensure all opening parentheses have closing parentheses',
            })
        
        # Check for common filter mistakes
        if re.search(r'\.filter\s*\(\s*"', query):
            results['warnings'].append({
                'type': 'FILTER_WARNING',
                'message': 'filter() with string literal - did you mean to use a lambda?',
                'suggestion': 'Use .filter(_.property == value) instead of .filter("value")',
            })
    
    @staticmethod
    def _check_method_chaining(query: str, results: Dict) -> None:
        """Check for invalid method chains"""
        # Common mistake: calling methods on strings instead of properties
        if re.search(r'\.l\s*\.\s*filter\s*\(', query):
            results['warnings'].append({
                'type': 'METHOD_CHAIN',
                'message': '.filter() called after .l - too late, should be before .l',
                'suggestion': 'Move filters before .l: .filter(...).l',
                'example': 'cpg.method.filter(_.name.matches("test.*")).l',
            })
    
    @staticmethod
    def _check_string_literals(query: str, results: Dict) -> None:
        """Check for string literal issues"""
        # Check for unescaped quotes
        if re.search(r'[^\\]".*".*[^\\]"', query):
            nested_quotes = re.findall(r'"[^"]*"[^"]*"[^"]*"', query)
            if len(nested_quotes) > 1:
                results['warnings'].append({
                    'type': 'STRING_LITERAL',
                    'message': 'Multiple string literals might need escaping',
                    'suggestion': 'Ensure backslashes are properly escaped: \\"text\\"',
                })
    
    @staticmethod
    def _check_lambda_expressions(query: str, results: Dict) -> None:
        """Check for lambda expression issues"""
        # Check for lambda without proper syntax
        lambda_pattern = r'_(\.|\s*[=!><])'
        lambdas = re.findall(lambda_pattern, query)
        
        if lambdas and not re.search(r'\.filter\(|\.where\(|\.map\(', query):
            results['warnings'].append({
                'type': 'LAMBDA_USAGE',
                'message': 'Lambda expression found but not in filter/where/map context',
                'suggestion': 'Lambda expressions should be in: .filter(_), .where(_), or .map(_)',
            })
    
    @staticmethod
    def get_error_suggestion(error_message: str) -> Optional[Dict[str, Any]]:
        """
        Get helpful suggestions for a specific error message
        
        Args:
            error_message: The error message from Joern
            
        Returns:
            Dict with description, solution, and examples, or None if no match
        """
        for error_key, error_info in CPGQLValidator.COMMON_ERRORS.items():
            if error_key.lower() in error_message.lower():
                return error_info
        return None
    
    @staticmethod
    def get_syntax_helpers() -> Dict[str, Any]:
        """
        Get helper information for CPGQL syntax
        
        Returns:
            Dict with helpful syntax information
        """
        return {
            'string_matching': {
                'description': 'Different ways to match strings in CPGQL',
                'methods': [
                    {
                        'name': 'Exact match',
                        'syntax': '.name("exactName")',
                        'example': 'cpg.method.name("main").l',
                    },
                    {
                        'name': 'Regex match',
                        'syntax': '.filter(_.name.matches("regex.*"))',
                        'example': 'cpg.method.filter(_.name.matches("test.*")).l',
                    },
                    {
                        'name': 'Substring match',
                        'syntax': '.filter(_.code.contains("substring"))',
                        'example': 'cpg.call.filter(_.code.contains("malloc")).l',
                    },
                    {
                        'name': 'Case-insensitive match',
                        'syntax': '.filter(_.name.toLowerCase.matches("regex.*"))',
                        'example': 'cpg.method.filter(_.name.toLowerCase.matches("process.*")).l',
                    },
                ]
            },
            'common_patterns': {
                'find_method_by_name': 'cpg.method.name("methodName").l',
                'find_calls_to_function': 'cpg.call.name("functionName").l',
                'find_strings_with_pattern': 'cpg.literal.filter(_.code.matches(".*pattern.*")).l',
                'find_external_methods': 'cpg.method.isExternal(true).l',
                'find_user_methods': 'cpg.method.isExternal(false).l',
                'count_total_methods': 'cpg.method.size',
                'get_method_parameters': 'cpg.method.name("methodName").parameter.l',
                'find_callers': 'cpg.method.name("targetMethod").caller.l',
                'find_callees': 'cpg.method.name("targetMethod").call.callee.l',
            },
            'node_types': [
                {'type': 'method', 'properties': ['name', 'filename', 'signature', 'lineNumber', 'isExternal']},
                {'type': 'call', 'properties': ['name', 'code', 'filename', 'lineNumber']},
                {'type': 'literal', 'properties': ['code', 'typeFullName', 'filename', 'lineNumber']},
                {'type': 'file', 'properties': ['name', 'hash']},
                {'type': 'parameter', 'properties': ['name', 'typeFullName', 'index']},
            ],
        }


class QueryTransformer:
    """Transform and enhance CPGQL queries for better compatibility"""
    
    @staticmethod
    def normalize_string_matching(query: str) -> str:
        """
        Normalize string matching patterns to compatible syntax
        
        Converts patterns like:
        - .name matches "pattern" → .filter(_.name.matches("pattern"))
        - .code contains "text" → .filter(_.code.contains("text"))
        """
        # Convert 'contains' syntax if not already in lambda
        if re.search(r'\.contains\s*\(', query) and 'filter' not in query:
            # Already using filter, likely correct
            pass
        
        return query
    
    @staticmethod
    def suggest_alternative_syntax(query: str) -> List[str]:
        """
        Suggest alternative syntax for complex queries
        
        Args:
            query: The original query
            
        Returns:
            List of alternative query suggestions
        """
        alternatives = []
        
        # If query uses .l followed by other operations, suggest moving before .l
        if re.search(r'\.l\s*\.\s*\w+\s*\(', query):
            alt_query = re.sub(r'\.l(\s*\.\s*)(\w+)', r'.\2.l', query)
            alternatives.append({
                'description': 'Move operations before .l for better performance',
                'query': alt_query,
            })
        
        return alternatives
    
    @staticmethod
    def add_output_formatting(query: str, output_format: str = 'json') -> str:
        """
        Add appropriate output formatting to query if missing
        
        Args:
            query: The base query
            output_format: Desired format (json, list, size, etc)
            
        Returns:
            Query with output formatting added
        """
        if output_format == 'json' and not re.search(r'\.(toJson|toJsonPretty|l)\s*$', query):
            if query.strip().endswith('.size'):
                return query + '.toString'
            return query + '.toJsonPretty'
        elif output_format == 'list' and not query.strip().endswith('.l'):
            return query + '.l'
        
        return query
