"""
HTTP client for communicating with Joern server API
"""

import json
import logging
import time
from typing import Dict, Optional, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class JoernServerClient:
    """Client for Joern server HTTP API with connection pooling"""

    def __init__(self, host: str = "localhost", port: int = 8080, username: Optional[str] = None, password: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Joern server client with connection pooling

        Args:
            host: Server hostname
            port: Server port
            username: Optional authentication username
            password: Optional authentication password
            config: Optional configuration dict with HTTP settings
        """
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.auth = (username, password) if username and password else None
        self.config = config or {}

        # Initialize session with connection pooling
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests Session with connection pooling configuration"""
        session = requests.Session()

        # Get HTTP configuration from config dict (with sensible defaults)
        pool_connections = self.config.get("http_pool_connections", 10)
        pool_maxsize = self.config.get("http_pool_maxsize", 10)
        max_retries = self.config.get("http_max_retries", 3)
        backoff_factor = self.config.get("http_backoff_factor", 0.3)

        # Create retry strategy
        retry_strategy = Retry(
            total=max_retries,
            read=0,  # Do NOT retry on read timeouts
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )

        # Create HTTP adapter with connection pooling
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy
        )

        # Mount adapters for both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set authentication if provided
        if self.auth:
            session.auth = self.auth

        logger.debug(f"Created session with connection pooling: pools={pool_connections}, maxsize={pool_maxsize}, retries={max_retries}")
        return session

    def close(self):
        """Close the session and cleanup connections"""
        if hasattr(self, 'session') and self.session:
            self.session.close()
            logger.debug(f"Closed session for {self.host}:{self.port}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup session"""
        self.close()
        return False

    # Legacy async submission methods removed: use execute_query() for synchronous API

    def check_health(self, timeout: int = 5) -> bool:
        """
        Quick health check to verify the Joern server is responsive.
        
        Args:
            timeout: Maximum time to wait for response (seconds)
            
        Returns:
            True if server is responding, False otherwise
        """
        try:
            response = self.session.get(self.base_url, timeout=timeout)
            return response.status_code in [200, 404]
        except Exception:
            return False

    def execute_query(
        self,
        query: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Execute a query synchronously using the /query-sync endpoint

        Args:
            query: The CPGQL query to execute
            timeout: Maximum time to wait for result (seconds)

        Returns:
            Dictionary with keys: success (bool), stdout (str), stderr (str)
        """
        try:
            url = f"{self.base_url}/query-sync"
            payload = {"query": query}

            logger.debug(f"Executing query synchronously at {url}: {query[:100]}...")

            response = self.session.post(url, json=payload, timeout=timeout)
            
            if response.status_code != 200:
                error_text = response.text
                logger.error(f"Query execution failed: {response.status_code} - {error_text}")
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"HTTP {response.status_code}: {error_text}"
                }
            
            result = response.json()
            
            # The response should have success, stdout, stderr keys
            success = result.get("success", False)
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            
            logger.debug(f"Query executed: success={success}")
            if not success:
                logger.error(f"Query failed: {stderr}")
            
            return {
                "success": success,
                "stdout": stdout,
                "stderr": stderr
            }
            
        except requests.Timeout:
            logger.error(f"Query timeout after {timeout}s: {query[:100]}...")
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Query timeout after {timeout}s. The Joern server may be overloaded. "
                         f"Consider filtering by filename or increasing the timeout."
            }
        except requests.RequestException as e:
            error_str = str(e)
            if "ReadTimeoutError" in error_str or "Read timed out" in error_str:
                logger.error(f"Read timeout after {timeout}s for query: {query[:100]}...")
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Query read timeout after {timeout}s. Large codebase queries (taint analysis, dataflow) "
                             f"may need more time. Try increasing the timeout parameter or filtering by filename."
                }
            logger.error(f"HTTP error executing query: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": f"HTTP error: {str(e)}"
            }
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Error: {str(e)}"
            }

    def load_cpg(self, cpg_path: str, project_name: Optional[str] = None, timeout: int = 600) -> bool:
        """
        Load a CPG file into the Joern server
        
        Args:
            cpg_path: Path to the CPG file to load
            project_name: Optional name to assign to the project
            timeout: Maximum time to wait for loading (seconds, default 600 for large codebases)
            
        Returns:
            True if CPG was loaded successfully, False otherwise
        """
        try:
            # Use importCpg to load pre-built cpg.bin file
            # Use workspace.resett to ensure clean state in the isolated workspace
            # We don't force project name to avoid potential API issues, letting Joern derive it from filename
            query = f'workspace.reset; importCpg("{cpg_path}")'
            logger.info(f"Loading CPG from {cpg_path} (timeout={timeout}s)")
            
            result = self.execute_query(query, timeout=timeout)
            
            if result.get("success"):
                logger.info(f"CPG loaded successfully from {cpg_path}")
                # Verify the CPG is actually loaded by checking method count
                try:
                    verify_query = "cpg.method.isExternal(false).l.size"
                    verify_result = self.execute_query(verify_query, timeout=10)
                    if verify_result.get("success"):
                        stdout = verify_result.get("stdout", "")
                        # Extract the number from the output
                        import re
                        match = re.search(r'= (\d+)', stdout)
                        if match:
                            method_count = int(match.group(1))
                            logger.info(f"CPG verified: {method_count} methods found")
                            return True
                        else:
                            logger.error(f"Could not parse method count from: {stdout}")
                            return False
                    else:
                        logger.error(f"Could not verify CPG: {verify_result.get('stderr')}")
                        return False
                except Exception as e:
                    logger.error(f"Could not verify CPG: {e}")
                    return False
            else:
                error_msg = result.get('stderr', '')
                # Check if error mentions connection issues but might have succeeded
                if "Connection" in error_msg or "reset" in error_msg:
                    logger.warning(f"Connection issue during importCpg, verifying if CPG loaded anyway")
                    try:
                        # Try to verify if CPG is actually there despite connection error
                        verify_query = "cpg.method.isExternal(false).l.size"
                        verify_result = self.execute_query(verify_query, timeout=10)
                        if verify_result.get("success"):
                            logger.info("CPG verification successful - CPG was loaded despite connection error")
                            return True
                    except Exception as verify_error:
                        logger.warning(f"CPG verification failed after connection error: {verify_error}")
                
                logger.error(f"Failed to load CPG from {cpg_path}: {error_msg}")
                return False
                
        except Exception as e:
            logger.error(f"Error loading CPG from {cpg_path}: {e}")
            # Try to verify if CPG might be loaded anyway
            try:
                verify_query = "cpg.method.isExternal(false).l.size"
                verify_result = self.execute_query(verify_query, timeout=10)
                if verify_result.get("success"):
                    logger.info("CPG verification successful - CPG was loaded despite exception")
                    return True
            except Exception as verify_error:
                logger.warning(f"CPG verification failed after exception: {verify_error}")
            return False


