"""
HTTP client for communicating with Joern server API
"""

import json
import logging
import time
from typing import Dict, Optional, Any

import requests

logger = logging.getLogger(__name__)


class JoernServerClient:
    """Client for Joern server HTTP API"""

    def __init__(self, host: str = "localhost", port: int = 8080, username: Optional[str] = None, password: Optional[str] = None):
        """
        Initialize Joern server client
        
        Args:
            host: Server hostname
            port: Server port
            username: Optional authentication username
            password: Optional authentication password
        """
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.auth = (username, password) if username and password else None

    # Legacy async submission methods removed: use execute_query() for synchronous API

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
            
            response = requests.post(url, json=payload, timeout=timeout, auth=self.auth)
            
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
            logger.error(f"Query timeout after {timeout}s")
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Query timeout after {timeout}s"
            }
        except requests.RequestException as e:
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

    def load_cpg(self, cpg_path: str, project_name: Optional[str] = None, timeout: int = 120) -> bool:
        """
        Load a CPG file into the Joern server
        
        Args:
            cpg_path: Path to the CPG file to load
            project_name: Optional name to assign to the project
            timeout: Maximum time to wait for loading (seconds)
            
        Returns:
            True if CPG was loaded successfully, False otherwise
        """
        try:
            # Use importCpg to load pre-built cpg.bin file
            # Use workspace.resett to ensure clean state in the isolated workspace
            # We don't force project name to avoid potential API issues, letting Joern derive it from filename
            query = f'workspace.reset; importCpg("{cpg_path}")'
            logger.info(f"Loading CPG from {cpg_path}")
            
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
                    except:
                        pass
                
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
            except:
                pass
            return False


