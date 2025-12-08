"""
Joern Server Manager for spawning and managing individual Joern server instances per CPG
"""

import logging
import time
import os
from typing import Dict, Optional

import docker
from docker.errors import DockerException, NotFound, APIError

from .port_manager import PortManager

logger = logging.getLogger(__name__)


class JoernServerManager:
    """Manages individual Joern server instances running in Docker container using Docker Python API"""

    def __init__(self, joern_binary_path: str = "joern", container_name: str = "codebadger-joern-server"):
        self.joern_binary = joern_binary_path
        self.container_name = container_name
        self.port_manager = PortManager()
        self.docker_client = docker.from_env()
        # _exec_ids will store the exec instance IDs for running joern servers
        self._exec_ids: Dict[str, str] = {}  # codebase_hash -> exec_id or container_id
        self._ports: Dict[str, int] = {}  # codebase_hash -> port

    def spawn_server(self, codebase_hash: str) -> int:
        """
        Spawn a new Joern server instance INSIDE the existing Docker container for the given codebase

        Args:
            codebase_hash: The codebase identifier

        Returns:
            Port number where the server is running (on host, maps to container)
        """
        try:
            # Check if server already exists for THIS codebase
            if codebase_hash in self._ports:
                port = self._ports[codebase_hash]
                if self.is_server_running(codebase_hash):
                    logger.info(f"Joern server for {codebase_hash} already running on port {port}")
                    return port
                else:
                    logger.warning(f"Server for {codebase_hash} registered but not running, cleaning up")
                    self._cleanup_server(codebase_hash)

            # Allocate a port (on host side - maps to container)
            port = self.port_manager.allocate_port(codebase_hash)

            # Get the existing container
            try:
                container = self.docker_client.containers.get(self.container_name)
            except NotFound:
                logger.error(f"Container {self.container_name} not found")
                self.port_manager.release_port(codebase_hash)
                raise RuntimeError(f"Container {self.container_name} not found")

            # Start Joern server inside the existing container using exec
            # Use nohup and background to keep it running
            # IMPORTANT: Run in unique directory to isolate Joern workspace
            work_dir = f"/tmp/joern-server-{codebase_hash}"
            joern_cmd = f"mkdir -p {work_dir} && cd {work_dir} && nohup /opt/joern/joern-cli/joern --server --server-host 0.0.0.0 --server-port {port} > /tmp/joern-{codebase_hash}.log 2>&1 &"
            
            logger.info(f"Starting Joern server for {codebase_hash} on port {port} inside container {self.container_name}")
            logger.debug(f"Command: bash -c '{joern_cmd}'")

            # Execute the command in the container
            exec_result = container.exec_run(
                cmd=["bash", "-c", joern_cmd],
                detach=True,  # Run in background
                stream=False
            )

            # Store exec info
            self._exec_ids[codebase_hash] = f"exec-{codebase_hash}"
            self._ports[codebase_hash] = port

            logger.info(f"Joern server command executed, waiting for server to be ready on port {port}...")

            # Wait for server to start
            if self._wait_for_server(port, timeout=60):
                logger.info(f"Joern server for {codebase_hash} started successfully on port {port}")
                return port
            else:
                # Cleanup on failure - check logs
                logger.error(f"Joern server for {codebase_hash} failed to become ready on port {port}")
                try:
                    log_result = container.exec_run(
                        cmd=["cat", f"/tmp/joern-{codebase_hash}.log"],
                        stream=False
                    )
                    if log_result.exit_code == 0:
                        logger.error(f"Joern server log:\n{log_result.output.decode('utf-8')}")
                except Exception as log_error:
                    logger.warning(f"Could not read log file: {log_error}")
                
                self._cleanup_server(codebase_hash)
                raise RuntimeError(f"Joern server for {codebase_hash} failed to start on port {port}")

        except DockerException as e:
            logger.error(f"Docker error while spawning Joern server for {codebase_hash}: {e}", exc_info=True)
            self._cleanup_server(codebase_hash)
            raise
        except Exception as e:
            logger.error(f"Failed to spawn Joern server for {codebase_hash}: {e}", exc_info=True)
            self._cleanup_server(codebase_hash)
            raise

    def load_cpg(self, codebase_hash: str, cpg_path: str, timeout: int = 120) -> bool:
        """
        Load a CPG into the Joern server for the given codebase

        Args:
            codebase_hash: The codebase identifier
            cpg_path: Path to the CPG file
            timeout: Timeout for loading operation

        Returns:
            True if CPG was loaded successfully
        """
        try:
            if codebase_hash not in self._ports:
                raise RuntimeError(f"No Joern server running for codebase {codebase_hash}")

            port = self._ports[codebase_hash]

            # Use JoernServerClient to load the CPG
            from .joern_client import JoernServerClient
            client = JoernServerClient(host="localhost", port=port)

            # Convert host path to container path for Joern running in Docker
            # Host path like /home/aleks/.../playground/cpgs/hash/cpg.bin -> /playground/cpgs/hash/cpg.bin
            container_cpg_path = cpg_path
            if "/playground/" in cpg_path:
                parts = cpg_path.split("/playground/")
                if len(parts) >= 2:
                    container_cpg_path = f"/playground/{parts[-1]}"
            
            logger.info(f"Loading CPG {cpg_path} (container: {container_cpg_path}) into Joern server for {codebase_hash} (port {port})")
            
            # Retry loading with exponential backoff
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # Pass the container path to the client with explicit project name
                    success = client.load_cpg(container_cpg_path, project_name=codebase_hash, timeout=timeout)
                    if success:
                        logger.info(f"CPG loaded successfully for {codebase_hash}")
                        return True
                    else:
                        logger.warning(f"CPG load attempt {attempt + 1}/{max_retries} failed for {codebase_hash}")
                        if attempt < max_retries - 1:
                            wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                            logger.info(f"Waiting {wait_time}s before retry...")
                            time.sleep(wait_time)
                except Exception as e:
                    logger.warning(f"CPG load attempt {attempt + 1}/{max_retries} error: {e}")
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        logger.info(f"Waiting {wait_time}s before retry...")
                        time.sleep(wait_time)
                    else:
                        raise
            
            logger.error(f"Failed to load CPG for {codebase_hash} after {max_retries} attempts")
            return False

        except Exception as e:
            logger.error(f"Error loading CPG for {codebase_hash}: {e}")
            return False

    def get_server_port(self, codebase_hash: str) -> Optional[int]:
        """
        Get the port for the Joern server of the given codebase

        Args:
            codebase_hash: The codebase identifier

        Returns:
            Port number or None if no server is running
        """
        return self._ports.get(codebase_hash)

    def is_server_running(self, codebase_hash: str) -> bool:
        """
        Check if the Joern server for the given codebase is running by checking port connectivity

        Args:
            codebase_hash: The codebase identifier

        Returns:
            True if server is running
        """
        if codebase_hash not in self._ports:
            return False

        port = self._ports[codebase_hash]
        
        # Check if we can connect to the port
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def terminate_server(self, codebase_hash: str) -> bool:
        """
        Terminate the Joern server for the given codebase

        Args:
            codebase_hash: The codebase identifier

        Returns:
            True if server was terminated successfully
        """
        try:
            if codebase_hash not in self._exec_ids:
                logger.warning(f"No server found for codebase {codebase_hash}")
                return False

            port = self._ports.get(codebase_hash)
            logger.info(f"Terminating Joern server for {codebase_hash} on port {port}")

            # Kill the Joern process inside the container
            try:
                container = self.docker_client.containers.get(self.container_name)
                # Find and kill the joern process on this port
                kill_cmd = f"pkill -f 'joern.*--server-port {port}' || true"
                container.exec_run(cmd=["bash", "-c", kill_cmd])
                logger.info(f"Killed Joern server process for {codebase_hash}")
            except Exception as e:
                logger.warning(f"Error killing Joern process: {e}")

            # Cleanup internal state and release port
            self._cleanup_server(codebase_hash)
            return True

        except Exception as e:
            logger.error(f"Error terminating Joern server for {codebase_hash}: {e}")
            return False

    def terminate_all_servers(self) -> None:
        """Terminate all running Joern servers"""
        logger.info("Terminating all Joern servers")
        codebases = list(self._processes.keys())
        for codebase_hash in codebases:
            self.terminate_server(codebase_hash)
        logger.info("All Joern servers terminated")

    def get_running_servers(self) -> Dict[str, int]:
        """Get information about all running servers"""
        return {
            codebase_hash: port
            for codebase_hash, port in self._ports.items()
            if self.is_server_running(codebase_hash)
        }

    def _wait_for_server(self, port: int, timeout: int = 30) -> bool:
        """Wait for Joern server to be ready on the given port"""
        import socket

        start_time = time.time()
        server_responding = False
        
        while time.time() - start_time < timeout:
            try:
                # Try to connect to the port
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                sock.close()

                if result == 0:
                    # Server port is open, now check HTTP
                    try:
                        import requests
                        response = requests.get(f"http://localhost:{port}", timeout=2)
                        # Server responds (even 404 is OK - means it's up)
                        if response.status_code in [200, 404]:
                            server_responding = True
                            # Wait a bit more for Joern to fully initialize
                            logger.debug(f"Server responding on port {port}, waiting for full initialization...")
                            time.sleep(3)  # Give Joern more time to initialize
                            return True
                    except Exception as e:
                        logger.debug(f"HTTP check failed: {e}")
                        pass

            except Exception as e:
                logger.debug(f"Connection check failed: {e}")
                pass

            time.sleep(1)

        return server_responding

    def _cleanup_server(self, codebase_hash: str) -> None:
        """Clean up server resources"""
        if codebase_hash in self._exec_ids:
            del self._exec_ids[codebase_hash]
        if codebase_hash in self._ports:
            port = self._ports[codebase_hash]
            self.port_manager.release_port(codebase_hash)
            del self._ports[codebase_hash]
            logger.debug(f"Cleaned up resources for {codebase_hash} (port {port})")