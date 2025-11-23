"""
CPG Generator for creating Code Property Graphs using Joern CLI
"""

import asyncio
import logging
import os
import subprocess
from typing import AsyncIterator, Dict, Optional

from ..exceptions import CPGGenerationError
from ..models import CPGConfig, Config
from .joern_client import JoernServerClient

logger = logging.getLogger(__name__)


class CPGGenerator:
    """Generates CPG from source code using Docker containers"""

    # Language-specific Joern commands (full paths inside container)
    LANGUAGE_COMMANDS = {
        "java": "/opt/joern/joern-cli/javasrc2cpg",
        "c": "/opt/joern/joern-cli/c2cpg.sh",
        "cpp": "/opt/joern/joern-cli/c2cpg.sh",
        "javascript": "/opt/joern/joern-cli/jssrc2cpg.sh",
        "python": "/opt/joern/joern-cli/pysrc2cpg",
        "go": "/opt/joern/joern-cli/gosrc2cpg",
        "kotlin": "/opt/joern/joern-cli/kotlin2cpg",
        "csharp": "/opt/joern/joern-cli/csharpsrc2cpg",
        "ghidra": "/opt/joern/joern-cli/ghidra2cpg",
        "jimple": "/opt/joern/joern-cli/jimple2cpg",
        "php": "/opt/joern/joern-cli/php2cpg",
        "ruby": "/opt/joern/joern-cli/rubysrc2cpg",
        "swift": "/opt/joern/joern-cli/swiftsrc2cpg.sh",
    }

    def __init__(
        self, config: Config, joern_server_manager: Optional['JoernServerManager'] = None, docker_orchestrator=None
    ):
        self.config = config
        self.joern_server_manager = joern_server_manager
        # docker_orchestrator is ignored - we run Joern CLI directly

    def initialize(self):
        """Initialize CPG Generator (no-op in container)"""
        logger.info("CPG Generator initialized (running locally)")

    def generate_cpg(
        self, source_path: str, language: str, cpg_path: str, codebase_hash: str
    ) -> tuple[str, Optional[int]]:
        """Generate CPG from source code using Joern CLI inside Docker container
        
        Args:
            source_path: Host path to source code (e.g., /home/aleks/.../playground/codebases/<hash>/)
            language: Programming language
            cpg_path: Host path where CPG should be stored (e.g., /home/aleks/.../playground/cpgs/<hash>/cpg.bin)
            codebase_hash: The codebase identifier for server management
            
        Returns:
            Tuple of (host path to generated CPG file, joern server port or None)
        """
        try:
            logger.info(f"Starting CPG generation for {source_path} -> {cpg_path}")

            # Get language-specific command
            if language not in self.LANGUAGE_COMMANDS:
                raise CPGGenerationError(f"Unsupported language: {language}")
            
            base_cmd = self.LANGUAGE_COMMANDS[language]
            
            # Create CPG directory on host (we can do this from host)
            cpg_dir = os.path.dirname(cpg_path)
            os.makedirs(cpg_dir, exist_ok=True)
            logger.info(f"CPG directory created: {cpg_dir}")
            
            # Convert host paths to container paths for Joern to use
            # Host path like /home/aleks/.../playground/codebases/hash -> /playground/codebases/hash
            container_source_path = self._host_to_container_path(source_path)
            container_cpg_path = self._host_to_container_path(cpg_path)
            
            logger.info(f"Container paths: src={container_source_path}, cpg={container_cpg_path}")
            
            # Get Java opts from config
            java_opts = self.config.joern.java_opts or "-Xmx2G -Xms512M"
            
            # Build command arguments (base_cmd is already the full path in container)
            cmd_args = [base_cmd, container_source_path, "-o", container_cpg_path]
            
            # Add Java opts as environment variables (Joern scripts read JAVA_OPTS)
            env = os.environ.copy()
            if java_opts:
                env["JAVA_OPTS"] = java_opts
                logger.info(f"Using JAVA_OPTS: {java_opts}")
            
            # Apply exclusions for languages that support them
            if (
                language in self.config.cpg.languages_with_exclusions
                and self.config.cpg.exclusion_patterns
            ):
                combined_regex = "|".join(
                    f"({pattern})" for pattern in self.config.cpg.exclusion_patterns
                )
                cmd_args.extend(["--exclude-regex", combined_regex])

            logger.info(f"Executing CPG generation: {' '.join(cmd_args)}")

            # Execute with timeout (run inside container)
            try:
                result = self._exec_command_sync(cmd_args, env, self.config.cpg.generation_timeout)

                logger.info(f"CPG generation output:\n{result[:2000]}")

                # Check for fatal errors
                if "ERROR:" in result or "Exception" in result:
                    logger.error(f"CPG generation reported fatal errors:\n{result[:2000]}")
                    error_msg = "Joern reported fatal errors during CPG generation"
                    raise CPGGenerationError(error_msg)

                # Validate CPG was created on disk using host path
                if self._validate_cpg(cpg_path):
                    logger.info(f"CPG generation completed: {cpg_path}")
                    
                    # Spawn Joern server and load CPG if manager is available
                    joern_port = None
                    if self.joern_server_manager:
                        try:
                            logger.info(f"Spawning Joern server for codebase {codebase_hash}")
                            joern_port = self.joern_server_manager.spawn_server(codebase_hash)
                            logger.info(f"Joern server spawned successfully on port {joern_port}")
                            
                            logger.info(f"Loading CPG into Joern server on port {joern_port}")
                            if self.joern_server_manager.load_cpg(codebase_hash, cpg_path):
                                logger.info(f"CPG loaded into Joern server successfully on port {joern_port}")
                            else:
                                logger.warning("Failed to load CPG into Joern server")
                                # Don't fail the whole operation, but log the issue
                        except Exception as e:
                            logger.error(f"Failed to setup Joern server for {codebase_hash}: {e}", exc_info=True)
                            # Don't fail the whole operation, but the CPG is still usable
                    else:
                        logger.warning("joern_server_manager is None - cannot spawn Joern server")
                    
                    logger.info(f"Returning CPG path: {cpg_path}, joern_port: {joern_port}")
                    return cpg_path, joern_port
                else:
                    error_msg = "CPG file was not created"
                    logger.error(f"{error_msg}: {result[:2000]}")
                    raise CPGGenerationError(error_msg)

            except asyncio.TimeoutError:
                error_msg = (
                    f"CPG generation timed out after {self.config.cpg.generation_timeout}s"
                )
                logger.error(error_msg)
                raise CPGGenerationError(error_msg)

        except CPGGenerationError:
            raise
        except Exception as e:
            error_msg = f"CPG generation failed: {str(e)}"
            logger.error(error_msg)
            raise CPGGenerationError(error_msg)

    def _host_to_container_path(self, host_path: str) -> str:
        """Convert host path to container path
        
    The container mounts ./playground as /playground
    So /home/aleks/workspace/codebadger/playground/cpgs/hash/cpg.bin 
        becomes /playground/cpgs/hash/cpg.bin
        """
        # Find the playground directory in the path
        if "/playground/" not in host_path:
            logger.warning(f"Path doesn't contain '/playground/': {host_path}")
            return host_path
        
        # Extract everything after /playground/
        parts = host_path.split("/playground/")
        if len(parts) >= 2:
            return f"/playground/{parts[-1]}"
        
        return host_path

    def _exec_command_async(self, cmd_args: list, env: dict) -> str:
        """Execute command synchronously using subprocess"""
        def _exec_sync():
            result = subprocess.run(
                cmd_args,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.config.cpg.generation_timeout
            )
            # Combine stdout and stderr
            output = result.stdout + result.stderr
            return output

        return _exec_sync()

    def _exec_command_sync(self, cmd_args: list, env: dict, timeout: int) -> str:
        """Execute command synchronously INSIDE Docker container with timeout"""
        # Get the container name from environment or use default
        container_name = os.getenv("JOERN_CONTAINER_NAME", "codebadger-joern-server")
        
        # Build docker exec command
        # Format: docker exec -e VAR=value CONTAINER COMMAND
        docker_cmd = ["docker", "exec"]
        
        # Add environment variables BEFORE the container name
        for key, value in env.items():
            if key not in os.environ or env[key] != os.environ[key]:
                docker_cmd.extend(["-e", f"{key}={value}"])
        
        # Container name
        docker_cmd.append(container_name)
        
        # The actual command to run inside container
        docker_cmd.extend(cmd_args)
        
        logger.info(f"Executing in container: {' '.join(docker_cmd)}")
        
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            logger.info(f"Docker exec return code: {result.returncode}")
            
            # Combine stdout and stderr
            output = result.stdout + result.stderr
            if output:
                logger.debug(f"Command output: {output[:500]}")
            
            return output
        except subprocess.TimeoutExpired as e:
            logger.error(f"Docker exec command timed out after {timeout}s")
            raise asyncio.TimeoutError(f"Command timed out after {timeout}s") from e
        except Exception as e:
            logger.error(f"Error executing docker exec: {e}")
            raise

    def _validate_cpg_async(self, cpg_path: str) -> bool:
        """Validate that CPG file was created successfully and is not empty"""
        try:
            # Check if file exists
            if not os.path.exists(cpg_path):
                logger.error(f"CPG file not found: {cpg_path}")
                return False

            # Check file size
            file_size = os.path.getsize(cpg_path)
            min_cpg_size = 1024  # 1KB minimum

            if file_size < min_cpg_size:
                logger.error(
                    f"CPG file is too small ({file_size} bytes), likely empty or corrupted. "
                    f"Minimum expected size: {min_cpg_size} bytes"
                )
                return False

            logger.info(
                f"CPG file created successfully: {cpg_path} (size: {file_size} bytes)"
            )
            return True

        except Exception as e:
            logger.error(f"CPG validation failed: {e}")
            return False

    def _validate_cpg(self, cpg_path: str) -> bool:
        """Validate that CPG file was created successfully and is not empty"""
        try:
            # Check if file exists
            if not os.path.exists(cpg_path):
                logger.error(f"CPG file not found: {cpg_path}")
                return False

            # Check file size
            file_size = os.path.getsize(cpg_path)
            min_cpg_size = 1024  # 1KB minimum

            if file_size < min_cpg_size:
                logger.error(
                    f"CPG file is too small ({file_size} bytes), likely empty or corrupted. "
                    f"Minimum expected size: {min_cpg_size} bytes"
                )
                return False

            logger.info(
                f"CPG file created successfully: {cpg_path} (size: {file_size} bytes)"
            )
            return True

        except Exception as e:
            logger.error(f"CPG validation failed: {e}")
            return False

    def cleanup(self):
        """Cleanup (no-op in container)"""
        logger.info("CPG Generator cleanup (no-op)")
