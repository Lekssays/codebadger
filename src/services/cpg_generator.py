"""
CPG Generator for creating Code Property Graphs using Joern CLI
"""

import asyncio
import logging
import os
import re
import subprocess
from typing import AsyncIterator, Dict, Optional

from ..defaults import LANGUAGE_COMMANDS
from ..exceptions import CPGGenerationError
from ..models import CPGConfig, Config
from ..telemetry import get_tracer
from .joern_client import JoernServerClient

logger = logging.getLogger(__name__)
tracer = get_tracer()


class CPGGenerator:
    """Generates CPG from source code using Docker containers"""

    LANGUAGE_COMMANDS = LANGUAGE_COMMANDS

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
        with tracer.start_as_current_span("cpg.generate") as span:
            span.set_attribute("cpg.language", language)
            span.set_attribute("cpg.codebase_hash", codebase_hash)
            span.set_attribute("cpg.source_path", source_path)

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

                # Validate repository size before CPG generation
                repo_size_mb = self._calculate_repo_size_mb(source_path)
                max_size_mb = self.config.cpg.max_repo_size_mb
                span.set_attribute("cpg.repo_size_mb", repo_size_mb)
                logger.info(f"Repository size: {repo_size_mb}MB, max allowed: {max_size_mb}MB")

                if repo_size_mb > max_size_mb:
                    error_msg = (
                        f"Repository size ({repo_size_mb}MB) exceeds maximum allowed "
                        f"({max_size_mb}MB). Please reduce the repository size or increase "
                        f"the max_repo_size_mb configuration."
                    )
                    logger.error(error_msg)
                    raise CPGGenerationError(error_msg)

                # Convert host paths to container paths for Joern to use
                # Host path like /home/aleks/.../playground/codebases/hash -> /playground/codebases/hash
                container_source_path = self._host_to_container_path(source_path)
                container_cpg_path = self._host_to_container_path(cpg_path)

                logger.info(f"Container paths: src={container_source_path}, cpg={container_cpg_path}")

                # Size the build JVM from CPG_BUILD_HEAP_GB. The frontend (c2cpg)
                # and the overlay pass both run here in the build container; the
                # dataflow overlay (ReachingDefPass) is memory-heavy on real C/C++
                # trees, so the small default -Xmx would OOM it. build_heap_gb is
                # budgeted against JOERN_MEM_LIMIT (build_workers * build_heap_gb).
                build_heap_gb = max(1, int(self.config.cpg.build_heap_gb or 4))
                java_opts = (
                    f"-Xmx{build_heap_gb}G -Xms2G -XX:+UseG1GC "
                    f"-XX:+UseStringDeduplication -Dfile.encoding=UTF-8"
                )

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
                    # Escape special regex characters in patterns and combine with OR
                    escaped_patterns = [self._escape_regex_pattern(p) for p in self.config.cpg.exclusion_patterns]
                    combined_regex = "|".join(f"({p})" for p in escaped_patterns)
                    cmd_args.extend(["--exclude-regex", combined_regex])
                    logger.info(f"Applied {len(self.config.cpg.exclusion_patterns)} exclusion patterns")

                logger.info(f"Executing CPG generation: {' '.join(cmd_args)}")

                # Execute with timeout (run inside container)
                try:
                    with tracer.start_as_current_span("cpg.joern_cli_exec") as exec_span:
                        exec_span.set_attribute("cpg.command", base_cmd)
                        result = self._exec_command_sync(cmd_args, env, self.config.cpg.generation_timeout)

                    truncation_length = self.config.cpg.output_truncation_length
                    logger.info(f"CPG generation output:\n{result[:truncation_length]}")

                    # Check for fatal errors
                    if "ERROR:" in result or "Exception" in result:
                        truncation_length = self.config.cpg.output_truncation_length
                        logger.error(f"CPG generation reported fatal errors:\n{result[:truncation_length]}")
                        error_msg = "Joern reported fatal errors during CPG generation"
                        raise CPGGenerationError(error_msg)

                    # Validate CPG was created on disk using host path
                    if self._validate_cpg(cpg_path):
                        logger.info(f"CPG generation completed: {cpg_path}")

                        # Persist the dataflow overlay INTO the cpg.bin now, in the
                        # build container (large heap). Otherwise importCpg recomputes
                        # ReachingDefPass on every load, which OOMs the memory-capped
                        # query workers -> "No projects loaded". Best-effort: on
                        # failure we keep the base CPG and let the worker try.
                        self._apply_overlays(container_cpg_path, codebase_hash, build_heap_gb)

                        # Spawn Joern server and load CPG if manager is available
                        joern_port = None
                        if self.joern_server_manager:
                            try:
                                with tracer.start_as_current_span("cpg.spawn_server") as srv_span:
                                    logger.info(f"Spawning Joern server for codebase {codebase_hash}")
                                    joern_port = self.joern_server_manager.spawn_server(codebase_hash)
                                    srv_span.set_attribute("cpg.joern_port", joern_port)
                                    logger.info(f"Joern server spawned successfully on port {joern_port}")

                                with tracer.start_as_current_span("cpg.load_cpg"):
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
                        truncation_length = self.config.cpg.output_truncation_length
                        logger.error(f"{error_msg}: {result[:truncation_length]}")
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

    def _calculate_repo_size_mb(self, source_path: str) -> int:
        """Calculate total repository size in MB

        Args:
            source_path: Path to the repository directory

        Returns:
            Size in MB
        """
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(source_path):
                # Skip .git directories and other common exclusions for size calculation
                dirnames[:] = [d for d in dirnames if d not in {'.git', '.svn', '.hg', '.idea', '.vscode', 'node_modules'}]

                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except OSError as e:
                        logger.warning(f"Failed to get size of {filepath}: {e}")

            size_mb = total_size / (1024 * 1024)
            return int(size_mb)
        except Exception as e:
            logger.error(f"Failed to calculate repository size: {e}")
            raise CPGGenerationError(f"Failed to calculate repository size: {e}")

    def _escape_regex_pattern(self, pattern: str) -> str:
        """Escape special regex characters while preserving regex patterns

        Args:
            pattern: The pattern that may contain regex

        Returns:
            Escaped pattern safe for use in regex
        """
        # Don't escape regex metacharacters that are likely intentional
        # Just validate the pattern is valid regex
        try:
            re.compile(pattern)
            return pattern
        except re.error as e:
            logger.warning(f"Invalid regex pattern '{pattern}': {e}. Using literal match.")
            # If regex is invalid, escape it for literal matching
            return re.escape(pattern)

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

    def _apply_overlays(self, container_cpg_path: str, codebase_hash: str, heap_gb: int) -> bool:
        """Apply and persist Joern's default overlays (incl. OSS dataflow) into the
        cpg.bin, in the build container where a large heap is available.

        importCpg applies the dataflow overlay (ReachingDefPass) the first time a CPG
        is opened and re-saves it INTO the project's cpg.bin. By doing that once here
        — instead of on every load in a memory-capped query worker — later importCpg
        calls print "Overlay dataflowOss already exists - skipping" and just
        deserialize, so even a tiny tier-S (2 GB) worker loads a large CPG reliably.

        Best-effort: returns True on success; on any failure logs and leaves the base
        CPG untouched (the worker falls back to the old recompute-on-load behavior).
        """
        # codebase_hash is validated upstream as [0-9a-f]{16}; the cpg path is derived
        # from it, so these interpolations carry no untrusted input.
        cpg_dir = container_cpg_path.rsplit("/", 1)[0]
        script = (
            "set -euo pipefail; "
            f'SRC="{container_cpg_path}"; WS="{cpg_dir}/_ovlws"; '
            'rm -rf "$WS"; mkdir -p "$WS"; cd "$WS"; '
            'printf \'importCpg("%s", "ovl")\\n\' "$SRC" > ovl.sc; '
            "/opt/joern/joern-cli/joern --script ovl.sc; "
            # The overlaid project cpg lands under the per-hash workspace; promote it.
            "OUT=\"$(find \"$WS\" -name cpg.bin -printf '%s\\t%p\\n' | sort -rn | head -1 | cut -f2)\"; "
            'if [ -z "$OUT" ] || [ ! -f "$OUT" ]; then echo OVERLAY_NO_OUTPUT; rm -rf "$WS"; exit 3; fi; '
            'mv -f "$OUT" "$SRC"; rm -rf "$WS"; '
            'echo "OVERLAY_OK bytes=$(stat -c %s "$SRC")"'
        )
        env = os.environ.copy()
        env["JAVA_OPTS"] = (
            f"-Xmx{heap_gb}G -Xms2G -XX:+UseG1GC -XX:+UseStringDeduplication -Dfile.encoding=UTF-8"
        )
        container_name = os.getenv("JOERN_CONTAINER_NAME", "codebadger-joern-server")
        docker_cmd = ["docker", "exec"]
        for key, value in env.items():
            if key not in os.environ or env[key] != os.environ[key]:
                docker_cmd.extend(["-e", f"{key}={value}"])
        docker_cmd.append(container_name)
        docker_cmd.extend(["bash", "-lc", script])

        logger.info(f"Applying+persisting overlays for {codebase_hash} (heap {heap_gb}G)")
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.cpg.generation_timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                f"Overlay persistence timed out for {codebase_hash}; keeping base CPG "
                f"(worker will recompute overlays on load)"
            )
            self._cleanup_overlay_workspace(cpg_dir)
            return False
        except Exception as e:
            logger.warning(f"Overlay persistence error for {codebase_hash}: {e}; keeping base CPG")
            self._cleanup_overlay_workspace(cpg_dir)
            return False

        if result.returncode == 0 and "OVERLAY_OK" in (result.stdout + result.stderr):
            logger.info(f"Overlays persisted for {codebase_hash}: {result.stdout.strip().splitlines()[-1:]}")
            return True

        tail = (result.stdout + result.stderr)[-1000:]
        logger.warning(
            f"Overlay persistence failed for {codebase_hash} (rc={result.returncode}); "
            f"keeping base CPG. Output tail: {tail}"
        )
        self._cleanup_overlay_workspace(cpg_dir)
        return False

    def _cleanup_overlay_workspace(self, cpg_dir: str) -> None:
        """Remove a leftover overlay workspace so a failed run can't strand disk."""
        container_name = os.getenv("JOERN_CONTAINER_NAME", "codebadger-joern-server")
        try:
            subprocess.run(
                ["docker", "exec", container_name, "rm", "-rf", f"{cpg_dir}/_ovlws"],
                capture_output=True, text=True, timeout=60,
            )
        except Exception:
            pass

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

    def _validate_cpg(self, cpg_path: str) -> bool:
        """Validate that CPG file was created successfully and is not empty"""
        try:
            # Check if file exists
            if not os.path.exists(cpg_path):
                logger.error(f"CPG file not found: {cpg_path}")
                return False

            # Check file size
            file_size = os.path.getsize(cpg_path)
            min_cpg_size = self.config.cpg.min_cpg_file_size

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
