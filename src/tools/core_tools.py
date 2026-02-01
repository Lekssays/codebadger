"""
Core MCP Tools for CodeBadger Server - Simplified hash-based version

Provides core CPG management functionality
"""

import docker
import hashlib
import io
import logging
import os
import shutil
import tarfile
from typing import Any, Dict, Optional, Annotated
from pydantic import Field

from ..exceptions import ValidationError
from ..models import CodebaseInfo
from ..utils.validators import (
    validate_github_url,
    validate_language,
    validate_local_path,
    validate_source_type,
    resolve_host_path,
)

logger = logging.getLogger(__name__)


def get_cpg_cache_key(source_type: str, source_path: str, language: str) -> str:
    """
    Generate a deterministic CPG cache key based on source type, path, and language.
    """
    if source_type == "github":
        # Extract owner/repo from GitHub URL
        if "github.com/" in source_path:
            parts = source_path.split("github.com/")[-1].split("/")
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1].replace(".git", "")
                identifier = f"github:{owner}/{repo}:{language}"
            else:
                identifier = f"github:{source_path}:{language}"
        else:
            identifier = f"github:{source_path}:{language}"
    else:
        # For local paths, use absolute path
        source_path = os.path.abspath(source_path)
        identifier = f"local:{source_path}:{language}"

    hash_digest = hashlib.sha256(identifier.encode()).hexdigest()[:16]
    return hash_digest


def get_cpg_cache_path(cache_key: str, playground_path: str) -> str:
    """
    Generate the CPG cache file path for a given cache key and playground path.
    """
    return os.path.join(playground_path, "cpgs", cache_key, "cpg.bin")


async def _generate_cpg_async(
    codebase_hash: str,
    codebase_dir: str,
    cpg_path: str,
    language: str,
    container_cpg_path: str,
    services: dict
):
    """Async task to generate CPG and start Joern server"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"Starting async CPG generation for {codebase_hash}")
        
        # Get services
        codebase_tracker = services["codebase_tracker"]
        joern_server_manager = services.get("joern_server_manager")
        
        # Use Docker API to generate CPG inside container
        docker_client = docker.from_env()
        container = docker_client.containers.get("codebadger-joern-server")
        
        # Get language-specific command
        language_commands = {
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
        
        cmd_binary = language_commands.get(language)
        if not cmd_binary:
            raise ValueError(f"Unsupported language: {language}")
        
        # Build command
        cmd = [cmd_binary, f"/playground/codebases/{codebase_hash}", "-o", container_cpg_path]
        
        logger.info(f"Executing CPG generation in container: {' '.join(cmd)}")
        
        # Execute CPG generation
        exec_result = container.exec_run(cmd=cmd, stream=False)
        
        if exec_result.exit_code != 0:
            error_msg = f"CPG generation failed: {exec_result.output.decode('utf-8')}"
            logger.error(error_msg)
            codebase_tracker.update_codebase(
                codebase_hash=codebase_hash,
                metadata={"status": "failed", "error": error_msg}
            )
            return
        
        logger.info(f"CPG generated successfully: {cpg_path}")
        
        # Step 4: Start Joern server with randomly assigned port (2000-2999)
        joern_port = None
        if joern_server_manager:
            try:
                logger.info(f"Spawning Joern server for {codebase_hash}")
                joern_port = joern_server_manager.spawn_server(codebase_hash)
                logger.info(f"Joern server started on port {joern_port}")
                
                # Load CPG into server (use container path, not host path)
                if joern_server_manager.load_cpg(codebase_hash, container_cpg_path):
                    logger.info(f"CPG loaded into Joern server on port {joern_port}")
                else:
                    logger.warning("Failed to load CPG into Joern server")
            except Exception as e:
                logger.error(f"Failed to start Joern server: {e}", exc_info=True)
        
        # Update DB with final metadata (preserving container paths)
        codebase_tracker.update_codebase(
            codebase_hash=codebase_hash,
            cpg_path=cpg_path,
            joern_port=joern_port,
            metadata={
                "status": "ready",
                "container_codebase_path": f"/playground/codebases/{codebase_hash}",
                "container_cpg_path": container_cpg_path
            }
        )
        
        logger.info(f"CPG generation complete for {codebase_hash}, port: {joern_port}")

        # Trigger cache warm-up
        if "code_browsing_service" in services:
            logger.info(f"Starting cache warm-up for {codebase_hash}")
            try:
                import asyncio
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, services["code_browsing_service"].warm_up_cache, codebase_hash)
                logger.info(f"Cache warm-up complete for {codebase_hash}")
            except Exception as e:
                logger.error(f"Cache warm-up failed for {codebase_hash}: {e}")
        
    except Exception as e:
        logger.error(f"Error in async CPG generation for {codebase_hash}: {e}", exc_info=True)
        try:
            codebase_tracker = services["codebase_tracker"]
            codebase_tracker.update_codebase(
                codebase_hash=codebase_hash,
                metadata={"status": "failed", "error": str(e)}
            )
        except:
            pass


def register_core_tools(mcp, services: dict):
    """Register core MCP tools with the FastMCP server"""

    @mcp.tool(
        description="""Generate a Code Property Graph (CPG) for a codebase.

This tool initiates the analysis process by generating a CPG for the specified codebase.
For GitHub repositories, it clones the repo first. For local paths, it copies the source code.
The CPG is cached by a hash of the codebase.

Args:
    source_type: Either 'local' or 'github'.
    source_path: Absolute path (local) or full GitHub URL.
    language: Programming language (java, c, cpp, python, javascript, go, etc.).
    github_token: Optional PAT for private repos.
    branch: Optional specific git branch.

Returns:
    {
        "codebase_hash": "hash of the codebase",
        "status": "ready" | "generating" | "cached",
        "message": "Status message",
        "cpg_path": "path to CPG file"
    }

Notes:
    - This is an async operation. Use get_cpg_status to check progress.
    - Large codebases may take several minutes to analyze.
    - Supported languages: c, cpp, java, javascript, python, go, kotlin, csharp, php, ruby, swift.

Examples:
    generate_cpg(
        source_type="github",
        source_path="https://github.com/joernio/sample-repo",
        language="java"
    )"""
    )
    async def generate_cpg(
        source_type: Annotated[str, Field(description="Either 'local' or 'github'")],
        source_path: Annotated[str, Field(description="For local: absolute path to source directory. For github: full GitHub URL (e.g., https://github.com/user/repo)")],
        language: Annotated[str, Field(description="Programming language - one of: java, c, cpp, javascript, python, go, kotlin, csharp, ghidra, jimple, php, ruby, swift")],
        github_token: Annotated[Optional[str], Field(description="GitHub Personal Access Token for private repositories (optional)")] = None,
        branch: Annotated[Optional[str], Field(description="Specific git branch to checkout (optional, defaults to default branch)")] = None,
    ) -> Dict[str, Any]:
        """Create a Code Property Graph from source code for analysis."""
        try:
            # Validate inputs
            validate_source_type(source_type)
            validate_language(language)

            codebase_tracker = services["codebase_tracker"]

            # Generate CPG cache key (codebase_hash)
            codebase_hash = get_cpg_cache_key(source_type, source_path, language)
            logger.info(f"Processing codebase with hash: {codebase_hash}")

            # Check if codebase already exists in DB
            existing_codebase = codebase_tracker.get_codebase(codebase_hash)
            if existing_codebase and existing_codebase.cpg_path and os.path.exists(existing_codebase.cpg_path):
                logger.info(f"Found existing codebase in DB: {codebase_hash}")
                
                # Check if Joern server is still running
                joern_server_manager = services.get("joern_server_manager")
                joern_port = existing_codebase.joern_port
                
                if joern_server_manager:
                    # If we have a port recorded, check if it's actually running
                    if joern_port and not joern_server_manager.is_server_running(codebase_hash):
                        logger.info(f"Joern server recorded on port {joern_port} but not running for {codebase_hash}")
                        joern_port = None # Reset port since it's not running
                    
                    # If not running (or wasn't running), start it
                    if not joern_port:
                        logger.info(f"Starting Joern server for existing codebase {codebase_hash}")
                        try:
                            # Start server
                            joern_port = joern_server_manager.spawn_server(codebase_hash)
                            
                            # Load CPG
                            container_cpg_path = existing_codebase.metadata.get("container_cpg_path")
                            if not container_cpg_path:
                                # Fallback if not in metadata
                                container_cpg_path = f"/playground/cpgs/{codebase_hash}/cpg.bin"
                                
                            joern_server_manager.load_cpg(codebase_hash, container_cpg_path)
                            
                            # Update port in DB
                            codebase_tracker.update_codebase(codebase_hash, joern_port=joern_port)
                            logger.info(f"Joern server started on port {joern_port}")
                        except Exception as e:
                            logger.warning(f"Failed to start Joern server: {e}")
                
                return {
                    "codebase_hash": codebase_hash,
                    "status": "ready",
                    "message": "CPG already exists",
                    "cpg_path": existing_codebase.cpg_path,
                    "joern_port": joern_port,
                    "source_type": existing_codebase.source_type,
                    "source_path": existing_codebase.source_path,
                    "language": existing_codebase.language,
                }

            # Get services
            git_manager = services["git_manager"]
            
            # Get playground path (absolute)
            playground_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "playground")
            )

            # Step 1 & 2: Prepare source code - copy local path or clone repo
            codebase_dir = os.path.join(playground_path, "codebases", codebase_hash)
            container_codebase_path = f"/playground/codebases/{codebase_hash}"
            
            logger.info(f"Preparing source code for {codebase_hash}")
            
            # Store repository URL if git
            repository_url = source_path if source_type == "github" else None
            
            if source_type == "github":
                validate_github_url(source_path)
                
                # Clone to playground/codebases/<hash>
                if not os.path.exists(codebase_dir):
                    os.makedirs(codebase_dir, exist_ok=True)
                    git_manager.clone_repository(
                        repo_url=source_path,
                        target_path=codebase_dir,
                        branch=branch,
                        token=github_token,
                    )
                    logger.info(f"Cloned repository to {codebase_dir}")
                else:
                    logger.info(f"Using existing cloned repository at {codebase_dir}")
            else:
                # Local path - copy to playground/codebases/<hash>
                host_path = resolve_host_path(source_path)
                
                if not os.path.exists(codebase_dir):
                    os.makedirs(codebase_dir, exist_ok=True)
                    logger.info(f"Copying source from {host_path} to {codebase_dir}")
                    
                    try:
                        for item in os.listdir(host_path):
                            src_item = os.path.join(host_path, item)
                            dst_item = os.path.join(codebase_dir, item)
                            
                            if os.path.isdir(src_item):
                                shutil.copytree(src_item, dst_item, dirs_exist_ok=True)
                            else:
                                shutil.copy2(src_item, dst_item)
                        logger.info(f"Source copied successfully to {codebase_dir}")
                    except OSError as e:
                        raise ValidationError(f"Failed to copy from {host_path}: {e}")
                else:
                    logger.info(f"Using existing source at {codebase_dir}")

            # Step 3: Create CPG directory
            cpg_dir = os.path.join(playground_path, "cpgs", codebase_hash)
            cpg_path = os.path.join(cpg_dir, "cpg.bin")
            container_cpg_path = f"/playground/cpgs/{codebase_hash}/cpg.bin"
            os.makedirs(cpg_dir, exist_ok=True)
            logger.info(f"CPG directory ready: {cpg_dir}")

            # Step 5: Store initial metadata in DB (before CPG generation)
            codebase_tracker.save_codebase(
                codebase_hash=codebase_hash,
                source_type=source_type,
                source_path=source_path,
                language=language,
                cpg_path=None,  # Will be updated after generation
                joern_port=None,  # Will be updated after server starts
                metadata={
                    "container_codebase_path": container_codebase_path,
                    "container_cpg_path": container_cpg_path,
                    "repository": repository_url,
                    "status": "generating"
                }
            )

            # Start async CPG generation task
            import asyncio
            asyncio.create_task(
                _generate_cpg_async(
                    codebase_hash=codebase_hash,
                    codebase_dir=codebase_dir,
                    cpg_path=cpg_path,
                    language=language,
                    container_cpg_path=container_cpg_path,
                    services=services
                )
            )

            # Return immediately with generating status
            return {
                "codebase_hash": codebase_hash,
                "status": "generating",
                "message": "CPG generation started. Use get_cpg_status to check progress.",
                "source_type": source_type,
                "source_path": source_path,
                "language": language,
            }

        except ValidationError as e:
            logger.error(f"Validation error: {e}")
            return {
                "success": False,
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Failed to generate CPG: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }

    @mcp.tool(
        description="""Get the status of a CPG generation or check if CPG exists.

Check if the analysis for a given codebase hash is complete and the CPG is ready.
Also retrieves the connection port for the Joern server if running.

Args:
    codebase_hash: The unique hash identifier returned by generate_cpg.

Returns:
    {
        "codebase_hash": "hash",
        "status": "ready" | "generating" | "failed" | "not_found",
        "cpg_path": "path to CPG if exists",
        "joern_port": port number or null,
        "language": "programming language"
    }

Notes:
    - If status is 'ready', the CPG is available for queries.
    - If status is 'generating', wait and retry.

Examples:
    get_cpg_status(codebase_hash="abc123456789")"""
    )
    def get_cpg_status(
        codebase_hash: Annotated[str, Field(description="The hash identifier of the codebase")]
    ) -> Dict[str, Any]:
        """Check CPG generation status or verify if a CPG exists and is ready."""
        try:
            codebase_tracker = services["codebase_tracker"]
            
            # Step 6: If codebase exists in DB, return metadata
            codebase_info = codebase_tracker.get_codebase(codebase_hash)
            
            if not codebase_info:
                return {
                    "codebase_hash": codebase_hash,
                    "status": "not_found",
                    "message": "Codebase not found. Please generate CPG first.",
                }
            
            # Get status from metadata
            status = codebase_info.metadata.get("status", "unknown")
            if status == "unknown" and codebase_info.cpg_path and os.path.exists(codebase_info.cpg_path):
                status = "ready"
            
            # Ensure Joern server is running if status is ready
            joern_port = codebase_info.joern_port
            if status == "ready":
                joern_server_manager = services.get("joern_server_manager")
                if joern_server_manager:
                    # Check if running
                    is_running = False
                    if joern_port:
                        is_running = joern_server_manager.is_server_running(codebase_hash)
                    
                    if not is_running:
                        logger.info(f"Joern server not running for ready codebase {codebase_hash}, starting it...")
                        try:
                            # Start server
                            joern_port = joern_server_manager.spawn_server(codebase_hash)
                            
                            # Load CPG
                            container_cpg_path = codebase_info.metadata.get("container_cpg_path")
                            if not container_cpg_path:
                                container_cpg_path = f"/playground/cpgs/{codebase_hash}/cpg.bin"
                                
                            joern_server_manager.load_cpg(codebase_hash, container_cpg_path)
                            
                            # Update port in DB
                            codebase_tracker.update_codebase(codebase_hash, joern_port=joern_port)
                            logger.info(f"Joern server started on port {joern_port}")
                        except Exception as e:
                            logger.warning(f"Failed to start Joern server in get_cpg_status: {e}")
                            # Don't fail the status check, just return what we have but maybe with a warning
            
            return {
                "codebase_hash": codebase_hash,
                "status": status,
                "cpg_path": codebase_info.cpg_path,
                "joern_port": joern_port,
                "source_type": codebase_info.source_type,
                "source_path": codebase_info.source_path,
                "language": codebase_info.language,
                "container_codebase_path": codebase_info.metadata.get("container_codebase_path"),
                "container_cpg_path": codebase_info.metadata.get("container_cpg_path"),
                "repository": codebase_info.metadata.get("repository"),
                "created_at": codebase_info.created_at.isoformat(),
                "last_accessed": codebase_info.last_accessed.isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get CPG status: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
            }
