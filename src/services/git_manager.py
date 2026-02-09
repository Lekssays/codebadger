"""
Git repository manager for cloning and managing GitHub repositories
"""

import asyncio
import logging
import os
import re
import shutil
from typing import Dict, Optional
from urllib.parse import urlparse

import git

from ..exceptions import GitOperationError, ValidationError
from ..utils.validators import validate_github_url

logger = logging.getLogger(__name__)


def _mask_token_in_url(url: str) -> str:
    """
    Mask authentication tokens in URLs for safe logging.

    Args:
        url: URL that may contain a token

    Returns:
        URL with token replaced by '***'
    """
    # Pattern to match tokens in URLs: scheme://token@host/path
    return re.sub(
        r"(https?://)[^@\s]+@",
        r"\1***@",
        url
    )


def _mask_token_in_text(text: str) -> str:
    """
    Mask authentication tokens in error messages or logs.

    Args:
        text: Text that may contain tokens in URLs

    Returns:
        Text with tokens masked
    """
    return re.sub(
        r"(https?://)[^@\s]+@",
        r"\1***@",
        text
    )


class GitManager:
    """Handles GitHub repository operations"""

    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root
        self.repos_dir = os.path.join(workspace_root, "repos")
        os.makedirs(self.repos_dir, exist_ok=True)

    def clone_repository(
        self,
        repo_url: str,
        target_path: str,
        branch: Optional[str] = None,
        token: Optional[str] = None,
    ) -> str:
        """Clone a GitHub repository"""
        try:
            # Validate URL
            validate_github_url(repo_url)

            # Parse URL and inject token if provided
            if token:
                parsed = urlparse(repo_url)
                auth_url = f"{parsed.scheme}://{token}@{parsed.netloc}{parsed.path}"
            else:
                auth_url = repo_url

            # Create target directory
            os.makedirs(target_path, exist_ok=True)
            source_path = os.path.join(target_path, "source")

            # Clone in a thread pool (git operations are blocking)
            loop = asyncio.get_event_loop()
            loop.run_in_executor(
                None, self._do_clone, auth_url, source_path, branch
            )

            logger.info(f"Cloned repository {repo_url} to {source_path}")
            return source_path

        except ValidationError:
            raise
        except Exception as e:
            # Mask tokens in error messages before logging
            safe_error = _mask_token_in_text(str(e))
            logger.error(f"Failed to clone repository: {safe_error}")
            raise GitOperationError(f"Failed to clone repository: {safe_error}")

    def _do_clone(self, url: str, target: str, branch: Optional[str]):
        """Blocking clone operation"""
        try:
            if branch:
                git.Repo.clone_from(url, target, branch=branch, depth=1)
            else:
                git.Repo.clone_from(url, target, depth=1)
        except Exception as e:
            # Mask tokens in error messages
            safe_error = _mask_token_in_text(str(e))
            raise GitOperationError(f"Git clone failed: {safe_error}")

    def validate_repository(self, repo_url: str) -> bool:
        """Validate that repository exists and is accessible"""
        try:
            validate_github_url(repo_url)
            # Could add additional checks here (API call to check if repo exists)
            return True
        except Exception as e:
            logger.error(f"Repository validation failed: {e}")
            return False

    def get_repository_info(self, repo_url: str) -> Dict:
        """Get repository information"""
        try:
            validate_github_url(repo_url)
            parsed = urlparse(repo_url)
            parts = parsed.path.strip("/").split("/")

            return {
                "owner": parts[0] if len(parts) > 0 else "",
                "repo": parts[1] if len(parts) > 1 else "",
                "url": repo_url,
            }
        except Exception as e:
            logger.error(f"Failed to get repository info: {e}")
            raise GitOperationError(f"Failed to parse repository URL: {str(e)}")

    def parse_github_url(self, url: str) -> Dict:
        """Parse GitHub URL into components"""
        try:
            validate_github_url(url)
            parsed = urlparse(url)
            parts = parsed.path.strip("/").split("/")

            # Remove .git suffix if present
            repo = parts[1].replace(".git", "") if len(parts) > 1 else ""

            return {
                "owner": parts[0] if len(parts) > 0 else "",
                "repo": repo,
                "host": parsed.netloc,
                "scheme": parsed.scheme,
            }
        except Exception as e:
            logger.error(f"Failed to parse GitHub URL: {e}")
            raise GitOperationError(f"Invalid GitHub URL: {str(e)}")

    def cleanup_repository(self, target_path: str):
        """Clean up cloned repository"""
        try:
            if os.path.exists(target_path):
                shutil.rmtree(target_path)
                logger.info(f"Cleaned up repository at {target_path}")
        except Exception as e:
            logger.error(f"Failed to cleanup repository: {e}")
