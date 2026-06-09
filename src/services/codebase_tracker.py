"""
Codebase tracker for managing CPG codebase information by hash
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..models import CodebaseInfo
from ..utils.postgres_db_manager import PostgresDBManager

logger = logging.getLogger(__name__)


class CodebaseTracker:
    """Tracks codebase information by hash"""

    def __init__(self, db_manager: PostgresDBManager):
        self.db = db_manager

    def save_codebase(
        self,
        codebase_hash: str,
        source_type: str,
        source_path: str,
        language: str,
        cpg_path: Optional[str] = None,
        joern_port: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CodebaseInfo:
        """Save or update codebase information"""
        try:
            codebase = CodebaseInfo(
                codebase_hash=codebase_hash,
                source_type=source_type,
                source_path=source_path,
                language=language,
                cpg_path=cpg_path,
                joern_port=joern_port,
                metadata=metadata or {},
            )

            data = codebase.to_dict()
            self.db.save_codebase(data)

            logger.info(f"Saved codebase info for hash {codebase_hash}")
            return codebase

        except Exception as e:
            logger.error(f"Failed to save codebase {codebase_hash}: {e}")
            raise

    def get_codebase(self, codebase_hash: str) -> Optional[CodebaseInfo]:
        """Get codebase information by hash"""
        try:
            data = self.db.get_codebase(codebase_hash)
            
            if not data:
                return None
            
            return CodebaseInfo.from_dict(data)

        except Exception as e:
            logger.error(f"Failed to get codebase {codebase_hash}: {e}")
            return None

    def update_codebase(self, codebase_hash: str, **updates) -> None:
        """Update codebase fields.

        Delegates to the DB layer, which merges metadata and sets the given fields
        under a row lock in one transaction — so concurrent updates to the same
        codebase don't lose each other's metadata keys (a read-modify-write race)."""
        try:
            if not self.db.update_codebase(codebase_hash, updates):
                raise ValueError(f"Codebase {codebase_hash} not found")
            logger.debug(f"Updated codebase {codebase_hash}")
        except Exception as e:
            logger.error(f"Failed to update codebase {codebase_hash}: {e}")
            raise

    def delete_codebase(self, codebase_hash: str) -> bool:
        """Delete codebase record and associated data."""
        return self.db.delete_codebase(codebase_hash)

    def list_codebases(self) -> list[str]:
        """List all tracked codebase hashes"""
        return self.db.list_codebases()

    def list_codebases_full(self) -> list[CodebaseInfo]:
        """All codebases as CodebaseInfo in a single bulk query (read-only).

        For /health and the status logger — avoids N per-codebase DB round-trips
        (one DB connection per codebase on the event loop under Postgres)."""
        out = []
        for data in self.db.list_all():
            try:
                out.append(CodebaseInfo.from_dict(data))
            except Exception as e:
                logger.warning(f"Skipping malformed codebase row {data.get('hash')}: {e}")
        return out
