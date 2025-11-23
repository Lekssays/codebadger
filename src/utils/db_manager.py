import sqlite3
import json
import logging
import os
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class DBManager:
    """SQLite database manager for CodeBadger"""

    def __init__(self, db_path: str = "codebadger.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database schema"""
        try:
            with self._get_connection() as conn:
                # Codebases table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS codebases (
                        hash TEXT PRIMARY KEY,
                        source_type TEXT,
                        source_path TEXT,
                        language TEXT,
                        cpg_path TEXT,
                        joern_port INTEGER,
                        metadata TEXT,
                        created_at TEXT,
                        last_accessed TEXT
                    )
                """)

                # Tool cache table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tool_cache (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tool_name TEXT,
                        codebase_hash TEXT,
                        parameters_hash TEXT,
                        parameters TEXT,
                        output TEXT,
                        created_at TEXT,
                        UNIQUE(tool_name, codebase_hash, parameters_hash)
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    # Codebase operations
    def save_codebase(self, data: Dict[str, Any]):
        """Save or update codebase information"""
        try:
            with self._get_connection() as conn:
                now = datetime.now(timezone.utc).isoformat()
                
                # Ensure metadata is JSON string
                if isinstance(data.get("metadata"), dict):
                    data["metadata"] = json.dumps(data["metadata"])
                
                # Check if exists to preserve created_at
                cursor = conn.execute("SELECT created_at FROM codebases WHERE hash = ?", (data["hash"],))
                existing = cursor.fetchone()
                
                if existing:
                    created_at = existing["created_at"]
                else:
                    created_at = now

                conn.execute("""
                    INSERT OR REPLACE INTO codebases (
                        hash, source_type, source_path, language, 
                        cpg_path, joern_port, metadata, created_at, last_accessed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    data["hash"],
                    data.get("source_type"),
                    data.get("source_path"),
                    data.get("language"),
                    data.get("cpg_path"),
                    data.get("joern_port"),
                    data.get("metadata", "{}"),
                    created_at,
                    now
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to save codebase: {e}")
            raise

    def get_codebase(self, codebase_hash: str) -> Optional[Dict[str, Any]]:
        """Get codebase information by hash"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT * FROM codebases WHERE hash = ?", (codebase_hash,))
                row = cursor.fetchone()
                
                if row:
                    # Update last_accessed
                    now = datetime.now(timezone.utc).isoformat()
                    conn.execute("UPDATE codebases SET last_accessed = ? WHERE hash = ?", (now, codebase_hash))
                    conn.commit()
                    
                    data = dict(row)
                    if data["metadata"]:
                        data["metadata"] = json.loads(data["metadata"])
                    return data
                return None
        except Exception as e:
            logger.error(f"Failed to get codebase: {e}")
            return None

    def list_codebases(self) -> List[str]:
        """List all tracked codebase hashes"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT hash FROM codebases")
                return [row["hash"] for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to list codebases: {e}")
            return []

    # Tool cache operations
    def cache_tool_output(self, tool_name: str, codebase_hash: str, parameters: Dict[str, Any], output: Any):
        """Cache tool output"""
        try:
            import hashlib
            
            # Create a stable hash of parameters
            param_str = json.dumps(parameters, sort_keys=True)
            param_hash = hashlib.sha256(param_str.encode()).hexdigest()
            
            with self._get_connection() as conn:
                now = datetime.now(timezone.utc).isoformat()
                
                conn.execute("""
                    INSERT OR REPLACE INTO tool_cache (
                        tool_name, codebase_hash, parameters_hash, parameters, output, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    tool_name,
                    codebase_hash,
                    param_hash,
                    param_str,
                    json.dumps(output),
                    now
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to cache tool output: {e}")
            # Don't raise, just log error as caching is optional

    def get_cached_tool_output(self, tool_name: str, codebase_hash: str, parameters: Dict[str, Any]) -> Optional[Any]:
        """Get cached tool output"""
        try:
            import hashlib
            
            param_str = json.dumps(parameters, sort_keys=True)
            param_hash = hashlib.sha256(param_str.encode()).hexdigest()
            
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT output FROM tool_cache 
                    WHERE tool_name = ? AND codebase_hash = ? AND parameters_hash = ?
                """, (tool_name, codebase_hash, param_hash))
                
                row = cursor.fetchone()
                if row:
                    return json.loads(row["output"])
                return None
        except Exception as e:
            logger.error(f"Failed to get cached tool output: {e}")
            return None
