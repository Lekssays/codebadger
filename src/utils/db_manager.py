import sqlite3
import json
import logging
import os
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

class DBManager:
    """SQLite database manager for CodeBadger"""

    def __init__(self, db_path: str = "codebadger.db"):
        self.db_path = db_path
        self._init_db()

    def close(self):
        """Close the database manager and clean up resources."""
        logger.debug(f"DBManager closed for {self.db_path}")

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

                # Findings table for storing vulnerability findings
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        codebase_hash TEXT NOT NULL,
                        finding_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        confidence TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        line_number INTEGER NOT NULL,
                        message TEXT NOT NULL,
                        description TEXT,
                        cwe_id INTEGER,
                        rule_id TEXT,
                        flow_data TEXT,
                        metadata TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (codebase_hash) REFERENCES codebases(hash)
                    )
                """)

                # Create indexes for efficient querying
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_codebase ON findings(codebase_hash)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type)")

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

    def delete_codebase(self, codebase_hash: str) -> bool:
        """Delete a codebase record and its associated findings."""
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM findings WHERE codebase_hash = ?", (codebase_hash,))
                conn.execute("DELETE FROM tool_cache WHERE codebase_hash = ?", (codebase_hash,))
                conn.execute("DELETE FROM codebases WHERE hash = ?", (codebase_hash,))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to delete codebase {codebase_hash}: {e}")
            return False

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

    def get_cached_tool_output(self, tool_name: str, codebase_hash: str, parameters: Dict[str, Any], cache_ttl: int = 300) -> Optional[Any]:
        """Get cached tool output if not expired.
        
        Args:
            tool_name: Name of the tool
            codebase_hash: Hash of the codebase
            parameters: Tool parameters
            cache_ttl: Time-to-live in seconds (default: 300)
        
        Returns:
            Cached output if found and not expired, None otherwise
        """
        try:
            import hashlib
            
            param_str = json.dumps(parameters, sort_keys=True)
            param_hash = hashlib.sha256(param_str.encode()).hexdigest()
            
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT output, created_at FROM tool_cache 
                    WHERE tool_name = ? AND codebase_hash = ? AND parameters_hash = ?
                """, (tool_name, codebase_hash, param_hash))
                
                row = cursor.fetchone()
                if row:
                    # Check if entry is expired
                    created_at = datetime.fromisoformat(row["created_at"])
                    # Ensure created_at is timezone-aware
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    age_seconds = (now - created_at).total_seconds()
                    if age_seconds > cache_ttl:
                        logger.debug(f"Cache entry expired for {tool_name} (age: {age_seconds:.0f}s, ttl: {cache_ttl}s)")
                        return None
                    return json.loads(row["output"])
                return None
        except Exception as e:
            logger.error(f"Failed to get cached tool output: {e}")
            return None

    def cleanup_expired_cache(self, max_age_seconds: int = 3600) -> int:
        """Remove cache entries older than max_age_seconds.
        
        Args:
            max_age_seconds: Maximum age of cache entries to keep (default: 3600)
        
        Returns:
            Number of deleted entries
        """
        try:
            with self._get_connection() as conn:
                cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
                cursor = conn.execute("""
                    DELETE FROM tool_cache 
                    WHERE created_at < ?
                """, (cutoff.isoformat(),))
                conn.commit()
                deleted = cursor.rowcount
                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} expired cache entries")
                return deleted
        except Exception as e:
            logger.error(f"Failed to cleanup expired cache: {e}")
            return 0

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring.

        Returns:
            Dictionary with cache statistics
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT COUNT(*) as count FROM tool_cache")
                total = cursor.fetchone()["count"]
                return {"total_entries": total}
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {"total_entries": 0, "error": str(e)}

    # Findings operations
    def save_finding(self, finding_data: Dict[str, Any]) -> int:
        """Save a single finding to the database.

        Args:
            finding_data: Dictionary with finding data

        Returns:
            The finding ID (primary key)
        """
        try:
            with self._get_connection() as conn:
                now = datetime.now(timezone.utc).isoformat()

                # Ensure metadata and flow_data are JSON strings
                if isinstance(finding_data.get("metadata"), dict):
                    finding_data["metadata"] = json.dumps(finding_data["metadata"])
                if isinstance(finding_data.get("flow_data"), dict):
                    finding_data["flow_data"] = json.dumps(finding_data["flow_data"])

                cursor = conn.execute("""
                    INSERT INTO findings (
                        codebase_hash, finding_type, severity, confidence,
                        filename, line_number, message, description,
                        cwe_id, rule_id, flow_data, metadata, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding_data.get("codebase_hash"),
                    finding_data.get("finding_type"),
                    finding_data.get("severity"),
                    finding_data.get("confidence"),
                    finding_data.get("filename"),
                    finding_data.get("line_number"),
                    finding_data.get("message"),
                    finding_data.get("description"),
                    finding_data.get("cwe_id"),
                    finding_data.get("rule_id"),
                    finding_data.get("flow_data"),
                    finding_data.get("metadata"),
                    now
                ))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to save finding: {e}")
            raise

    def save_findings_batch(self, findings: List[Dict[str, Any]]) -> int:
        """Save multiple findings to the database.

        Args:
            findings: List of finding dictionaries

        Returns:
            Number of findings saved
        """
        try:
            with self._get_connection() as conn:
                now = datetime.now(timezone.utc).isoformat()
                count = 0

                for finding_data in findings:
                    # Ensure metadata and flow_data are JSON strings
                    if isinstance(finding_data.get("metadata"), dict):
                        finding_data["metadata"] = json.dumps(finding_data["metadata"])
                    if isinstance(finding_data.get("flow_data"), dict):
                        finding_data["flow_data"] = json.dumps(finding_data["flow_data"])

                    conn.execute("""
                        INSERT INTO findings (
                            codebase_hash, finding_type, severity, confidence,
                            filename, line_number, message, description,
                            cwe_id, rule_id, flow_data, metadata, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        finding_data.get("codebase_hash"),
                        finding_data.get("finding_type"),
                        finding_data.get("severity"),
                        finding_data.get("confidence"),
                        finding_data.get("filename"),
                        finding_data.get("line_number"),
                        finding_data.get("message"),
                        finding_data.get("description"),
                        finding_data.get("cwe_id"),
                        finding_data.get("rule_id"),
                        finding_data.get("flow_data"),
                        finding_data.get("metadata"),
                        now
                    ))
                    count += 1

                conn.commit()
                return count
        except Exception as e:
            logger.error(f"Failed to save findings batch: {e}")
            raise

    def get_findings(self, codebase_hash: str, min_severity: Optional[str] = None,
                    min_confidence: Optional[str] = None, finding_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get findings for a codebase with optional filtering.

        Args:
            codebase_hash: The codebase hash
            min_severity: Minimum severity level (critical, high, medium, low)
            min_confidence: Minimum confidence level (high, medium, low)
            finding_type: Specific finding type to filter (taint_flow, use_after_free, double_free)

        Returns:
            List of finding dictionaries
        """
        try:
            with self._get_connection() as conn:
                query = "SELECT * FROM findings WHERE codebase_hash = ?"
                params = [codebase_hash]

                # Build severity filter if provided
                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                if min_severity and min_severity in severity_order:
                    min_sev_val = severity_order[min_severity]
                    severity_levels = [k for k, v in severity_order.items() if v >= min_sev_val]
                    if severity_levels:
                        query += f" AND severity IN ({','.join(['?'] * len(severity_levels))})"
                        params.extend(severity_levels)

                # Build confidence filter if provided
                if min_confidence and min_confidence in ("high", "medium", "low"):
                    conf_order = {"high": 3, "medium": 2, "low": 1}
                    min_conf_val = conf_order[min_confidence]
                    confidence_levels = [k for k, v in conf_order.items() if v >= min_conf_val]
                    if confidence_levels:
                        query += f" AND confidence IN ({','.join(['?'] * len(confidence_levels))})"
                        params.extend(confidence_levels)

                # Filter by type if provided
                if finding_type:
                    query += " AND finding_type = ?"
                    params.append(finding_type)

                query += " ORDER BY severity DESC, confidence DESC, created_at DESC"

                cursor = conn.execute(query, params)
                results = []
                for row in cursor.fetchall():
                    data = dict(row)
                    # Parse JSON fields
                    if data.get("metadata"):
                        try:
                            data["metadata"] = json.loads(data["metadata"])
                        except (json.JSONDecodeError, TypeError):
                            data["metadata"] = {}
                    if data.get("flow_data"):
                        try:
                            data["flow_data"] = json.loads(data["flow_data"])
                        except (json.JSONDecodeError, TypeError):
                            data["flow_data"] = {}
                    results.append(data)
                return results
        except Exception as e:
            logger.error(f"Failed to get findings: {e}")
            return []

    def get_finding_by_id(self, finding_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific finding by ID.

        Args:
            finding_id: The finding ID

        Returns:
            Finding dictionary or None if not found
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
                row = cursor.fetchone()
                if row:
                    data = dict(row)
                    # Parse JSON fields
                    if data.get("metadata"):
                        try:
                            data["metadata"] = json.loads(data["metadata"])
                        except (json.JSONDecodeError, TypeError):
                            data["metadata"] = {}
                    if data.get("flow_data"):
                        try:
                            data["flow_data"] = json.loads(data["flow_data"])
                        except (json.JSONDecodeError, TypeError):
                            data["flow_data"] = {}
                    return data
                return None
        except Exception as e:
            logger.error(f"Failed to get finding by ID: {e}")
            return None

    def delete_findings_for_codebase(self, codebase_hash: str) -> int:
        """Delete all findings for a codebase.

        Args:
            codebase_hash: The codebase hash

        Returns:
            Number of deleted findings
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("DELETE FROM findings WHERE codebase_hash = ?", (codebase_hash,))
                conn.commit()
                return cursor.rowcount
        except Exception as e:
            logger.error(f"Failed to delete findings: {e}")
            return 0

    def get_findings_stats(self, codebase_hash: str) -> Dict[str, Any]:
        """Get statistics about findings for a codebase.

        Args:
            codebase_hash: The codebase hash

        Returns:
            Dictionary with finding statistics
        """
        try:
            with self._get_connection() as conn:
                # Total count
                cursor = conn.execute("SELECT COUNT(*) as count FROM findings WHERE codebase_hash = ?",
                                    (codebase_hash,))
                total = cursor.fetchone()["count"]

                # Count by severity
                cursor = conn.execute("""
                    SELECT severity, COUNT(*) as count FROM findings
                    WHERE codebase_hash = ? GROUP BY severity
                """, (codebase_hash,))
                by_severity = {row["severity"]: row["count"] for row in cursor.fetchall()}

                # Count by type
                cursor = conn.execute("""
                    SELECT finding_type, COUNT(*) as count FROM findings
                    WHERE codebase_hash = ? GROUP BY finding_type
                """, (codebase_hash,))
                by_type = {row["finding_type"]: row["count"] for row in cursor.fetchall()}

                # Count by confidence
                cursor = conn.execute("""
                    SELECT confidence, COUNT(*) as count FROM findings
                    WHERE codebase_hash = ? GROUP BY confidence
                """, (codebase_hash,))
                by_confidence = {row["confidence"]: row["count"] for row in cursor.fetchall()}

                return {
                    "total": total,
                    "by_severity": by_severity,
                    "by_type": by_type,
                    "by_confidence": by_confidence,
                }
        except Exception as e:
            logger.error(f"Failed to get findings stats: {e}")
            return {"total": 0, "by_severity": {}, "by_type": {}, "by_confidence": {}}
