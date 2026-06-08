import sqlite3
import json
import logging
import os
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# Skip caching outputs larger than this (bytes); 0 disables the cap. Keeps the
# tool_cache from bloating with rarely-reused multi-hundred-KB query dumps.
MAX_CACHE_OUTPUT_BYTES = int(os.getenv("MAX_CACHE_OUTPUT_BYTES", "262144"))

class DBManager:
    """SQLite database manager for CodeBadger"""

    def __init__(self, db_path: str = "codebadger.db"):
        self.db_path = db_path
        self._init_db()

    def close(self):
        """No-op — connections are opened and closed per operation, so there is
        nothing to release here.  Exists so callers can call close() without
        needing to know the implementation detail."""
        pass

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # Allow readers to proceed concurrently with a single writer.
        conn.execute("PRAGMA journal_mode=WAL")
        # Retry for up to 5 s instead of immediately raising OperationalError on lock.
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self):
        """Initialize database schema"""
        try:
            with self._get_connection() as conn:
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

                # Durable job queue (Phase 3): survives restarts so a 300-CVE
                # batch is never dropped on a full in-memory queue. status is
                # queued -> running -> done|failed.
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS jobs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        codebase_hash TEXT NOT NULL,
                        job_type TEXT NOT NULL DEFAULT 'generate_cpg',
                        status TEXT NOT NULL DEFAULT 'queued',
                        payload TEXT,
                        result TEXT,
                        error TEXT,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, created_at)")
                # At most one active (queued/running) job per codebase+type — the
                # DB-level dedup that replaces the in-memory in-flight set.
                conn.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_active_unique
                    ON jobs(codebase_hash, job_type) WHERE status IN ('queued', 'running')
                """)

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

                if isinstance(data.get("metadata"), dict):
                    data["metadata"] = json.dumps(data["metadata"])

                # Preserve the original created_at on update.
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

    _CODEBASE_COLUMNS = ("source_type", "source_path", "language", "cpg_path", "joern_port")

    def update_codebase(self, codebase_hash: str, fields: Dict[str, Any]) -> bool:
        """Atomically merge metadata and set scalar columns for one codebase.

        Runs as a single BEGIN IMMEDIATE transaction so concurrent updates to the
        same row serialize instead of racing on a read-modify-write of metadata,
        which would silently drop one writer's keys. Returns False if the row is
        absent. Only the keys present in `fields` are written; other columns are
        left untouched (no stale-read overwrite)."""
        conn = self._get_connection()
        try:
            conn.isolation_level = None  # manual transaction control
            conn.execute("BEGIN IMMEDIATE")  # take the write lock up front
            row = conn.execute(
                "SELECT metadata FROM codebases WHERE hash = ?", (codebase_hash,)
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return False

            sets, params = [], []
            for col in self._CODEBASE_COLUMNS:
                if col in fields:
                    sets.append(f"{col} = ?")
                    params.append(fields[col])
            if isinstance(fields.get("metadata"), dict):
                merged = json.loads(row["metadata"]) if row["metadata"] else {}
                merged.update(fields["metadata"])
                sets.append("metadata = ?")
                params.append(json.dumps(merged))
            sets.append("last_accessed = ?")
            params.append(datetime.now(timezone.utc).isoformat())
            params.append(codebase_hash)

            conn.execute(f"UPDATE codebases SET {', '.join(sets)} WHERE hash = ?", params)
            conn.commit()
            return True
        except Exception as e:
            conn.execute("ROLLBACK")
            logger.error(f"Failed to update codebase {codebase_hash}: {e}")
            raise
        finally:
            conn.close()

    def get_codebase(self, codebase_hash: str) -> Optional[Dict[str, Any]]:
        """Get codebase information by hash"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT * FROM codebases WHERE hash = ?", (codebase_hash,))
                row = cursor.fetchone()
                
                if row:
                    data = dict(row)
                    # Only write last_accessed when the stored value is >60s old to avoid
                    # a DB write on every status poll from an LLM client.
                    try:
                        stored = datetime.fromisoformat(data["last_accessed"])
                        age = datetime.now(timezone.utc) - stored
                    except (KeyError, ValueError):
                        age = timedelta(seconds=61)
                    if age.total_seconds() > 60:
                        now = datetime.now(timezone.utc).isoformat()
                        conn.execute(
                            "UPDATE codebases SET last_accessed = ? WHERE hash = ?",
                            (now, codebase_hash),
                        )
                        conn.commit()
                        data["last_accessed"] = now
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

    def list_all(self) -> List[Dict[str, Any]]:
        """Return ALL codebase rows in one query (read-only — no last_accessed write).

        Used by /health and the status logger so they don't fan out into one
        query per codebase (which on Postgres is one connection per codebase on
        the event loop)."""
        try:
            with self._get_connection() as conn:
                rows = conn.execute("SELECT * FROM codebases").fetchall()
                out = []
                for row in rows:
                    d = dict(row)
                    if d.get("metadata"):
                        try:
                            d["metadata"] = json.loads(d["metadata"])
                        except (json.JSONDecodeError, TypeError):
                            d["metadata"] = {}
                    out.append(d)
                return out
        except Exception as e:
            logger.error(f"Failed to list all codebases: {e}")
            return []

    # job queue (Phase 3)

    def enqueue_job(
        self,
        codebase_hash: str,
        job_type: str,
        payload: Dict[str, Any],
        max_queued: int = 0,
    ) -> tuple:
        """Enqueue a durable job. Returns (job_id|None, status).

        status is 'submitted', 'duplicate' (an active job for this
        codebase+type already exists — enforced by the partial unique index),
        or 'queue_full' (queued count >= max_queued, when max_queued > 0).
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._get_connection() as conn:
                # Dedup takes precedence over backpressure: re-submitting a job
                # that's already active is a 'duplicate', never 'queue_full'.
                existing = conn.execute(
                    "SELECT id FROM jobs WHERE codebase_hash = ? AND job_type = ? "
                    "AND status IN ('queued', 'running') LIMIT 1",
                    (codebase_hash, job_type),
                ).fetchone()
                if existing:
                    return existing["id"], "duplicate"
                if max_queued and max_queued > 0:
                    queued = conn.execute(
                        "SELECT COUNT(*) AS c FROM jobs WHERE status = 'queued'"
                    ).fetchone()["c"]
                    if queued >= max_queued:
                        return None, "queue_full"
                try:
                    cur = conn.execute(
                        "INSERT INTO jobs (codebase_hash, job_type, status, payload, "
                        "attempts, created_at, updated_at) VALUES (?, ?, 'queued', ?, 0, ?, ?)",
                        (codebase_hash, job_type, json.dumps(payload), now, now),
                    )
                    conn.commit()
                    return cur.lastrowid, "submitted"
                except sqlite3.IntegrityError:
                    # Active job already exists (unique index violation).
                    row = conn.execute(
                        "SELECT id FROM jobs WHERE codebase_hash = ? AND job_type = ? "
                        "AND status IN ('queued', 'running') LIMIT 1",
                        (codebase_hash, job_type),
                    ).fetchone()
                    return (row["id"] if row else None), "duplicate"
        except Exception as e:
            logger.error(f"Failed to enqueue job for {codebase_hash}: {e}")
            return None, "error"

    def claim_next_job(self, job_type: str) -> Optional[Dict[str, Any]]:
        """Atomically claim the oldest queued job of job_type (queued -> running).

        Uses a single UPDATE ... RETURNING so concurrent workers each claim a
        distinct row under SQLite's write lock (Postgres backend would use
        FOR UPDATE SKIP LOCKED). Returns the claimed job dict, or None if none.
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._get_connection() as conn:
                row = conn.execute(
                    "UPDATE jobs SET status = 'running', attempts = attempts + 1, updated_at = ? "
                    "WHERE id = (SELECT id FROM jobs WHERE status = 'queued' AND job_type = ? "
                    "ORDER BY created_at LIMIT 1) "
                    "RETURNING id, codebase_hash, job_type, payload, attempts",
                    (now, job_type),
                ).fetchone()
                conn.commit()
                if not row:
                    return None
                job = dict(row)
                job["payload"] = json.loads(job["payload"]) if job["payload"] else {}
                return job
        except Exception as e:
            logger.error(f"Failed to claim job: {e}")
            return None

    def complete_job(self, job_id: int, result: Optional[Any] = None) -> None:
        self._finish_job(job_id, "done", result=result)

    def fail_job(self, job_id: int, error: str) -> None:
        self._finish_job(job_id, "failed", error=error)

    def _finish_job(self, job_id: int, status: str, result: Any = None, error: str = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._get_connection() as conn:
                conn.execute(
                    "UPDATE jobs SET status = ?, result = ?, error = ?, updated_at = ? WHERE id = ?",
                    (status, json.dumps(result) if result is not None else None, error, now, job_id),
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to finish job {job_id}: {e}")

    def get_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        try:
            with self._get_connection() as conn:
                row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
                if not row:
                    return None
                job = dict(row)
                if job.get("payload"):
                    job["payload"] = json.loads(job["payload"])
                return job
        except Exception as e:
            logger.error(f"Failed to get job {job_id}: {e}")
            return None

    def count_jobs(self, status: Optional[str] = None) -> int:
        try:
            with self._get_connection() as conn:
                if status:
                    row = conn.execute(
                        "SELECT COUNT(*) AS c FROM jobs WHERE status = ?", (status,)
                    ).fetchone()
                else:
                    row = conn.execute("SELECT COUNT(*) AS c FROM jobs").fetchone()
                return row["c"]
        except Exception as e:
            logger.error(f"Failed to count jobs: {e}")
            return 0

    def requeue_running_jobs(self) -> int:
        """Reset jobs left 'running' by a crashed worker back to 'queued'.

        Called at startup so interrupted CPG builds are retried rather than
        stuck. Returns the number of jobs requeued.
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "UPDATE jobs SET status = 'queued', updated_at = ? WHERE status = 'running'",
                    (now,),
                )
                conn.commit()
                return cur.rowcount
        except Exception as e:
            logger.error(f"Failed to requeue running jobs: {e}")
            return 0

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

            # sort_keys makes the hash stable across dict orderings.
            param_str = json.dumps(parameters, sort_keys=True)
            param_hash = hashlib.sha256(param_str.encode()).hexdigest()

            output_str = json.dumps(output)
            if MAX_CACHE_OUTPUT_BYTES and len(output_str) > MAX_CACHE_OUTPUT_BYTES:
                logger.debug(
                    f"Skipping cache for {tool_name} ({len(output_str)} bytes > "
                    f"{MAX_CACHE_OUTPUT_BYTES} cap)"
                )
                return

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
                    output_str,
                    now
                ))
                conn.commit()
        except Exception as e:
            # Caching is best-effort; never fail the caller on a cache write error.
            logger.error(f"Failed to cache tool output: {e}")

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
                    created_at = datetime.fromisoformat(row["created_at"])
                    # Older rows may lack tzinfo; treat naive timestamps as UTC.
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

                # min_severity is a floor: expand it to every level at or above it.
                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                if min_severity and min_severity in severity_order:
                    min_sev_val = severity_order[min_severity]
                    severity_levels = [k for k, v in severity_order.items() if v >= min_sev_val]
                    if severity_levels:
                        query += f" AND severity IN ({','.join(['?'] * len(severity_levels))})"
                        params.extend(severity_levels)

                if min_confidence and min_confidence in ("high", "medium", "low"):
                    conf_order = {"high": 3, "medium": 2, "low": 1}
                    min_conf_val = conf_order[min_confidence]
                    confidence_levels = [k for k, v in conf_order.items() if v >= min_conf_val]
                    if confidence_levels:
                        query += f" AND confidence IN ({','.join(['?'] * len(confidence_levels))})"
                        params.extend(confidence_levels)

                if finding_type:
                    query += " AND finding_type = ?"
                    params.append(finding_type)

                query += " ORDER BY severity DESC, confidence DESC, created_at DESC"

                cursor = conn.execute(query, params)
                results = []
                for row in cursor.fetchall():
                    data = dict(row)
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
                cursor = conn.execute("SELECT COUNT(*) as count FROM findings WHERE codebase_hash = ?",
                                    (codebase_hash,))
                total = cursor.fetchone()["count"]

                cursor = conn.execute("""
                    SELECT severity, COUNT(*) as count FROM findings
                    WHERE codebase_hash = ? GROUP BY severity
                """, (codebase_hash,))
                by_severity = {row["severity"]: row["count"] for row in cursor.fetchall()}

                cursor = conn.execute("""
                    SELECT finding_type, COUNT(*) as count FROM findings
                    WHERE codebase_hash = ? GROUP BY finding_type
                """, (codebase_hash,))
                by_type = {row["finding_type"]: row["count"] for row in cursor.fetchall()}

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
