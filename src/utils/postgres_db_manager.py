"""
Postgres-backed catalog/cache/findings store (Phase 3c).

Drop-in for the SQLite DBManager when DATABASE_URL points at Postgres, so the
codebase catalog, tool cache, findings AND the durable job queue all live in one
shared Postgres — the last piece needed for genuinely multi-process operation
(multiple API/scheduler processes reading/writing one catalog instead of a local
SQLite file). Subclasses PostgresJobStore to inherit the job-queue methods and
the connection helper.

Postgres dialect notes vs the SQLite manager: %s placeholders, BIGSERIAL ids,
INSERT ... ON CONFLICT upserts, RETURNING for generated ids. Large TEXT (cache
output, flow_data) is TOAST-compressed out-of-line by Postgres automatically, so
the SQLite-style inline bloat doesn't accrue; the MAX_CACHE_OUTPUT_BYTES cap
still applies.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .db_manager import MAX_CACHE_OUTPUT_BYTES
from .postgres_job_store import PostgresJobStore

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PostgresDBManager(PostgresJobStore):
    """Same method surface as DBManager, backed by Postgres."""

    def close(self):
        """No-op: connections are opened per operation."""
        pass

    def init_schema(self) -> None:
        super().init_schema()  # jobs table + indexes
        with self._connect() as conn:
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
                    id BIGSERIAL PRIMARY KEY,
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
                    id BIGSERIAL PRIMARY KEY,
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
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_codebase ON findings(codebase_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type)")
            conn.commit()
        logger.info("Postgres catalog/cache/findings schema ready")

    # codebases

    def save_codebase(self, data: Dict[str, Any]):
        now = _now()
        metadata = data.get("metadata", "{}")
        if isinstance(metadata, dict):
            metadata = json.dumps(metadata)
        try:
            with self._connect() as conn:
                # created_at is preserved on conflict (not in the UPDATE set).
                conn.execute("""
                    INSERT INTO codebases (hash, source_type, source_path, language,
                        cpg_path, joern_port, metadata, created_at, last_accessed)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (hash) DO UPDATE SET
                        source_type = EXCLUDED.source_type,
                        source_path = EXCLUDED.source_path,
                        language = EXCLUDED.language,
                        cpg_path = EXCLUDED.cpg_path,
                        joern_port = EXCLUDED.joern_port,
                        metadata = EXCLUDED.metadata,
                        last_accessed = EXCLUDED.last_accessed
                """, (
                    data["hash"], data.get("source_type"), data.get("source_path"),
                    data.get("language"), data.get("cpg_path"), data.get("joern_port"),
                    metadata, now, now,
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to save codebase: {e}")
            raise

    _CODEBASE_COLUMNS = ("source_type", "source_path", "language", "cpg_path", "joern_port")

    def update_codebase(self, codebase_hash: str, fields: Dict[str, Any]) -> bool:
        """Atomically merge metadata and set scalar columns for one codebase.

        SELECT ... FOR UPDATE locks the row so concurrent metadata merges serialize
        instead of racing on a read-modify-write that would drop one writer's keys.
        Returns False if the row is absent; only keys present in `fields` are written."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT metadata FROM codebases WHERE hash = %s FOR UPDATE",
                    (codebase_hash,),
                ).fetchone()
                if row is None:
                    conn.rollback()
                    return False

                sets, params = [], []
                for col in self._CODEBASE_COLUMNS:
                    if col in fields:
                        sets.append(f"{col} = %s")
                        params.append(fields[col])
                if isinstance(fields.get("metadata"), dict):
                    merged = json.loads(row["metadata"]) if row["metadata"] else {}
                    merged.update(fields["metadata"])
                    sets.append("metadata = %s")
                    params.append(json.dumps(merged))
                sets.append("last_accessed = %s")
                params.append(_now())
                params.append(codebase_hash)

                conn.execute(f"UPDATE codebases SET {', '.join(sets)} WHERE hash = %s", params)
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to update codebase {codebase_hash}: {e}")
            raise

    def get_codebase(self, codebase_hash: str) -> Optional[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                row = conn.execute("SELECT * FROM codebases WHERE hash = %s", (codebase_hash,)).fetchone()
                if not row:
                    return None
                data = dict(row)
                # Throttle last_accessed writes to once per 60s (avoid a write per poll).
                try:
                    stored = datetime.fromisoformat(data["last_accessed"])
                    age = datetime.now(timezone.utc) - stored
                except (KeyError, ValueError, TypeError):
                    age = timedelta(seconds=61)
                if age.total_seconds() > 60:
                    now = _now()
                    conn.execute("UPDATE codebases SET last_accessed = %s WHERE hash = %s",
                                 (now, codebase_hash))
                    conn.commit()
                    data["last_accessed"] = now
                if data.get("metadata"):
                    data["metadata"] = json.loads(data["metadata"])
                return data
        except Exception as e:
            logger.error(f"Failed to get codebase: {e}")
            return None

    def list_codebases(self) -> List[str]:
        try:
            with self._connect() as conn:
                rows = conn.execute("SELECT hash FROM codebases").fetchall()
                return [r["hash"] for r in rows]
        except Exception as e:
            logger.error(f"Failed to list codebases: {e}")
            return []

    def list_all(self) -> List[Dict[str, Any]]:
        """All codebase rows in ONE query (read-only). Avoids one Postgres
        connection per codebase on the event loop in the health/status path."""
        try:
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM codebases").fetchall()
                out = []
                for r in rows:
                    d = dict(r)
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

    def delete_codebase(self, codebase_hash: str) -> bool:
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM findings WHERE codebase_hash = %s", (codebase_hash,))
                conn.execute("DELETE FROM tool_cache WHERE codebase_hash = %s", (codebase_hash,))
                conn.execute("DELETE FROM codebases WHERE hash = %s", (codebase_hash,))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to delete codebase {codebase_hash}: {e}")
            return False

    # tool cache

    def cache_tool_output(self, tool_name: str, codebase_hash: str, parameters: Dict[str, Any], output: Any):
        try:
            param_str = json.dumps(parameters, sort_keys=True)
            param_hash = hashlib.sha256(param_str.encode()).hexdigest()
            output_str = json.dumps(output)
            if MAX_CACHE_OUTPUT_BYTES and len(output_str) > MAX_CACHE_OUTPUT_BYTES:
                logger.debug(f"Skipping cache for {tool_name} ({len(output_str)} bytes > cap)")
                return
            with self._connect() as conn:
                conn.execute("""
                    INSERT INTO tool_cache (tool_name, codebase_hash, parameters_hash,
                        parameters, output, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tool_name, codebase_hash, parameters_hash) DO UPDATE SET
                        parameters = EXCLUDED.parameters,
                        output = EXCLUDED.output,
                        created_at = EXCLUDED.created_at
                """, (tool_name, codebase_hash, param_hash, param_str, output_str, _now()))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to cache tool output: {e}")

    def get_cached_tool_output(self, tool_name: str, codebase_hash: str,
                               parameters: Dict[str, Any], cache_ttl: int = 300) -> Optional[Any]:
        try:
            param_str = json.dumps(parameters, sort_keys=True)
            param_hash = hashlib.sha256(param_str.encode()).hexdigest()
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT output, created_at FROM tool_cache "
                    "WHERE tool_name = %s AND codebase_hash = %s AND parameters_hash = %s",
                    (tool_name, codebase_hash, param_hash),
                ).fetchone()
                if not row:
                    return None
                created_at = datetime.fromisoformat(row["created_at"])
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                if (datetime.now(timezone.utc) - created_at).total_seconds() > cache_ttl:
                    return None
                return json.loads(row["output"])
        except Exception as e:
            logger.error(f"Failed to get cached tool output: {e}")
            return None

    def cleanup_expired_cache(self, max_age_seconds: int = 3600) -> int:
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)).isoformat()
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM tool_cache WHERE created_at < %s", (cutoff,))
                conn.commit()
                return cur.rowcount
        except Exception as e:
            logger.error(f"Failed to cleanup expired cache: {e}")
            return 0

    def get_cache_stats(self) -> Dict[str, Any]:
        try:
            with self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) AS count FROM tool_cache").fetchone()["count"]
                return {"total_entries": total}
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {"total_entries": 0, "error": str(e)}

    # findings

    def _finding_row(self, fd: Dict[str, Any]) -> tuple:
        meta = fd.get("metadata")
        flow = fd.get("flow_data")
        if isinstance(meta, dict):
            meta = json.dumps(meta)
        if isinstance(flow, dict):
            flow = json.dumps(flow)
        return (
            fd.get("codebase_hash"), fd.get("finding_type"), fd.get("severity"),
            fd.get("confidence"), fd.get("filename"), fd.get("line_number"),
            fd.get("message"), fd.get("description"), fd.get("cwe_id"),
            fd.get("rule_id"), flow, meta, _now(),
        )

    _FINDING_INSERT = (
        "INSERT INTO findings (codebase_hash, finding_type, severity, confidence, "
        "filename, line_number, message, description, cwe_id, rule_id, flow_data, "
        "metadata, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )

    def save_finding(self, finding_data: Dict[str, Any]) -> int:
        try:
            with self._connect() as conn:
                row = conn.execute(self._FINDING_INSERT + " RETURNING id",
                                   self._finding_row(finding_data)).fetchone()
                conn.commit()
                return row["id"]
        except Exception as e:
            logger.error(f"Failed to save finding: {e}")
            raise

    def save_findings_batch(self, findings: List[Dict[str, Any]]) -> int:
        try:
            with self._connect() as conn:
                count = 0
                for fd in findings:
                    conn.execute(self._FINDING_INSERT, self._finding_row(fd))
                    count += 1
                conn.commit()
                return count
        except Exception as e:
            logger.error(f"Failed to save findings batch: {e}")
            raise

    def get_findings(self, codebase_hash: str, min_severity: Optional[str] = None,
                     min_confidence: Optional[str] = None,
                     finding_type: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                query = "SELECT * FROM findings WHERE codebase_hash = %s"
                params: List[Any] = [codebase_hash]
                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                if min_severity and min_severity in severity_order:
                    levels = [k for k, v in severity_order.items() if v >= severity_order[min_severity]]
                    query += f" AND severity IN ({','.join(['%s'] * len(levels))})"
                    params.extend(levels)
                if min_confidence and min_confidence in ("high", "medium", "low"):
                    conf_order = {"high": 3, "medium": 2, "low": 1}
                    levels = [k for k, v in conf_order.items() if v >= conf_order[min_confidence]]
                    query += f" AND confidence IN ({','.join(['%s'] * len(levels))})"
                    params.extend(levels)
                if finding_type:
                    query += " AND finding_type = %s"
                    params.append(finding_type)
                query += " ORDER BY severity DESC, confidence DESC, created_at DESC"
                rows = conn.execute(query, params).fetchall()
                return [self._parse_finding(dict(r)) for r in rows]
        except Exception as e:
            logger.error(f"Failed to get findings: {e}")
            return []

    def _parse_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
        for field in ("metadata", "flow_data"):
            if data.get(field):
                try:
                    data[field] = json.loads(data[field])
                except (json.JSONDecodeError, TypeError):
                    data[field] = {}
        return data

    def get_finding_by_id(self, finding_id: int) -> Optional[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                row = conn.execute("SELECT * FROM findings WHERE id = %s", (finding_id,)).fetchone()
                return self._parse_finding(dict(row)) if row else None
        except Exception as e:
            logger.error(f"Failed to get finding by ID: {e}")
            return None

    def delete_findings_for_codebase(self, codebase_hash: str) -> int:
        try:
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM findings WHERE codebase_hash = %s", (codebase_hash,))
                conn.commit()
                return cur.rowcount
        except Exception as e:
            logger.error(f"Failed to delete findings: {e}")
            return 0

    def get_findings_stats(self, codebase_hash: str) -> Dict[str, Any]:
        try:
            with self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) AS count FROM findings WHERE codebase_hash = %s",
                                     (codebase_hash,)).fetchone()["count"]

                def _group(col):
                    rows = conn.execute(
                        f"SELECT {col} AS k, COUNT(*) AS count FROM findings "
                        f"WHERE codebase_hash = %s GROUP BY {col}", (codebase_hash,)
                    ).fetchall()
                    return {r["k"]: r["count"] for r in rows}

                return {
                    "total": total,
                    "by_severity": _group("severity"),
                    "by_type": _group("finding_type"),
                    "by_confidence": _group("confidence"),
                }
        except Exception as e:
            logger.error(f"Failed to get findings stats: {e}")
            return {"total": 0, "by_severity": {}, "by_type": {}, "by_confidence": {}}
