"""
Postgres-backed durable job store.

Exposes the job-queue method surface used by DurableCPGQueue (enqueue_job /
claim_next_job / complete_job / fail_job / get_job / count_jobs /
requeue_running_jobs). claim_next_job uses `FOR UPDATE SKIP LOCKED`, so many
generation workers across multiple processes / hosts can pull from one shared
queue concurrently without blocking each other or double-claiming.

Connections are opened per operation (queue ops are low-frequency); swap in
psycopg_pool later if that ever shows up in a profile.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg
from psycopg.rows import dict_row

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PostgresJobStore:
    """Durable job queue on Postgres with SKIP LOCKED claims."""

    def __init__(self, dsn: str):
        # No connection here — construction must not require a live DB (so it can
        # be imported/instantiated cheaply). Call init_schema() at startup.
        self.dsn = dsn

    def _connect(self):
        return psycopg.connect(self.dsn, row_factory=dict_row, autocommit=False)

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id BIGSERIAL PRIMARY KEY,
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
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_active_unique
                ON jobs(codebase_hash, job_type) WHERE status IN ('queued', 'running')
            """)
            conn.commit()
        logger.info("Postgres job store schema ready")

    def enqueue_job(self, codebase_hash: str, job_type: str, payload: Dict[str, Any],
                    max_queued: int = 0) -> tuple:
        """Enqueue a job. Returns (job_id|None, 'submitted'|'duplicate'|'queue_full'|'error')."""
        now = _now()
        try:
            with self._connect() as conn:
                # Dedup precedes backpressure: a re-submit of an active job is a
                # 'duplicate', never 'queue_full'.
                row = conn.execute(
                    "SELECT id FROM jobs WHERE codebase_hash = %s AND job_type = %s "
                    "AND status IN ('queued', 'running') LIMIT 1",
                    (codebase_hash, job_type),
                ).fetchone()
                if row:
                    return row["id"], "duplicate"
                if max_queued and max_queued > 0:
                    queued = conn.execute(
                        "SELECT COUNT(*) AS c FROM jobs WHERE status = 'queued'"
                    ).fetchone()["c"]
                    if queued >= max_queued:
                        return None, "queue_full"
                try:
                    jid = conn.execute(
                        "INSERT INTO jobs (codebase_hash, job_type, status, payload, "
                        "attempts, created_at, updated_at) VALUES (%s, %s, 'queued', %s, 0, %s, %s) "
                        "RETURNING id",
                        (codebase_hash, job_type, json.dumps(payload), now, now),
                    ).fetchone()["id"]
                    conn.commit()
                    return jid, "submitted"
                except psycopg.errors.UniqueViolation:
                    conn.rollback()  # clear the aborted txn before re-querying
                    row = conn.execute(
                        "SELECT id FROM jobs WHERE codebase_hash = %s AND job_type = %s "
                        "AND status IN ('queued', 'running') LIMIT 1",
                        (codebase_hash, job_type),
                    ).fetchone()
                    return (row["id"] if row else None), "duplicate"
        except Exception as e:
            logger.error(f"Postgres enqueue_job failed for {codebase_hash}: {e}")
            return None, "error"

    def claim_next_job(self, job_type: str) -> Optional[Dict[str, Any]]:
        """Atomically claim the oldest queued job via FOR UPDATE SKIP LOCKED."""
        now = _now()
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "UPDATE jobs SET status = 'running', attempts = attempts + 1, updated_at = %s "
                    "WHERE id = (SELECT id FROM jobs WHERE status = 'queued' AND job_type = %s "
                    "ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) "
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
            logger.error(f"Postgres claim_next_job failed: {e}")
            return None

    def complete_job(self, job_id: int, result: Optional[Any] = None) -> None:
        self._finish_job(job_id, "done", result=result)

    def fail_job(self, job_id: int, error: str) -> None:
        self._finish_job(job_id, "failed", error=error)

    def _finish_job(self, job_id: int, status: str, result: Any = None, error: str = None) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE jobs SET status = %s, result = %s, error = %s, updated_at = %s WHERE id = %s",
                    (status, json.dumps(result) if result is not None else None, error, _now(), job_id),
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Postgres finish job {job_id} failed: {e}")

    def get_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        try:
            with self._connect() as conn:
                row = conn.execute("SELECT * FROM jobs WHERE id = %s", (job_id,)).fetchone()
                if not row:
                    return None
                job = dict(row)
                if job.get("payload"):
                    job["payload"] = json.loads(job["payload"])
                return job
        except Exception as e:
            logger.error(f"Postgres get_job {job_id} failed: {e}")
            return None

    def count_jobs(self, status: Optional[str] = None) -> int:
        try:
            with self._connect() as conn:
                if status:
                    row = conn.execute(
                        "SELECT COUNT(*) AS c FROM jobs WHERE status = %s", (status,)
                    ).fetchone()
                else:
                    row = conn.execute("SELECT COUNT(*) AS c FROM jobs").fetchone()
                return row["c"]
        except Exception as e:
            logger.error(f"Postgres count_jobs failed: {e}")
            return 0

    def requeue_running_jobs(self) -> int:
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE jobs SET status = 'queued', updated_at = %s WHERE status = 'running'",
                    (_now(),),
                )
                conn.commit()
                return cur.rowcount
        except Exception as e:
            logger.error(f"Postgres requeue_running_jobs failed: {e}")
            return 0
