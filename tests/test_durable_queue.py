"""Tests for the Phase-3 durable job queue: Postgres jobs table + DurableCPGQueue.

Needs a real Postgres (SQLite was removed) — set CODEBADGER_TEST_PG_DSN to run;
skipped otherwise. Mirrors the skip pattern in tests/test_postgres_db_manager.py.
"""

import asyncio
import os

import pytest

PG_DSN = os.getenv("CODEBADGER_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(
    not PG_DSN, reason="set CODEBADGER_TEST_PG_DSN to run durable-queue (Postgres) tests"
)


@pytest.fixture
def db():
    from src.utils.postgres_job_store import PostgresJobStore
    store = PostgresJobStore(PG_DSN)
    store.init_schema()
    import psycopg
    with psycopg.connect(PG_DSN) as conn:
        conn.execute("TRUNCATE jobs RESTART IDENTITY")
        conn.commit()
    return store


def test_enqueue_and_claim_roundtrip(db):
    job_id, status = db.enqueue_job("h1", "generate_cpg", {"language": "c"})
    assert status == "submitted" and job_id
    assert db.count_jobs("queued") == 1

    claimed = db.claim_next_job("generate_cpg")
    assert claimed["id"] == job_id
    assert claimed["codebase_hash"] == "h1"
    assert claimed["payload"] == {"language": "c"}
    assert db.count_jobs("queued") == 0 and db.count_jobs("running") == 1

    db.complete_job(job_id, result={"ok": True})
    assert db.get_job(job_id)["status"] == "done"
    assert db.count_jobs("running") == 0


def test_dedup_active_job(db):
    id1, s1 = db.enqueue_job("h1", "generate_cpg", {})
    id2, s2 = db.enqueue_job("h1", "generate_cpg", {})
    assert s1 == "submitted"
    assert s2 == "duplicate" and id2 == id1  # same active job returned

    # Once finished, a new job for the same hash is allowed again.
    db.claim_next_job("generate_cpg")
    db.complete_job(id1)
    id3, s3 = db.enqueue_job("h1", "generate_cpg", {})
    assert s3 == "submitted" and id3 != id1


def test_queue_full_backpressure(db):
    db.enqueue_job("a", "generate_cpg", {})
    db.enqueue_job("b", "generate_cpg", {})
    _id, status = db.enqueue_job("c", "generate_cpg", {}, max_queued=2)
    assert status == "queue_full"


def test_claim_returns_none_when_empty(db):
    assert db.claim_next_job("generate_cpg") is None


def test_claim_is_fifo_and_exclusive(db):
    db.enqueue_job("a", "generate_cpg", {})
    db.enqueue_job("b", "generate_cpg", {})
    first = db.claim_next_job("generate_cpg")
    second = db.claim_next_job("generate_cpg")
    assert {first["codebase_hash"], second["codebase_hash"]} == {"a", "b"}
    assert first["codebase_hash"] == "a"  # oldest first
    assert db.claim_next_job("generate_cpg") is None  # both claimed


def test_fail_job_and_requeue_running(db):
    jid, _ = db.enqueue_job("h1", "generate_cpg", {})
    db.claim_next_job("generate_cpg")
    db.fail_job(jid, "boom")
    assert db.get_job(jid)["status"] == "failed"
    assert db.get_job(jid)["error"] == "boom"

    # A job stuck in 'running' (worker crash) is requeued at startup.
    jid2, _ = db.enqueue_job("h2", "generate_cpg", {})
    db.claim_next_job("generate_cpg")
    assert db.count_jobs("running") == 1
    assert db.requeue_running_jobs() == 1
    assert db.count_jobs("queued") == 1 and db.count_jobs("running") == 0


@pytest.mark.asyncio
async def test_durable_queue_worker_roundtrip(db, monkeypatch):
    """A submitted job is claimed by a worker, run, and marked done."""
    import src.tools.core_tools as core_tools

    ran = []

    async def fake_generate(**kwargs):
        ran.append(kwargs["codebase_hash"])

    monkeypatch.setattr(core_tools, "_generate_cpg_async", fake_generate)

    services = {"marker": object()}
    q = core_tools.DurableCPGQueue(db, services, workers=1, maxsize=8, poll_interval=0.05)
    await q.start()
    try:
        status = await q.submit("h1", {"codebase_hash": "h1", "language": "c", "services": services})
        assert status == "submitted"
        # Wait for the worker to process it.
        for _ in range(40):
            if db.count_jobs("done") == 1:
                break
            await asyncio.sleep(0.05)
        assert ran == ["h1"]
        assert db.get_job(1)["status"] == "done"
        # Duplicate submit while none active again -> resubmits fine after done
        dup_status = await q.submit("h2", {"codebase_hash": "h2", "services": services})
        assert dup_status == "submitted"
    finally:
        await q.stop()


@pytest.mark.asyncio
async def test_durable_queue_dedup_and_full(db):
    import src.tools.core_tools as core_tools
    q = core_tools.DurableCPGQueue(db, {}, workers=0, maxsize=1)  # no workers: jobs stay queued
    assert await q.submit("h1", {"codebase_hash": "h1"}) == "submitted"
    assert await q.submit("h1", {"codebase_hash": "h1"}) == "duplicate"
    assert await q.submit("h2", {"codebase_hash": "h2"}) == "queue_full"  # maxsize=1 reached
    assert q.depth == 1 and q.is_full is True
