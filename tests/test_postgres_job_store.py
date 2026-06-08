"""Tests for the Phase-3b Postgres job store.

The roundtrip/SKIP-LOCKED tests need a real Postgres — set CODEBADGER_TEST_PG_DSN
(e.g. postgresql://codebadger:codebadger@localhost:55432/codebadger) to run them;
they're skipped otherwise. Construction is always tested (must not connect).
"""

import os

import pytest

PG_DSN = os.getenv("CODEBADGER_TEST_PG_DSN")
pg = pytest.mark.skipif(not PG_DSN, reason="set CODEBADGER_TEST_PG_DSN to run Postgres tests")


def test_construction_does_not_connect():
    """Constructing the store must not require a live DB."""
    from src.utils.postgres_job_store import PostgresJobStore
    store = PostgresJobStore("postgresql://nobody@127.0.0.1:1/none")  # bogus, never dialed
    assert store.dsn.startswith("postgresql://")


@pytest.fixture
def store():
    from src.utils.postgres_job_store import PostgresJobStore
    s = PostgresJobStore(PG_DSN)
    s.init_schema()
    # Clean slate.
    import psycopg
    with psycopg.connect(PG_DSN) as conn:
        conn.execute("TRUNCATE jobs RESTART IDENTITY")
        conn.commit()
    return s


@pg
def test_enqueue_claim_complete(store):
    jid, status = store.enqueue_job("h1", "generate_cpg", {"language": "c"})
    assert status == "submitted" and jid
    assert store.count_jobs("queued") == 1

    claimed = store.claim_next_job("generate_cpg")
    assert claimed["id"] == jid
    assert claimed["codebase_hash"] == "h1"
    assert claimed["payload"] == {"language": "c"}
    assert store.count_jobs("running") == 1

    store.complete_job(jid, result={"ok": True})
    assert store.get_job(jid)["status"] == "done"


@pg
def test_dedup_backpressure_and_skiplocked(store):
    id1, s1 = store.enqueue_job("h1", "generate_cpg", {})
    id2, s2 = store.enqueue_job("h1", "generate_cpg", {})
    assert s1 == "submitted" and s2 == "duplicate" and id1 == id2

    store.enqueue_job("h2", "generate_cpg", {})
    _id, full = store.enqueue_job("h3", "generate_cpg", {}, max_queued=2)
    assert full == "queue_full"

    # Two concurrent-style claims return distinct rows (SKIP LOCKED), oldest first.
    a = store.claim_next_job("generate_cpg")
    b = store.claim_next_job("generate_cpg")
    assert {a["codebase_hash"], b["codebase_hash"]} == {"h1", "h2"}
    assert a["codebase_hash"] == "h1"
    assert store.claim_next_job("generate_cpg") is None


@pg
def test_requeue_running(store):
    jid, _ = store.enqueue_job("h1", "generate_cpg", {})
    store.claim_next_job("generate_cpg")
    assert store.count_jobs("running") == 1
    assert store.requeue_running_jobs() == 1
    assert store.count_jobs("queued") == 1 and store.count_jobs("running") == 0
