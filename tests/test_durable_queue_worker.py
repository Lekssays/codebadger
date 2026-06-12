"""Infra-free unit tests for DurableCPGQueue's worker loop (poll backoff).

These use a fake in-memory store, so they exercise the backoff/reset logic with
no Postgres — complementing the Postgres-gated tests in test_durable_queue.py.
"""

import asyncio

import pytest

import src.tools.core_tools as core_tools


class _FakeStore:
    """Minimal job-store stand-in: claim_next_job returns queued results in order."""

    def __init__(self, claim_results):
        self._claims = list(claim_results)
        self.completed = []
        self.failed = []

    def requeue_running_jobs(self):
        return 0

    def claim_next_job(self, job_type):
        return self._claims.pop(0) if self._claims else None

    def complete_job(self, job_id, result=None):
        self.completed.append(job_id)

    def fail_job(self, job_id, error):
        self.failed.append((job_id, error))


def _patch_sleep(monkeypatch, stop_after):
    """Record asyncio.sleep delays; abort the worker loop after ``stop_after``."""
    delays = []
    real_sleep = asyncio.sleep

    async def fake_sleep(delay):
        delays.append(delay)
        if len(delays) >= stop_after:
            raise asyncio.CancelledError
        await real_sleep(0)

    monkeypatch.setattr(core_tools.asyncio, "sleep", fake_sleep)
    return delays


@pytest.mark.asyncio
async def test_idle_poll_backs_off_exponentially_capped(monkeypatch):
    delays = _patch_sleep(monkeypatch, stop_after=5)
    store = _FakeStore([])  # queue always empty -> always idle
    q = core_tools.DurableCPGQueue(
        store, {}, workers=0, poll_interval=0.1, max_poll_interval=0.8
    )
    with pytest.raises(asyncio.CancelledError):
        await q._worker()
    # base, 2x, 4x, capped, capped
    assert delays == pytest.approx([0.1, 0.2, 0.4, 0.8, 0.8])


@pytest.mark.asyncio
async def test_backoff_resets_after_a_job_is_claimed(monkeypatch):
    async def fake_generate(**kwargs):
        return None

    monkeypatch.setattr(core_tools, "_generate_cpg_async", fake_generate)
    delays = _patch_sleep(monkeypatch, stop_after=4)
    # idle, idle, JOB, idle, idle
    store = _FakeStore(
        [None, None, {"id": 1, "payload": {}, "codebase_hash": "h"}, None, None]
    )
    q = core_tools.DurableCPGQueue(
        store, {}, workers=0, poll_interval=0.1, max_poll_interval=0.8
    )
    with pytest.raises(asyncio.CancelledError):
        await q._worker()
    # 0.1, 0.2 (backing off) -> job claimed (reset) -> 0.1, 0.2 again
    assert delays == pytest.approx([0.1, 0.2, 0.1, 0.2])
    assert store.completed == [1]


def test_max_poll_interval_never_below_base():
    store = _FakeStore([])
    q = core_tools.DurableCPGQueue(
        store, {}, workers=0, poll_interval=2.0, max_poll_interval=0.5
    )
    # A misconfigured max below the base must not shrink the base interval.
    assert q._max_poll_interval == 2.0
