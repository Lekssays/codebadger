"""Cache warm-up: sequential execution + off-critical-path scheduling.

warm_up_cache must run its default queries sequentially (they serialize on the
per-CPG query lock anyway) and keep going when one fails; _schedule_warmup must
fire-and-forget so it never blocks the build worker that calls it.
"""

import asyncio

import pytest

import src.tools.core_tools as core_tools
from src.services.code_browsing_service import CodeBrowsingService


def _make_service(calls, failing=()):
    """A CodeBrowsingService whose 5 warm-up queries just record their order."""
    svc = CodeBrowsingService.__new__(CodeBrowsingService)  # bypass __init__ deps

    def make(name):
        def _q(codebase_hash):
            calls.append(name)
            if name in failing:
                raise RuntimeError(f"{name} boom")
        return _q

    for name in ("list_methods", "list_files", "list_calls", "list_parameters", "find_literals"):
        setattr(svc, name, make(name))
    return svc


def test_warm_up_cache_runs_all_queries_in_order():
    calls = []
    _make_service(calls).warm_up_cache("h1")
    assert calls == ["list_methods", "list_files", "list_calls", "list_parameters", "find_literals"]


def test_warm_up_cache_continues_after_a_failing_query():
    calls = []
    # A failure in the middle must not abort the remaining warm-up queries.
    _make_service(calls, failing={"list_calls"}).warm_up_cache("h1")
    assert calls == ["list_methods", "list_files", "list_calls", "list_parameters", "find_literals"]


@pytest.mark.asyncio
async def test_schedule_warmup_is_fire_and_forget():
    ran = []

    class FakeSvc:
        def warm_up_cache(self, codebase_hash):
            ran.append(codebase_hash)

    services = {"code_browsing_service": FakeSvc()}
    assert core_tools._schedule_warmup(services, "h1") is None  # returns immediately

    for _ in range(100):
        if ran and not core_tools._warmup_tasks:
            break
        await asyncio.sleep(0.01)
    assert ran == ["h1"]
    assert core_tools._warmup_tasks == set()  # done-callback drained the registry


@pytest.mark.asyncio
async def test_schedule_warmup_swallows_warmup_errors():
    class FakeSvc:
        def warm_up_cache(self, codebase_hash):
            raise RuntimeError("boom")

    services = {"code_browsing_service": FakeSvc()}
    core_tools._schedule_warmup(services, "h1")  # must not raise

    for _ in range(100):
        if not core_tools._warmup_tasks:
            break
        await asyncio.sleep(0.01)
    assert core_tools._warmup_tasks == set()


def test_schedule_warmup_noop_without_service():
    core_tools._schedule_warmup({}, "h1")  # no code_browsing_service -> nothing scheduled
    assert core_tools._warmup_tasks == set()


def test_schedule_warmup_noop_without_running_loop():
    class FakeSvc:
        def warm_up_cache(self, codebase_hash):
            raise AssertionError("warm-up should not run without a loop")

    # Called from a sync context (no running loop) -> skipped, no error.
    core_tools._schedule_warmup({"code_browsing_service": FakeSvc()}, "h1")
