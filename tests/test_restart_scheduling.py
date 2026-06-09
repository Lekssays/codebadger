"""Tests for #6: Joern-server restart scheduling from sync tools + zombie reconciliation.

The bug: get_cpg_status is a SYNC MCP tool, so FastMCP runs it in a worker thread
with no running event loop. The old code flipped status -> "loading" and then
asyncio.create_task() raised, dropping the coroutine and stranding the codebase
in "loading" forever. The fixes:
  * _schedule_restart_server_task falls back to run_coroutine_threadsafe on the
    captured main loop, and returns a bool (no longer raises).
  * get_cpg_status only persists "loading" when a restart actually started, and
    reconciles a stranded "loading" (with an error / no live task) to "failed".
  * _restart_server_async marks FAILED when the reload fails instead of READY.
"""

import asyncio
import threading
from unittest.mock import MagicMock

import pytest

import src.tools.core_tools as core_tools
from src.models import CodebaseInfo, SessionStatus
from src.services.codebase_tracker import CodebaseTracker

HASH = "abcdef0123456789"


# ── _schedule_restart_server_task ─────────────────────────────────────────────

def test_schedule_returns_true_when_already_active():
    services = {}
    active = MagicMock()
    active.done.return_value = False
    core_tools._get_restart_task_registry(services)[HASH] = active
    # Already running -> report success without creating a second task.
    assert core_tools._schedule_restart_server_task(HASH, "/p/cpg.bin", services) is True


def test_schedule_falls_back_to_main_loop_from_sync_thread(monkeypatch):
    ran = threading.Event()

    async def fake_restart(codebase_hash, container_cpg_path, services):
        ran.set()

    monkeypatch.setattr(core_tools, "_restart_server_async", fake_restart)

    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    try:
        services = {"event_loop": loop}
        # This test body runs with no running loop in this thread (the bug case).
        ok = core_tools._schedule_restart_server_task(HASH, "/p/cpg.bin", services)
        assert ok is True
        assert ran.wait(2.0), "restart coroutine was never run on the main loop"
    finally:
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=2)
        loop.close()


def test_schedule_returns_false_when_no_loop_available(monkeypatch):
    async def fake_restart(codebase_hash, container_cpg_path, services):
        pass  # must be closed cleanly by the scheduler, no "never awaited" warning

    monkeypatch.setattr(core_tools, "_restart_server_async", fake_restart)
    # No running loop here and no captured main loop -> cannot schedule.
    assert core_tools._schedule_restart_server_task(HASH, "/p/cpg.bin", {}) is False


# ── _restart_server_async terminal status ─────────────────────────────────────

@pytest.mark.asyncio
async def test_restart_marks_failed_when_reload_fails():
    mgr = MagicMock()
    mgr.spawn_server.return_value = 14000
    mgr.load_cpg.return_value = False  # reload fails
    tracker = MagicMock()
    services = {"joern_server_manager": mgr, "codebase_tracker": tracker}

    await core_tools._restart_server_async(HASH, "/playground/cpgs/x/cpg.bin", services)

    meta = tracker.update_codebase.call_args_list[-1].kwargs["metadata"]
    assert meta["status"] == SessionStatus.FAILED
    assert "error" in meta
    # Must NOT have been marked ready anywhere in this run.
    assert all(
        c.kwargs.get("metadata", {}).get("status") != SessionStatus.READY
        for c in tracker.update_codebase.call_args_list
    )


@pytest.mark.asyncio
async def test_restart_marks_ready_when_reload_succeeds():
    mgr = MagicMock()
    mgr.spawn_server.return_value = 14000
    mgr.load_cpg.return_value = True
    tracker = MagicMock()
    services = {"joern_server_manager": mgr, "codebase_tracker": tracker}

    await core_tools._restart_server_async(HASH, "/playground/cpgs/x/cpg.bin", services)

    statuses = [
        c.kwargs.get("metadata", {}).get("status")
        for c in tracker.update_codebase.call_args_list
    ]
    assert SessionStatus.READY in statuses
    assert SessionStatus.FAILED not in statuses


# ── get_cpg_status zombie reconciliation ──────────────────────────────────────

@pytest.mark.asyncio
async def test_get_cpg_status_reconciles_loading_with_error_to_failed():
    from fastmcp import FastMCP
    from fastmcp import Client
    from src.tools.core_tools import register_core_tools
    import json

    tracker = MagicMock(spec=CodebaseTracker)
    tracker.get_codebase.return_value = CodebaseInfo(
        codebase_hash=HASH,
        source_type="local",
        source_path="/src",
        language="c",
        cpg_path="/tmp/x.cpg",
        joern_port=None,
        metadata={
            "status": "loading",
            "error": "CPG generated but failed to load into Joern server",
            "container_cpg_path": f"/playground/cpgs/{HASH}/cpg.bin",
        },
    )
    services = {
        "codebase_tracker": tracker,
        "joern_server_manager": MagicMock(),
        "config": MagicMock(),
    }

    mcp = FastMCP("TestServer")
    register_core_tools(mcp, services)
    async with Client(mcp) as client:
        result = await client.call_tool("get_cpg_status", {"codebase_hash": HASH})
        data = json.loads(result.content[0].text)

    # A "loading" with a recorded error is a zombie -> surfaced as failed,
    # with the cause exposed so the caller stops polling forever.
    assert data["status"] == "failed"
    assert data.get("error")
    # And it must have been persisted back as failed.
    assert any(
        c.kwargs.get("metadata", {}).get("status") == SessionStatus.FAILED
        for c in tracker.update_codebase.call_args_list
    )
