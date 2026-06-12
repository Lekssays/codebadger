"""Health/status primitives for the CodeBadger MCP server.

Context-free helpers extracted from main.py: dependency-status rollup, the
bounded async liveness probe, process/host resource measurements, and the
output formatters. These take only their arguments (no server globals), so they
are unit-testable in isolation; main.py keeps the `services`-coupled
orchestration (`_build_health`, the catalog lookups, the periodic status log)
and imports these.
"""

import asyncio
import shutil


# Overall status / dependency vocabulary: up | partial | down.
def aggregate_status(dependencies: dict) -> str:
    """Roll per-dependency statuses into one overall up/partial/down value.

    `up` ONLY when every dependency is up. ANY dependency that is down makes the
    whole server `down` — every dependency here (Postgres, Redis, Docker, Joern,
    the CPG queue) is required for the server to do its job, so losing any one is
    a full outage, not a degradation. A dependency that is merely degraded
    (`partial`, e.g. Joern memory pressure or a full queue) reports as `partial`.
    """
    statuses = list(dependencies.values())
    if any(status == "down" for status in statuses):
        return "down"
    if any(status == "partial" for status in statuses):
        return "partial"
    return "up"


async def run_probe(fn, timeout: float = 2.0) -> dict:
    """Run a blocking liveness probe in a thread with a hard timeout.

    Never raises: a hung backend (dead socket, no connect timeout) resolves to
    {"ok": False, "error": ...} so /health always answers promptly instead of
    blocking the event loop. Returns whatever `fn` returns on success.
    """
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(loop.run_in_executor(None, fn), timeout=timeout)
    except asyncio.TimeoutError:
        return {"ok": False, "error": f"probe timed out after {timeout}s"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def const(value):
    return value


def format_uptime(seconds: float) -> str:
    s = int(seconds)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    minutes, s = divmod(s, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def get_process_memory_mb() -> float:
    try:
        import psutil
        return round(psutil.Process().memory_info().rss / (1024 ** 2), 1)
    except ImportError:
        pass
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    kb = int(line.split()[1])
                    return round(kb / 1024, 1)
    except Exception:
        pass
    return -1.0


def get_system_memory_available_gb() -> float:
    try:
        import psutil
        return round(psutil.virtual_memory().available / (1024 ** 3), 2)
    except ImportError:
        pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    return round(kb / (1024 ** 2), 2)
    except Exception:
        pass
    return -1.0


def get_disk_usage(path: str) -> dict:
    try:
        stat = shutil.disk_usage(path)
        return {
            "total_gb": round(stat.total / (1024 ** 3), 2),
            "used_gb": round(stat.used / (1024 ** 3), 2),
            "free_gb": round(stat.free / (1024 ** 3), 2),
            "percent_used": round((stat.used / stat.total) * 100, 1) if stat.total > 0 else 0,
        }
    except Exception as e:
        return {"error": str(e)}


def format_codebase_source(source_type: str, source_path: str, include_sensitive: bool = False) -> str:
    """Format a codebase source for operator output.

    Health responses default to redacted values so repository locations are not
    exposed. Internal status logs can opt into the original source path.
    """
    if include_sensitive:
        return source_path
    return f"<redacted:{source_type or 'unknown'}>"


def describe_joern_container_issue(container_info: dict):
    """Return a user-facing issue string for the current Joern container state."""
    status = container_info.get("status")
    container_name = container_info.get("container_name", "codebadger-joern-server")

    if status == "running":
        return None
    if status == "not_found":
        return f"Joern Docker container '{container_name}' not found"
    if status == "docker_unavailable":
        return f"Cannot connect to Docker daemon: {container_info.get('error', 'Docker unavailable')}"
    if status == "error":
        return f"Failed to inspect Joern Docker container '{container_name}': {container_info.get('error', 'unknown error')}"
    return f"Joern Docker container '{container_name}' is not running"
