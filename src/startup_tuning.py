"""Startup memory tuning for the CodeBadger MCP server.

Extracted from main.py: the logic that logs the host-memory recommendation and
auto-derives unset Joern memory limits before the Joern manager is constructed,
plus the pool-mode over-commit guard. Pure functions over `config` and the
environment — no server state — so they can be unit-tested in isolation.
"""

import logging
import os
import re

from src.utils import compute_recommendation, current_from_config, render_recommendation

logger = logging.getLogger(__name__)


def parse_mem_to_mb(value):
    """Parse a Docker-style memory string ('100g', '512m', '2048') to MB, or None."""
    if value is None:
        return None
    s = str(value).strip().lower().rstrip("b")
    m = re.match(r"^(\d+(?:\.\d+)?)\s*([gmk]?)$", s)
    if not m:
        return None
    factor = {"g": 1024, "m": 1, "k": 1 / 1024, "": 1}[m.group(2)]  # bare value treated as MB
    return int(float(m.group(1)) * factor)


def guard_pool_memory(config, rec) -> None:
    """Prevent pool-mode host over-commit by clamping the worker memory budget.

    The joern-server container (builds) is capped by JOERN_MEM_LIMIT and the
    query workers by memory_budget_mb; those are independent pools, so we hold
    build_cap + memory_budget <= joern_budget."""
    joern_budget_mb = rec.joern_budget_gb * 1024
    build_cap_mb = parse_mem_to_mb(os.getenv("JOERN_MEM_LIMIT"))
    if build_cap_mb is None:
        build_cap_mb = 100 * 1024  # docker-compose default when unset
    safe_worker_mb = joern_budget_mb - build_cap_mb
    min_worker_mb = min((t.container_cap_gb for t in rec.tiers), default=3) * 1024

    if safe_worker_mb < min_worker_mb:
        logger.warning(
            f"Pool mode: the build container cap (JOERN_MEM_LIMIT≈{build_cap_mb}MB) leaves only "
            f"{safe_worker_mb}MB for query workers within the {joern_budget_mb}MB Joern budget. "
            f"Lower JOERN_MEM_LIMIT to ~{rec.build_container_cap_gb}g (the build reserve) so workers "
            f"get ~{rec.query_budget_gb}GB. Forcing worker budget to {min_worker_mb}MB for now."
        )
        config.joern.memory_budget_mb = min_worker_mb
    elif config.joern.memory_budget_mb > safe_worker_mb:
        logger.warning(
            f"Pool-mode over-commit guard: build cap {build_cap_mb}MB + worker budget "
            f"{config.joern.memory_budget_mb}MB > Joern budget {joern_budget_mb}MB. Clamping worker "
            f"budget to {safe_worker_mb}MB. To regain capacity set JOERN_MEM_LIMIT="
            f"{rec.build_container_cap_gb}g (build-only) in docker-compose."
        )
        config.joern.memory_budget_mb = safe_worker_mb


def container_mem_limit_mb(joern_manager, container_name: str):
    """Actual mem_limit (MB) of the running build container, or None.

    A container's memory cap is fixed at `docker compose up` time, so this is the
    REAL limit in force — not whatever JOERN_MEM_LIMIT is set to for this process."""
    try:
        import docker

        client = getattr(joern_manager, "docker_client", None) or docker.from_env()
        container = client.containers.get(container_name)
        mem_bytes = (container.attrs.get("HostConfig", {}) or {}).get("Memory", 0)
        if mem_bytes and mem_bytes > 0:
            return int(mem_bytes / (1024 * 1024))
    except Exception:
        return None
    return None


def apply_startup_tuning(config) -> None:
    """Log the memory-aware recommendation and auto-derive unset memory limits.

    Logging is gated by RECOMMEND_ON_STARTUP (default on); the auto-tuning that
    fills in an unset Joern memory budget / RSS threshold from host RAM is gated
    by AUTO_TUNE_MEMORY (default on). Auto-tuning runs before the Joern manager
    is constructed so it picks up the derived values. Explicit config always
    wins — only values left at 0 are filled in."""
    try:
        rec = compute_recommendation(worker_mode=getattr(config.joern, "worker_mode", "shared"))
    except Exception as e:
        logger.warning(f"Could not compute startup config recommendation: {e}")
        return

    if os.getenv("RECOMMEND_ON_STARTUP", "true").lower() != "false":
        try:
            for line in render_recommendation(rec, current=current_from_config(config)).splitlines():
                logger.info(line)
        except Exception as e:
            logger.warning(f"Could not render startup recommendation: {e}")

    if os.getenv("AUTO_TUNE_MEMORY", "true").lower() == "false":
        return
    try:
        if getattr(config.joern, "memory_budget_mb", 0) <= 0:
            config.joern.memory_budget_mb = rec.query_budget_gb * 1024
            logger.info(
                f"Auto-tuned Joern memory_budget_mb={config.joern.memory_budget_mb} "
                f"({rec.query_budget_gb}GB query pool from {rec.host.total_mem_gb:g}GB host). "
                f"Set JOERN_MEMORY_BUDGET_MB or AUTO_TUNE_MEMORY=false to override."
            )
        if getattr(config.joern, "rss_eviction_threshold_mb", 0) <= 0:
            config.joern.rss_eviction_threshold_mb = rec.rss_eviction_threshold_mb
            logger.info(
                f"Auto-tuned Joern rss_eviction_threshold_mb={config.joern.rss_eviction_threshold_mb}"
            )
        # Pool mode: the build (joern-server) container cap and the worker
        # reservation ledger are SEPARATE memory pools. Keep their sum within the
        # Joern budget so they can't jointly over-commit host RAM.
        if getattr(config.joern, "worker_mode", "shared") == "pool":
            guard_pool_memory(config, rec)
    except Exception as e:
        logger.warning(f"Could not apply startup memory auto-tuning: {e}")
