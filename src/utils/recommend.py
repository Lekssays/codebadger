"""
Resource-aware configuration recommendations for CodeBadger.

CodeBadger fails under concurrent load when the configured Joern memory
footprint exceeds host RAM: the default 16 active servers x 4 GB heap = 64 GB
of query JVMs, plus build-worker JVMs, on a single Docker container with no
memory cap.  When that overshoots RAM the kernel OOM-killer reaps the whole
container and every Joern server dies at once.

This module computes a *memory-aware* configuration envelope from the host's
actual RAM and core count, so admission is bounded by memory rather than a
fixed server count.  It is consumed in two places:

  * main.py logs the recommendation (and flags drift from the live config)
    at startup, before the heavy service init -- so an operator sees the safe
    envelope before "munching" the server.
  * scripts/recommend_config.py prints it standalone, with copy-pasteable
    env-var and config.yaml snippets.

The numbers map onto the constants that exist today (a single global query
heap + a count cap).  The per-CPG size tiers (S/M/L/XL) are informational and
describe the memory-budget scheduler; see docs / the README.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# host detect

@dataclass
class HostSpec:
    """Detected (or supplied) host resources."""

    total_mem_gb: float
    cores: int
    source: str  # "psutil", "proc", or "manual"


def _detect_total_mem_gb() -> Optional[float]:
    """Return total physical RAM in GB, or None if it can't be determined."""
    try:
        import psutil

        return round(psutil.virtual_memory().total / (1024 ** 3), 1)
    except ImportError:
        pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return round(kb / (1024 ** 2), 1)
    except Exception:
        pass
    return None


def detect_host() -> HostSpec:
    """Detect host RAM and core count, falling back gracefully."""
    cores = os.cpu_count() or 4
    mem = _detect_total_mem_gb()
    if mem is not None:
        source = "psutil"
        try:
            import psutil  # noqa: F401
        except ImportError:
            source = "proc"
        return HostSpec(total_mem_gb=mem, cores=cores, source=source)
    # Last-resort default so callers never crash; clearly conservative.
    return HostSpec(total_mem_gb=16.0, cores=cores, source="manual")


# tier model

@dataclass
class Tier:
    name: str
    cpg_max_gb: Optional[float]  # upper bound of CPG .bin size; None = unbounded
    heap_gb: int                 # JVM -Xmx for this tier
    container_cap_gb: int        # cgroup --memory cap (heap + JVM/OS overhead)
    note: str = ""


# CPG on-disk size is a good proxy for the memory importCpg's overlay passes
# need.  These tiers are the memory-budget scheduler's placement sizes.
DEFAULT_TIERS: List[Tier] = [
    Tier("S", 1.0, 2, 3, "libsoup, small libxml2 modules"),
    Tier("M", 4.0, 6, 8, "ImageMagick, php, wireshark dissectors"),
    Tier("L", 12.0, 16, 20, "full wireshark, large php"),
    Tier("XL", None, 28, 32, "v8 (keep 1-2 concurrent)"),
]


def tier_for_cpg_size_gb(size_gb: float, tiers: List[Tier] = DEFAULT_TIERS) -> Tier:
    """Pick the smallest tier whose cpg_max_gb covers size_gb (XL is the catch-all)."""
    for tier in tiers:
        if tier.cpg_max_gb is None or size_gb <= tier.cpg_max_gb:
            return tier
    return tiers[-1]


# recommendation

@dataclass
class Recommendation:
    host: HostSpec
    headroom_gb: int          # reserved for OS + Docker + Postgres + Redis + API
    joern_budget_gb: int      # RAM available to all Joern JVMs (build + query)
    build_workers: int
    build_heap_gb: int
    build_reserve_gb: int     # build_workers * (build_heap + overhead)
    query_budget_gb: int      # joern_budget - build_reserve; the worker ledger budget
    query_heap_gb: int        # -Xmx for the standard query server (single-knob model)
    query_container_cap_gb: int
    max_active_servers: int
    max_mcp_connections: int
    rss_eviction_threshold_mb: int
    docker_mem_limit_gb: int  # mem_limit for the codebadger-joern-server container
    generation_timeout_s: int
    worker_mode: str = "shared"
    # In pool mode the joern-server container only builds CPGs, so its cap is the
    # build reserve; query servers run in separate cgroup-capped worker
    # containers bounded by query_budget. The invariant that prevents host
    # over-commit: build_container_cap_gb + query_budget_gb == joern_budget_gb.
    build_container_cap_gb: int = 0
    tiers: List[Tier] = field(default_factory=lambda: list(DEFAULT_TIERS))
    per_tier_capacity: Dict[str, int] = field(default_factory=dict)


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def compute(
    host: Optional[HostSpec] = None,
    *,
    query_heap_gb: int = 4,
    build_heap_gb: int = 6,
    headroom_gb: Optional[int] = None,
    build_workers: Optional[int] = None,
    generation_timeout_s: int = 1800,
    worker_mode: str = "shared",
    tiers: List[Tier] = DEFAULT_TIERS,
) -> Recommendation:
    """Compute a memory-aware configuration envelope for ``host``.

    The model: reserve headroom for non-Joern processes, split the rest between
    a generation reserve (build_workers x build-frontend heap) and a query pool,
    then size the query pool by how many standard-heap servers fit in its budget.
    """
    host = host or detect_host()
    total = host.total_mem_gb

    # Reserve ~15% (clamped to 12-24 GB) for OS, Docker daemon, Postgres, Redis,
    # and the stateless API workers.
    if headroom_gb is None:
        headroom_gb = int(_clamp(round(total * 0.15), 12, 24))
    headroom_gb = min(headroom_gb, int(total) - 4)  # never starve Joern entirely

    joern_budget = max(4, int(total) - headroom_gb)

    # Build workers: c2cpg & friends are multi-threaded, so prefer fewer workers
    # each with more cores over many thin ones.  ~1 worker per 16 cores, 2-6.
    if build_workers is None:
        build_workers = int(_clamp(host.cores // 16, 2, 6))

    overhead = 1  # GB of non-heap (metaspace, code cache, OS) per JVM/container
    build_reserve = build_workers * (build_heap_gb + overhead)
    # Don't let generation eat more than half the Joern budget.
    build_reserve = min(build_reserve, joern_budget // 2)

    query_budget = max(query_heap_gb + overhead, joern_budget - build_reserve)
    query_cap = query_heap_gb + overhead
    max_active = max(1, query_budget // query_cap)

    # MCP connection ceiling: one slot per active query server + build workers,
    # plus slack for status polls.  This keeps the 503 limit from throttling
    # legitimate concurrent work while still bounding it.
    max_mcp = max_active + build_workers + 8

    # Evict under memory pressure at 90% of the Joern budget (belt-and-braces on
    # top of the reservation ledger).
    rss_threshold_mb = int(joern_budget * 0.90 * 1024)

    # Per-tier "how many fit if every live CPG were this size" -- gives a feel for
    # the heterogeneous mix the memory-budget scheduler will admit.
    per_tier: Dict[str, int] = {}
    for tier in tiers:
        per_tier[tier.name] = max(0, int((query_budget * 1024) // (tier.container_cap_gb * 1024)))

    # Container mem_limit:
    #  - shared: one container holds builds + all query servers -> cap = joern_budget.
    #  - pool:   the joern-server container only builds; query servers live in
    #            separate cgroup-capped workers (budgeted by query_budget). So the
    #            build container cap is the build reserve, and
    #            build_container_cap + query_budget == joern_budget (no over-commit).
    build_container_cap = build_reserve if worker_mode == "pool" else joern_budget

    return Recommendation(
        host=host,
        headroom_gb=headroom_gb,
        joern_budget_gb=joern_budget,
        build_workers=build_workers,
        build_heap_gb=build_heap_gb,
        build_reserve_gb=build_reserve,
        query_budget_gb=query_budget,
        query_heap_gb=query_heap_gb,
        query_container_cap_gb=query_cap,
        max_active_servers=max_active,
        max_mcp_connections=max_mcp,
        rss_eviction_threshold_mb=rss_threshold_mb,
        docker_mem_limit_gb=build_container_cap,
        generation_timeout_s=generation_timeout_s,
        worker_mode=worker_mode,
        build_container_cap_gb=build_container_cap,
        tiers=list(tiers),
        per_tier_capacity=per_tier,
    )


# config compare

def _parse_xmx_gb(java_opts: Optional[str]) -> Optional[float]:
    """Extract the -Xmx heap size from a JAVA_OPTS string, in GB."""
    if not java_opts:
        return None
    m = re.search(r"-Xmx(\d+)([gGmMkK])", java_opts)
    if not m:
        return None
    value, unit = int(m.group(1)), m.group(2).lower()
    return {"g": value, "m": value / 1024, "k": value / (1024 ** 2)}[unit]


def current_from_config(config) -> Dict[str, object]:
    """Pull the live config values the recommendation speaks to (best-effort)."""
    try:
        return {
            "query_heap_gb": _parse_xmx_gb(getattr(config.joern, "java_opts", None)),
            "max_active_servers": getattr(config.joern, "max_active_servers", None),
            "rss_eviction_threshold_mb": getattr(config.joern, "rss_eviction_threshold_mb", None),
            "build_workers": getattr(config.cpg, "build_workers", None),
            "generation_timeout_s": getattr(config.cpg, "generation_timeout", None),
            "max_mcp_connections": int(os.getenv("MAX_MCP_CONNECTIONS", "0")) or None,
        }
    except Exception:
        return {}


def _drift_warnings(rec: Recommendation, current: Dict[str, object]) -> List[str]:
    """Flag live config that risks OOM or wasted capacity vs the recommendation."""
    warnings: List[str] = []
    heap = current.get("query_heap_gb")
    active = current.get("max_active_servers")
    if isinstance(heap, (int, float)) and isinstance(active, int):
        configured_query_gb = heap * active
        if configured_query_gb > rec.joern_budget_gb:
            warnings.append(
                f"max_active_servers={active} x {heap:g}GB heap = "
                f"{configured_query_gb:g}GB of query JVMs > {rec.joern_budget_gb}GB Joern "
                f"budget -- OOM-cascade risk. Lower to {rec.max_active_servers} or set a "
                f"Docker mem_limit."
            )
    rss = current.get("rss_eviction_threshold_mb")
    if rss in (0, None):
        warnings.append(
            "rss_eviction_threshold_mb is disabled (0) -- no memory-pressure backstop; "
            f"recommend {rec.rss_eviction_threshold_mb}."
        )
    gt = current.get("generation_timeout_s")
    if isinstance(gt, int) and gt < 1200:
        warnings.append(
            f"generation_timeout={gt}s is short for large repos (v8/wireshark); "
            f"recommend >= {rec.generation_timeout_s}s (or size-based)."
        )
    return warnings


# rendering

def render(rec: Recommendation, current: Optional[Dict[str, object]] = None) -> str:
    """Render a human-readable recommendation block with copy-paste snippets."""
    h = rec.host
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append("CodeBadger — recommended configuration (memory-aware)")
    lines.append("=" * 70)
    lines.append(
        f"Host: {h.total_mem_gb:g} GB RAM, {h.cores} cores  (detected via {h.source})"
    )
    lines.append(
        f"Budget: headroom={rec.headroom_gb}GB  joern={rec.joern_budget_gb}GB  "
        f"(generation reserve={rec.build_reserve_gb}GB, query pool={rec.query_budget_gb}GB)"
    )
    lines.append(f"Worker mode: {rec.worker_mode}")
    lines.append("-" * 70)
    lines.append("Recommended constants:")
    lines.append(f"  JOERN_JAVA_OPTS heap (-Xmx)   : {rec.query_heap_gb}G")
    lines.append(f"  MAX_ACTIVE_JOERN_SERVERS      : {rec.max_active_servers}")
    lines.append(f"  CPG_BUILD_WORKERS             : {rec.build_workers}")
    lines.append(f"  MAX_MCP_CONNECTIONS           : {rec.max_mcp_connections}")
    lines.append(f"  rss_eviction_threshold_mb     : {rec.rss_eviction_threshold_mb}")
    lines.append(f"  JOERN_MEMORY_BUDGET_MB        : {rec.query_budget_gb * 1024}  (worker ledger)")
    lines.append(f"  CPG_GENERATION_TIMEOUT        : {rec.generation_timeout_s}")
    lines.append(f"  docker-compose mem_limit      : {rec.docker_mem_limit_gb}g  (joern-server container)")
    if rec.worker_mode == "pool":
        lines.append(
            f"  -> pool mode invariant: build container cap ({rec.build_container_cap_gb}GB) "
            f"+ worker budget ({rec.query_budget_gb}GB) = joern budget ({rec.joern_budget_gb}GB)."
        )
        lines.append(
            f"     The joern-server container ONLY builds CPGs in pool mode, so set its "
            f"mem_limit to {rec.build_container_cap_gb}g (JOERN_MEM_LIMIT) — NOT the full budget."
        )
    lines.append("-" * 70)
    lines.append("Per-CPG size tiers (memory-budget scheduler):")
    lines.append(f"  {'tier':<5}{'CPG .bin':<14}{'heap':<7}{'cap':<7}{'fit*':<6}example")
    for t in rec.tiers:
        bound = "<=%g GB" % t.cpg_max_gb if t.cpg_max_gb is not None else "> prev"
        fit = rec.per_tier_capacity.get(t.name, 0)
        lines.append(
            f"  {t.name:<5}{bound:<14}{str(t.heap_gb)+'G':<7}{str(t.container_cap_gb)+'G':<7}"
            f"{fit:<6}{t.note}"
        )
    lines.append("  *fit = how many live CPGs of that tier fit the query pool alone")
    lines.append("-" * 70)
    lines.append("Env-var snippet:")
    lines.append(f"  export JOERN_JAVA_OPTS='-Xmx{rec.query_heap_gb}G -Xms2G -XX:+UseG1GC -XX:+UseStringDeduplication -Dfile.encoding=UTF-8'")
    lines.append(f"  export MAX_ACTIVE_JOERN_SERVERS={rec.max_active_servers}")
    lines.append(f"  export CPG_BUILD_WORKERS={rec.build_workers}")
    lines.append(f"  export MAX_MCP_CONNECTIONS={rec.max_mcp_connections}")
    lines.append(f"  export CPG_GENERATION_TIMEOUT={rec.generation_timeout_s}")
    lines.append(f"  export JOERN_MEMORY_BUDGET_MB={rec.query_budget_gb * 1024}")
    if rec.worker_mode == "pool":
        lines.append(f"  export JOERN_WORKER_MODE=pool")
        lines.append(f"  export JOERN_MEM_LIMIT={rec.build_container_cap_gb}g   # build container only")
    lines.append("")
    lines.append("config.yaml snippet:")
    lines.append("  joern:")
    lines.append(f"    java_opts: '-Xmx{rec.query_heap_gb}G -Xms2G -XX:+UseG1GC -XX:+UseStringDeduplication -Dfile.encoding=UTF-8'")
    lines.append(f"    max_active_servers: {rec.max_active_servers}")
    lines.append(f"    rss_eviction_threshold_mb: {rec.rss_eviction_threshold_mb}")
    lines.append("  cpg:")
    lines.append(f"    build_workers: {rec.build_workers}")
    lines.append(f"    generation_timeout: {rec.generation_timeout_s}")
    lines.append("")
    lines.append("docker-compose.yml snippet (cap the container so it can't OOM the host):")
    lines.append("  codebadger-joern-server:")
    lines.append(f"    mem_limit: {rec.docker_mem_limit_gb}g")
    lines.append(f"    cpus: {rec.host.cores}")

    if current:
        warnings = _drift_warnings(rec, current)
        if warnings:
            lines.append("-" * 70)
            lines.append("⚠ Live-config drift:")
            for w in warnings:
                lines.append(f"  ⚠ {w}")

    lines.append("=" * 70)
    return "\n".join(lines)
