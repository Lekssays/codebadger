"""
Joern Server Manager for spawning and managing individual Joern server instances per CPG
"""

import asyncio
import logging
import re
import threading
import time
import os
from collections import OrderedDict
from typing import Callable, Dict, Optional, Tuple, TYPE_CHECKING

import docker
from docker.errors import DockerException, NotFound, APIError, ImageNotFound

from .port_manager import PortManager
from ..models import SessionStatus
from ..utils.recommend import tier_for_cpg_size_gb

if TYPE_CHECKING:
    from ..services.codebase_tracker import CodebaseTracker

logger = logging.getLogger(__name__)

class JoernServerManager:
    """Manages individual Joern server instances running in Docker container using Docker Python API"""

    def __init__(
        self,
        joern_binary_path: str = "joern",
        container_name: str = "codebadger-joern-server",
        config=None,
        codebase_tracker: Optional["CodebaseTracker"] = None,
        max_active_servers: Optional[int] = None,
        redis_url: Optional[str] = None,
    ):
        self.joern_binary = joern_binary_path
        self.container_name = container_name
        self.config = config
        self.codebase_tracker = codebase_tracker

        # Worker mode. "shared": Joern servers are processes inside the
        # single build container. "pool": each CPG gets its own cgroup-capped
        # container so an OOM isolates to one worker. Pool workers publish to a
        # disjoint host-port range so they don't collide with the shared
        # container's published 13371-13870 range.
        self.worker_mode = (config.joern.worker_mode if config else "shared")
        self.worker_image = (config.joern.worker_image if config else "codebadger-joern-server:latest")
        self.worker_internal_port = (config.joern.worker_internal_port if config else 8080)
        self.docker_network = (config.joern.docker_network if config else "")
        if self.worker_mode == "pool" and config:
            self.port_manager = PortManager(
                port_min=config.joern.worker_port_min, port_max=config.joern.worker_port_max
            )
        elif config:
            self.port_manager = PortManager(port_min=config.joern.port_min, port_max=config.joern.port_max)
        else:
            self.port_manager = PortManager()

        # Host path bind-mounted as /playground into pool workers. Derive from
        # the repo layout (src/services/ -> project root) when not configured.
        configured_pg = getattr(config.joern, "playground_host_path", "") if config else ""
        self.playground_host_path = configured_pg or os.path.abspath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "playground")
        )

        self.docker_client = docker.from_env()
        self._exec_ids: Dict[str, str] = {}
        self._ports: Dict[str, int] = {}
        self._clients: Dict[str, "JoernServerClient"] = {}
        # Pool mode: codebase_hash -> worker container name.
        self._worker_containers: Dict[str, str] = {}
        # Hashes with an in-flight spawn, so a concurrent spawn of the same
        # codebase (watchdog respawn vs query auto-wake) can't start a duplicate.
        self._spawning: set = set()

        # LRU pool
        if max_active_servers is not None:
            self._max_active = max_active_servers
        elif config:
            self._max_active = config.joern.max_active_servers
        else:
            self._max_active = 3
        self._lru: OrderedDict[str, None] = OrderedDict()
        self._lru_eviction_count: int = 0
        # Cause of the most recent load_cpg() (a JoernServerClient._VERIFY_* value
        # or "error"), captured before the server is torn down so reload_with_retry
        # can skip retrying a genuinely empty build.
        self._last_load_cause: Optional[str] = None

        # Memory-aware admission. When _memory_budget_mb > 0, servers
        # are admitted while the sum of per-CPG heap reservations stays under the
        # budget, evicting LRU to make room — memory, not a fixed count, is the
        # real concurrency limit. _reservations maps codebase_hash -> reserved MB.
        self._memory_budget_mb: int = (
            config.joern.memory_budget_mb if config else 0
        )
        self._reservations: Dict[str, int] = {}
        # Guards the admission/reservation bookkeeping (_reservations, _ports,
        # _lru) since spawn_server/load_cpg run in thread-pool executors and can
        # be entered concurrently by several CPG-build workers. Reentrant so the
        # nested spawn -> _make_room -> _evict -> terminate_server -> _cleanup
        # call chain on one thread doesn't self-deadlock.
        self._state_lock = threading.RLock()

        # Shared pool state in Redis so several processes coordinate spawn/evict
        # without over-committing or double-spawning. Only in pool mode (worker
        # containers are discoverable by name/port across processes).
        self._redis_pool = None
        if self.worker_mode == "pool" and redis_url:
            try:
                from .pool_store import RedisPoolStore
                self._redis_pool = RedisPoolStore(redis_url)
                logger.info("Pool state backed by Redis (multi-process coordination enabled)")
            except Exception as e:
                logger.warning(f"Redis pool store unavailable ({e}); using in-process pool state")
                self._redis_pool = None

        # Idle reaping: offload a worker not queried for _idle_ttl_seconds so it
        # stops pinning RAM; the next query reactivates it. _last_touch tracks the
        # local (non-Redis) last-query time; Redis mode reads the LRU ZSET score.
        self._idle_ttl_seconds: int = (config.joern.idle_ttl_seconds if config else 600)
        self._reaper_interval: int = (config.joern.reaper_interval_seconds if config else 60)
        self._last_touch: Dict[str, float] = {}

        self._watchdog_task: Optional[asyncio.Task] = None
        self._reaper_task: Optional[asyncio.Task] = None
        # Injected by main.py after tools are registered so the watchdog goes
        # through the shared dedup registry instead of spawning its own tasks.
        self._restart_callback: Optional[Callable[[str, str], bool]] = None

        # Pool mode: a previous run may have left worker containers behind. Clear
        # them so stale servers don't hold ports/memory or shadow fresh spawns.
        if self.worker_mode == "pool":
            self._cleanup_orphan_workers()

    def set_restart_callback(self, callback: Callable[[str, str], bool]) -> None:
        """Wire in the shared restart-dedup registry from core_tools.

        The callback receives (codebase_hash, cpg_path) and returns True when a
        new restart task was scheduled, False when one is already in-flight.
        Must be called after MCP tools are registered so the services dict is
        fully populated.
        """
        self._restart_callback = callback

    def _touch(self, codebase_hash: str) -> None:
        if self._redis_pool:
            self._redis_pool.touch(codebase_hash)
            return
        # Guard the OrderedDict: _make_room iterates _lru under the lock, and
        # query-path callers (get_or_create_client) touch concurrently from
        # other threads — an unguarded mutation here can corrupt that iteration.
        with self._state_lock:
            self._lru.pop(codebase_hash, None)
            self._lru[codebase_hash] = None
            self._last_touch[codebase_hash] = time.time()

    def _container_memory_mb(self) -> float:
        """Return the Docker container's current RSS in MB (0.0 on any error)."""
        try:
            container = self.docker_client.containers.get(self.container_name)
            stats = container.stats(stream=False)
            usage = stats.get("memory_stats", {}).get("usage", 0)
            return usage / (1024 * 1024)
        except Exception:
            return 0.0

    def _rss_limit_mb(self) -> int:
        if self.config and hasattr(self.config.joern, "rss_eviction_threshold_mb"):
            return self.config.joern.rss_eviction_threshold_mb or 0
        return 0

    def _current_reserved_mb(self) -> int:
        if self._redis_pool:
            return self._redis_pool.total_reserved_mb()
        return sum(self._reservations.values())

    def _evict(self, codebase_hash: str) -> None:
        """Tear down a server and mark its codebase sleeping.

        The local-state mutations are guarded by ``_state_lock`` directly: the
        local spawn path already holds it (reentrant, so this is a no-op re-entry),
        while the Redis make-room path holds only the Redis admit lock and would
        otherwise touch the in-process dicts unguarded.
        """
        logger.info(f"Evicting Joern server: {codebase_hash}")
        # terminate_server -> _cleanup_server releases the port, reservation and
        # LRU entry; we only add the sleeping-status bookkeeping on top.
        terminated = self.terminate_server(codebase_hash)
        with self._state_lock:
            # terminate_server -> _cleanup_server normally frees these, but it
            # no-ops when the hash isn't in _exec_ids; release defensively so the
            # budget loop can't leak a reservation and spin / under-admit.
            self._lru.pop(codebase_hash, None)
            self._reservations.pop(codebase_hash, None)
            self._last_touch.pop(codebase_hash, None)
            self._lru_eviction_count += 1
            # Always return the host port to the pool on eviction. _cleanup_server
            # frees it on the normal path, but when terminate_server no-ops (hash
            # out of sync with _exec_ids) that never runs — release here so an
            # evicted CPG can never strand its port. release_port is idempotent.
            if not terminated and self.port_manager.get_port(codebase_hash) is not None:
                self.port_manager.release_port(codebase_hash)
        # In Redis pool mode the make-room loops drive eviction off the SHARED
        # ledger (rp.oldest()/total_reserved_mb()), but a stale LRU/reservation
        # entry with no matching registry port makes terminate_server return
        # False before _cleanup_server runs -> the shared entry is never purged
        # and the loop re-picks the same victim forever ("No server found" spin).
        # Purge it directly here (frees the registry port too); release() is idempotent.
        if self._redis_pool and not terminated:
            self._redis_pool.release(codebase_hash)
        if self.codebase_tracker:
            try:
                self.codebase_tracker.update_codebase(
                    codebase_hash,
                    joern_port=None,
                    metadata={"status": SessionStatus.SLEEPING},
                )
            except Exception as e:
                logger.warning(f"Failed to update sleeping status for {codebase_hash}: {e}")

    def _evict_ledger(self, codebase_hash: str) -> Tuple[str, str]:
        """Free a victim's ledger + local state WITHOUT the blocking Docker
        teardown; return ``(codebase_hash, container_name)`` to remove later.

        Redis make-room only. Releasing the reservation/port in the shared ledger
        here (fast Redis ops) lets the make-room loop see reclaimed capacity
        immediately, while the slow ``docker remove --force`` is deferred to
        ``_reap_evicted`` off the global admit lock (HIGH-1: a container teardown
        under that lock serializes every process's admission on Docker I/O).
        """
        rp = self._redis_pool
        # Resolve the container name before we drop the registry entry.
        name = (
            self._worker_containers.get(codebase_hash)
            or (rp.get_worker(codebase_hash) if rp else None)
            or self._worker_name(codebase_hash)
        )
        # Free the shared ledger (reservation + port + worker + LRU) so the loop's
        # budget/port checks see the reclaimed capacity. Idempotent.
        if rp:
            rp.release(codebase_hash)
        with self._state_lock:
            self._exec_ids.pop(codebase_hash, None)
            self._ports.pop(codebase_hash, None)
            self._reservations.pop(codebase_hash, None)
            self._worker_containers.pop(codebase_hash, None)
            self._lru.pop(codebase_hash, None)
            self._last_touch.pop(codebase_hash, None)
            self._lru_eviction_count += 1
            # Local PortManager isn't the allocation authority in Redis mode, but
            # release defensively in case this hash was ever locally tracked.
            if self.port_manager.get_port(codebase_hash) is not None:
                self.port_manager.release_port(codebase_hash)
        # Drop the cached HTTP client; its worker is going away.
        client = self._clients.pop(codebase_hash, None)
        if client:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Error closing HTTP session for {codebase_hash}: {e}")
        return codebase_hash, name

    def _reap_evicted(self, victims: list) -> None:
        """Tear down ledger-evicted victims' containers, OFF the admit lock.

        Called after ``_spawn_server_redis`` drops the global admit lock so the
        blocking ``docker remove --force`` doesn't serialize other processes'
        admissions, and before the new worker publishes its port so the host port
        is guaranteed free. Marks each codebase SLEEPING once its container is
        gone. Best-effort; a failure here doesn't abort the spawn.
        """
        for codebase_hash, name in victims:
            try:
                self._remove_worker_container(name)
                logger.info(f"Reaped evicted worker {name} ({codebase_hash})")
            except Exception as e:
                logger.warning(f"Failed to reap evicted worker {name}: {e}")
            if self.codebase_tracker:
                try:
                    self.codebase_tracker.update_codebase(
                        codebase_hash,
                        joern_port=None,
                        metadata={"status": SessionStatus.SLEEPING},
                    )
                except Exception as e:
                    logger.warning(f"Failed to update sleeping status for {codebase_hash}: {e}")

    def _evict_under_rss_pressure(self) -> None:
        """Evict the LRU server if container RSS is over the configured threshold.

        Shared mode only: it measures the single container's RSS. In pool mode
        query servers live in separate containers each hard-capped by their own
        cgroup, so per-container limits — not this aggregate — govern memory.
        """
        if self.worker_mode == "pool":
            return
        limit = self._rss_limit_mb()
        if limit <= 0 or not self._lru:
            return
        rss_mb = self._container_memory_mb()
        if rss_mb >= limit:
            lru_hash = next(iter(self._lru))
            logger.warning(
                f"Container RSS {rss_mb:.0f} MB >= threshold {limit} MB — "
                f"evicting LRU server {lru_hash} under memory pressure"
            )
            self._evict(lru_hash)

    def _make_room(self, needed_mb: int) -> list:
        """Evict servers so a new ``needed_mb`` reservation can be admitted.

        Memory mode (budget > 0): evict LRU until the reservation fits the
        budget; the count cap then acts only as a safety ceiling. Legacy mode
        (budget == 0): the original count-based single eviction. Both then apply
        the RSS-pressure backstop.

        Returns a list of ``(codebase_hash, container_name)`` victims whose
        *ledger* entries were freed but whose containers still need removing — the
        Redis caller reaps them via ``_reap_evicted`` AFTER dropping the admit
        lock. The non-Redis branches evict synchronously and return ``[]``.

        Locking: the local (non-Redis) branch reads in-process state and must be
        called with ``_state_lock`` held; it evicts synchronously via ``_evict``.
        The Redis branch is serialized across processes by the caller's Redis
        admit lock. Crucially it does NOT do the blocking ``docker remove`` under
        that lock — that would serialize every process's admission on Docker I/O
        (HIGH-1). ``_evict_ledger`` frees the shared ledger entry (so the loop
        sees reclaimed capacity immediately) and defers the container teardown to
        the caller, off the lock.
        """
        if self._redis_pool:
            # Multi-process: evict from the GLOBAL ledger/LRU. Caller holds the
            # Redis admit lock, so make-room + allocate + reserve are atomic
            # across processes. Eviction frees the ledger for whichever worker is
            # globally oldest, even if another process spawned it.
            rp = self._redis_pool
            pmin, pmax = self.port_manager.port_min, self.port_manager.port_max
            # Track victims we've already evicted this call. _evict_ledger purges
            # the shared ledger, but excluding seen hashes is a belt-and-suspenders
            # against a Redis hiccup leaving an entry behind: never re-pick the
            # same victim, so the loop always terminates.
            seen: set[str] = set()
            evicted: list = []
            if self._memory_budget_mb > 0:
                while rp.total_reserved_mb() + needed_mb > self._memory_budget_mb:
                    victim = rp.oldest(exclude=seen)
                    if not victim:
                        break
                    seen.add(victim)
                    evicted.append(self._evict_ledger(victim))
            while rp.allocate_port(pmin, pmax) is None:
                victim = rp.oldest(exclude=seen)
                if not victim:
                    break
                seen.add(victim)
                evicted.append(self._evict_ledger(victim))
            return evicted

        if self._memory_budget_mb > 0:
            # Memory governs admission — not a fixed server count — so a batch of
            # many small (tier-S) CPGs can run far more servers concurrently than
            # max_active_servers would allow, while a few large ones run fewer.
            # The port pool (500 ports) is the only remaining hard ceiling.
            while self._lru and (self._current_reserved_mb() + needed_mb > self._memory_budget_mb):
                lru_hash = next(iter(self._lru))
                logger.info(
                    f"Memory budget: reserved {self._current_reserved_mb()}MB + "
                    f"need {needed_mb}MB > budget {self._memory_budget_mb}MB — evicting {lru_hash}"
                )
                self._evict(lru_hash)
            # Port-pool pressure: with the count cap gone, memory may admit more
            # servers than we have ports for. Evict LRU to free a port so
            # allocate_port() below can't raise "no available ports".
            while self._lru and self.port_manager.available_count() <= 0:
                lru_hash = next(iter(self._lru))
                logger.info(f"Port pool exhausted — evicting LRU {lru_hash} to free a port")
                self._evict(lru_hash)
            self._evict_under_rss_pressure()
            return []

        # Legacy count-based behavior.
        if len(self._ports) >= self._max_active and self._lru:
            self._evict(next(iter(self._lru)))
        self._evict_under_rss_pressure()
        return []

    # heap sizing (B?)

    def _default_heap_gb(self) -> int:
        """Heap (GB) from the configured JAVA_OPTS -Xmx, defaulting to 4."""
        opts = (self.config.joern.java_opts if self.config else "") or ""
        m = re.search(r"-Xmx(\d+)([gGmMkK])", opts)
        if m:
            value, unit = int(m.group(1)), m.group(2).lower()
            if unit == "g":
                return max(1, value)
            if unit == "m":
                return max(1, value // 1024)
            return max(1, value // (1024 ** 2))
        return 4

    def _cpg_size_gb(self, codebase_hash: str) -> Optional[float]:
        """Size of the codebase's CPG .bin on disk in GB, or None if unknown."""
        if not self.codebase_tracker:
            return None
        try:
            info = self.codebase_tracker.get_codebase(codebase_hash)
            if info and info.cpg_path and os.path.exists(info.cpg_path):
                return os.path.getsize(info.cpg_path) / (1024 ** 3)
        except Exception as e:
            logger.debug(f"Could not stat CPG for {codebase_hash}: {e}")
        return None

    def _plan_server(self, codebase_hash: str) -> Tuple[int, int]:
        """Decide (heap_gb, reservation_mb) for a server.

        In memory mode, size the heap to the CPG's on-disk size via the S/M/L/XL
        tiers (importCpg's overlay passes need roughly as much RAM as the CPG is
        large). When the size is unknown or memory mode is off, fall back to the
        single configured heap.
        """
        default_heap = self._default_heap_gb()
        if self._memory_budget_mb > 0:
            size_gb = self._cpg_size_gb(codebase_hash)
            if size_gb is not None:
                tier = tier_for_cpg_size_gb(size_gb)
                logger.info(
                    f"Sizing {codebase_hash}: CPG {size_gb:.2f}GB -> tier {tier.name} "
                    f"(heap {tier.heap_gb}G, reserve {tier.container_cap_gb}G)"
                )
                return tier.heap_gb, tier.container_cap_gb * 1024
        return default_heap, (default_heap + 1) * 1024

    def _java_opts_for(self, heap_gb: int) -> str:
        """Render JAVA_OPTS with -Xmx/-Xms set to this server's tiered heap."""
        base = (self.config.joern.java_opts if self.config else "") or ""
        xms = min(2, heap_gb)
        if not base:
            return (
                f"-Xmx{heap_gb}G -Xms{xms}G -XX:+UseG1GC "
                f"-XX:+UseStringDeduplication -Dfile.encoding=UTF-8"
            )
        opts = re.sub(r"-Xmx\d+[gGmMkK]", f"-Xmx{heap_gb}G", base)
        if "-Xmx" not in opts:
            opts = f"-Xmx{heap_gb}G {opts}"
        # Keep -Xms <= heap so the JVM doesn't refuse to start on small tiers.
        if "-Xms" in opts:
            opts = re.sub(r"-Xms\d+[gGmMkK]", f"-Xms{xms}G", opts)
        return opts

    def _joern_endpoint(self, codebase_hash: str, port: int) -> tuple:
        """Return (host, port) for connecting to a Joern server.

        Pool mode with docker_network: container name on the fixed internal port
        (no host port published). Otherwise: server_host and the allocated port.
        """
        if self.worker_mode == "pool" and self.docker_network:
            return (self._worker_name(codebase_hash), self.worker_internal_port)
        host = self.config.joern.server_host if self.config else "localhost"
        return (host, port)

    def _port_healthy(self, port: int, codebase_hash: str = "") -> bool:
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            host, conn_port = self._joern_endpoint(codebase_hash, port)
            result = sock.connect_ex((host, conn_port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _spawn_server_redis(self, codebase_hash: str) -> int:
        """Pool-mode spawn coordinated across processes via Redis.

        Holds a per-CPG spawn lock so only one process spawns a given CPG;
        discovers a worker another process already started; admits under the
        global lock so the memory ledger / port pool can't over-commit.
        """
        rp = self._redis_pool
        with rp.spawn_lock(codebase_hash):
            existing = rp.get_port(codebase_hash)
            if existing is not None:
                if self._port_healthy(existing, codebase_hash):
                    # Another process already runs this CPG — adopt it locally.
                    self._ports[codebase_hash] = existing
                    self._exec_ids[codebase_hash] = f"exec-{codebase_hash}"
                    self._worker_containers[codebase_hash] = (
                        rp.get_worker(codebase_hash) or self._worker_name(codebase_hash)
                    )
                    rp.touch(codebase_hash)
                    logger.info(f"Adopted existing worker for {codebase_hash} on port {existing}")
                    return existing
                logger.warning(f"Stale registry entry for {codebase_hash} (port {existing} dead); cleaning")
                self.terminate_server(codebase_hash)

            heap_gb, reserve_mb = self._plan_server(codebase_hash)
            pending_kills: list = []
            try:
                with rp.admit_lock():
                    pending_kills = self._make_room(reserve_mb)
                    port = rp.allocate_port(self.port_manager.port_min, self.port_manager.port_max)
                    if port is None:
                        raise RuntimeError("No free worker ports available")
                    # Reserve + register port + touch LRU as ONE transaction so a
                    # crash here can't leave a half-claimed (reserved-but-unregistered)
                    # entry that make-room would spin on.
                    rp.claim(codebase_hash, port, reserve_mb)
            finally:
                # Reap evicted victims' containers HERE, off the admit lock and
                # whether or not we got a port: _make_room already freed their
                # ledger entries, so the containers must be removed regardless to
                # avoid orphans. Doing it before the publish below also guarantees
                # the host port is free when the new worker binds it.
                self._reap_evicted(pending_kills)

            java_opts = self._java_opts_for(heap_gb)
            logger.info(
                f"Starting pooled Joern server for {codebase_hash} on port {port} "
                f"(heap {heap_gb}G, reserve {reserve_mb}MB)"
            )
            # Mark as spawning so the watchdog won't health-check (and kill) this
            # server while its JVM is still booting. The port is registered in
            # self._ports below, before _wait_for_server returns, so without this
            # guard a watchdog tick landing mid-boot would terminate a server that
            # simply hasn't bound its port yet (the cause of the "is dead,
            # respawning" 4s after launch churn under host load).
            self._spawning.add(codebase_hash)
            try:
                try:
                    self._start_worker_container(codebase_hash, port, java_opts, reserve_mb)
                    rp.set_worker(codebase_hash, self._worker_name(codebase_hash))
                    self._exec_ids[codebase_hash] = f"exec-{codebase_hash}"
                    self._ports[codebase_hash] = port
                except Exception as e:
                    logger.error(f"Failed to start pooled worker for {codebase_hash}: {e}")
                    self.terminate_server(codebase_hash)  # rm container + release Redis state
                    raise

                startup_timeout = self.config.joern.server_startup_timeout if self.config else 120
                if self._wait_for_server(port, timeout=startup_timeout, codebase_hash=codebase_hash):
                    rp.touch(codebase_hash)
                    logger.info(f"Pooled Joern server for {codebase_hash} ready on port {port}")
                    return port
                logger.error(f"Pooled Joern server for {codebase_hash} failed to become ready on port {port}")
                self._dump_server_log(codebase_hash)
                self.terminate_server(codebase_hash)
                raise RuntimeError(f"Pooled Joern server for {codebase_hash} failed to start on port {port}")
            finally:
                self._spawning.discard(codebase_hash)

    def spawn_server(self, codebase_hash: str) -> int:
        if self._redis_pool:
            return self._spawn_server_redis(codebase_hash)
        try:
            # Fast path: a healthy server already exists.
            if codebase_hash in self._ports and self.is_server_running(codebase_hash):
                self._touch(codebase_hash)
                return self._ports[codebase_hash]

            # Size the heap to the CPG (DB stat) before taking the lock.
            heap_gb, reserve_mb = self._plan_server(codebase_hash)

            with self._state_lock:
                # Guard against a second concurrent spawn of the SAME codebase
                # (e.g. a watchdog respawn racing a query-path auto-wake) starting
                # a duplicate process/container on a second port.
                if codebase_hash in self._spawning:
                    raise RuntimeError(f"Spawn already in progress for {codebase_hash}")
                if codebase_hash in self._ports:
                    # Registered but not healthy (fast path didn't return) — stale.
                    logger.warning(f"Server for {codebase_hash} registered but not running, cleaning up")
                    self._cleanup_server(codebase_hash)
                # Evict under the lock so concurrent build workers can't both
                # decide there is room. Reservation recorded up front;
                # _cleanup_server releases it if the spawn fails.
                self._make_room(reserve_mb)
                port = self.port_manager.allocate_port(codebase_hash)
                self._reservations[codebase_hash] = reserve_mb
                self._spawning.add(codebase_hash)

            try:
                java_opts = self._java_opts_for(heap_gb)
                logger.info(
                    f"Starting Joern server for {codebase_hash} on port {port} "
                    f"(mode={self.worker_mode}, heap {heap_gb}G, reserve {reserve_mb}MB)"
                )

                try:
                    if self.worker_mode == "pool":
                        self._start_worker_container(codebase_hash, port, java_opts, reserve_mb)
                    else:
                        self._start_shared_exec(codebase_hash, port, java_opts)
                except NotFound:
                    # Shared build container missing (shared mode) or image missing.
                    logger.error(f"Container/image not found while spawning {codebase_hash}")
                    self._release_reservation(codebase_hash)
                    self.port_manager.release_port(codebase_hash)
                    raise RuntimeError(f"Container {self.container_name} not found")

                with self._state_lock:
                    self._exec_ids[codebase_hash] = f"exec-{codebase_hash}"
                    self._ports[codebase_hash] = port

                conn_host, conn_port = self._joern_endpoint(codebase_hash, port)
                logger.info(f"Joern server starting, waiting for readiness at {conn_host}:{conn_port}...")

                startup_timeout = self.config.joern.server_startup_timeout if self.config else 120
                if self._wait_for_server(port, timeout=startup_timeout, codebase_hash=codebase_hash):
                    self._touch(codebase_hash)
                    logger.info(f"Joern server for {codebase_hash} started successfully on port {port}")
                    return port
                else:
                    logger.error(f"Joern server for {codebase_hash} failed to become ready on port {port}")
                    self._dump_server_log(codebase_hash)
                    self._cleanup_server(codebase_hash)
                    raise RuntimeError(f"Joern server for {codebase_hash} failed to start on port {port}")
            finally:
                with self._state_lock:
                    self._spawning.discard(codebase_hash)

        except DockerException as e:
            logger.error(f"Docker error while spawning Joern server for {codebase_hash}: {e}", exc_info=True)
            self._cleanup_server(codebase_hash)
            raise
        except Exception as e:
            logger.error(f"Failed to spawn Joern server for {codebase_hash}: {e}", exc_info=True)
            self._cleanup_server(codebase_hash)
            raise

    def _worker_name(self, codebase_hash: str) -> str:
        return f"codebadger-joern-{codebase_hash}"

    def _start_shared_exec(self, codebase_hash: str, port: int, java_opts: str) -> None:
        """Shared mode: run a Joern server process inside the build container."""
        container = self.docker_client.containers.get(self.container_name)  # NotFound -> caller
        # Ensure no stale JVM still holds the port (terminate releases the port
        # in our state before the SIGTERM'd JVM has actually exited).
        self._ensure_port_free(container, port)
        work_dir = f"/tmp/joern-server-{codebase_hash}"
        log_file = f"/tmp/joern-{codebase_hash}.log"
        java_opts_export = f"export JAVA_OPTS='{java_opts}' && " if java_opts else ""
        joern_cmd = [
            "bash", "-c",
            f"{java_opts_export}mkdir -p '{work_dir}' && cd '{work_dir}' && "
            f"nohup /opt/joern/joern-cli/joern --server --server-host 0.0.0.0 "
            f"--server-port {port} > '{log_file}' 2>&1 &",
        ]
        container.exec_run(cmd=joern_cmd, detach=True, stream=False)

    def _start_worker_container(self, codebase_hash: str, port: int, java_opts: str, mem_limit_mb: int) -> None:
        """Pool mode: launch a dedicated cgroup-capped container for this CPG.

        Joern binds worker_internal_port inside the container's own network
        namespace and we publish it to 0.0.0.0:<port> on the host so the MCP
        can reach it via host.docker.internal:<port> when running in a bridge
        network (macOS Docker Desktop). On Linux the port is still only reachable
        from the local machine unless your firewall is open. The mem_limit is the
        tier reservation, so an OOM kills only this container.
        """
        name = self._worker_name(codebase_hash)
        # Clear any stale container with the same name so the run() can't collide.
        self._remove_worker_container(name)

        if self.docker_network:
            # Bridge-network mode: attach to the named network so the MCP can
            # reach this worker by container name — no host port published.
            logger.info(
                f"Launching worker container {name} (image {self.worker_image}, "
                f"mem_limit {mem_limit_mb}MB) on network {self.docker_network}:{self.worker_internal_port}"
            )
            run_kwargs: dict = dict(
                network=self.docker_network,
            )
        else:
            # Host-port mode (legacy / running MCP on the host directly).
            # Removing the previous container doesn't synchronously release the
            # host port: docker-proxy/iptables teardown plus TIME_WAIT can leave
            # 127.0.0.1:<port> briefly occupied. Rotating allocation makes
            # back-to-back reuse rare, but wait it out so run()'s publish can't
            # race a stale mapping.
            self._wait_host_port_free(port)
            logger.info(
                f"Launching worker container {name} (image {self.worker_image}, "
                f"mem_limit {mem_limit_mb}MB) on 127.0.0.1:{port} -> :{self.worker_internal_port}"
            )
            run_kwargs = dict(
                ports={f"{self.worker_internal_port}/tcp": ("127.0.0.1", port)},
            )

        try:
            self.docker_client.containers.run(
                image=self.worker_image,
                name=name,
                command=[
                    "/opt/joern/joern-cli/joern", "--server",
                    "--server-host", "0.0.0.0",
                    "--server-port", str(self.worker_internal_port),
                ],
                environment={"JAVA_OPTS": java_opts},
                working_dir="/tmp",
                mem_limit=f"{mem_limit_mb}m",
                # Read-only playground: a query worker only LOADS its cpg.bin and
                # works in /tmp (Joern's workspace), never writing under
                # /playground — verified end-to-end. Mounting ro means a query
                # that escapes the CPGQL denylist can't tamper with or plant files
                # in other tenants' CPGs/source. The build container (compose)
                # keeps rw since it writes the CPGs.
                volumes={self.playground_host_path: {"bind": "/playground", "mode": "ro"}},
                detach=True,
                labels={"codebadger.role": "joern-worker", "codebadger.hash": codebase_hash},
                **run_kwargs,
            )
        except ImageNotFound:
            raise RuntimeError(
                f"Worker image '{self.worker_image}' not found. Build it with: docker compose build"
            )
        with self._state_lock:
            self._worker_containers[codebase_hash] = name

    def _remove_worker_container(self, name: str) -> None:
        try:
            self.docker_client.containers.get(name).remove(force=True)
            logger.debug(f"Removed worker container {name}")
        except NotFound:
            pass
        except Exception as e:
            logger.warning(f"Error removing worker container {name}: {e}")

    def _cleanup_orphan_workers(self) -> None:
        """Remove worker containers left over from a previous run (pool mode)."""
        try:
            orphans = self.docker_client.containers.list(
                all=True, filters={"label": "codebadger.role=joern-worker"}
            )
            for c in orphans:
                try:
                    c.remove(force=True)
                    logger.info(f"Removed orphan worker container {c.name}")
                except Exception as e:
                    logger.warning(f"Could not remove orphan worker {c.name}: {e}")
        except Exception as e:
            logger.warning(f"Orphan worker cleanup skipped: {e}")

    def _dump_server_log(self, codebase_hash: str) -> None:
        """Log the tail of a failed server's output (mode-aware).

        Always emits something at ERROR so a startup failure is diagnosable: the
        worker's own log if present, or an explicit reason when there's nothing to
        read (container already gone, or JVM never produced output). Previously a
        missing container name or an empty log made this silently return nothing,
        leaving "failed to start on port" with no accompanying cause.
        """
        try:
            if self.worker_mode == "pool":
                name = (
                    self._worker_containers.get(codebase_hash)
                    or (self._redis_pool.get_worker(codebase_hash) if self._redis_pool else None)
                    or self._worker_name(codebase_hash)
                )
                try:
                    c = self.docker_client.containers.get(name)
                except NotFound:
                    logger.error(
                        f"Worker {name} ({codebase_hash}) produced no log: container is already "
                        f"gone — removed before its JVM bound (killed mid-startup or OOM-reaped)."
                    )
                    return
                logs = c.logs(tail=50).decode("utf-8", "replace").strip()
                logger.error(
                    f"Worker {name} ({codebase_hash}) startup failed [container status={c.status}]; "
                    f"last 50 log lines:\n"
                    + (logs or "<no output — JVM likely never started: OOM at mem_limit or host starvation>")
                )
            else:
                log_file = f"/tmp/joern-{codebase_hash}.log"
                container = self.docker_client.containers.get(self.container_name)
                res = container.exec_run(cmd=["cat", log_file], stream=False)
                if res.exit_code == 0:
                    out = res.output.decode("utf-8", "replace").strip()
                    logger.error(f"Joern server log for {codebase_hash}:\n" + (out or "<empty log file>"))
                else:
                    logger.error(
                        f"No Joern server log at {log_file} for {codebase_hash} "
                        f"(cat exit {res.exit_code}) — process likely never wrote one."
                    )
        except Exception as e:
            logger.warning(f"Could not read server log for {codebase_hash}: {e}", exc_info=True)

    def reload_with_retry(self, codebase_hash: str, cpg_path: str) -> Optional[int]:
        """Spawn + load an existing cpg.bin, retrying transient load failures.

        Each failed load terminates the server, so every retry re-spawns. A
        transient cause (timeout, connection error, no-project race) is retried up
        to ``load_max_attempts``; a genuinely empty/broken build
        (``_VERIFY_EMPTY``) is never retried — reloading it can't help. Returns the
        serving port on success, or ``None`` if all attempts failed.
        """
        from .joern_client import JoernServerClient

        max_attempts = max(1, self.config.joern.load_max_attempts if self.config else 3)
        for attempt in range(1, max_attempts + 1):
            port = self.spawn_server(codebase_hash)
            if self.load_cpg(codebase_hash, cpg_path):
                if attempt > 1:
                    logger.info(f"CPG reload for {codebase_hash} succeeded on attempt {attempt}")
                return port
            cause = self._last_load_cause
            if cause == JoernServerClient._VERIFY_EMPTY:
                logger.error(
                    f"CPG for {codebase_hash} is empty/broken (not a transient "
                    f"failure) — not retrying reload"
                )
                return None
            if attempt < max_attempts:
                logger.warning(
                    f"Transient CPG load failure for {codebase_hash} "
                    f"(cause={cause}, attempt {attempt}/{max_attempts}) — re-spawning and retrying"
                )
                time.sleep(min(2.0 * attempt, 10.0))  # linear backoff, capped
        logger.error(f"CPG reload for {codebase_hash} failed after {max_attempts} attempts")
        return None

    def reactivate(self, codebase_hash: str, cpg_path: str) -> int:
        """Spawn a fresh Joern process and load the existing CPG binary (no regeneration)."""
        logger.info(f"Reactivating sleeping codebase {codebase_hash}")
        port = self.reload_with_retry(codebase_hash, cpg_path)
        if port is None:
            raise RuntimeError(f"Failed to reload CPG for {codebase_hash} during reactivation")
        if self.codebase_tracker:
            try:
                self.codebase_tracker.update_codebase(
                    codebase_hash,
                    joern_port=port,
                    metadata={"status": SessionStatus.READY},
                )
            except Exception as e:
                logger.warning(f"Failed to update ready status for {codebase_hash}: {e}")
        return port

    def get_or_create_client(self, codebase_hash: str) -> "JoernServerClient":
        port = self.get_server_port(codebase_hash)
        if port is None:
            raise RuntimeError(f"No Joern server running for codebase {codebase_hash}")

        conn_host, conn_port = self._joern_endpoint(codebase_hash, port)

        cached = self._clients.get(codebase_hash)
        if cached is not None:
            if cached.host == conn_host and cached.port == conn_port:
                self._touch(codebase_hash)
                return cached
            # The worker was re-spawned (e.g. evicted and reactivated by another
            # process), so the cached client points at a dead endpoint. Drop it.
            logger.info(
                f"Rebuilding stale client for {codebase_hash}: "
                f"{cached.host}:{cached.port} -> {conn_host}:{conn_port}"
            )
            try:
                cached.close()
            except Exception:
                pass
            self._clients.pop(codebase_hash, None)

        from .joern_client import JoernServerClient

        http_config = {}
        if self.config:
            joern_cfg = self.config.joern
            http_config = {
                "http_pool_connections": joern_cfg.http_pool_connections,
                "http_pool_maxsize": joern_cfg.http_pool_maxsize,
                "http_max_retries": joern_cfg.http_max_retries,
                "http_backoff_factor": joern_cfg.http_backoff_factor,
                "verify_timeout": joern_cfg.verify_timeout_seconds,
            }

        client = JoernServerClient(
            host=conn_host,
            port=conn_port,
            username=self.config.joern.server_auth_username if self.config else None,
            password=self.config.joern.server_auth_password if self.config else None,
            config=http_config,
        )

        self._clients[codebase_hash] = client
        self._touch(codebase_hash)
        logger.debug(f"Created and cached JoernServerClient for {codebase_hash} at {conn_host}:{conn_port}")
        return client

    def load_cpg(self, codebase_hash: str, cpg_path: str, timeout: int = 0) -> bool:
        """Load CPG into Joern server.

        importCpg triggers expensive overlay computation (ReachingDefPass, dataflow).
        On timeout or failure the server is terminated so the spinning JVM doesn't
        linger at 100% CPU.  We do NOT retry — a timeout means the JVM is stuck,
        not that there was a transient network hiccup.
        """
        if timeout == 0:
            timeout = self.config.joern.cpg_load_timeout if self.config else 300

        try:
            port = self.get_server_port(codebase_hash)
            if port is None:
                raise RuntimeError(f"No Joern server running for codebase {codebase_hash}")
            client = self.get_or_create_client(codebase_hash)

            container_cpg_path = cpg_path
            if "/playground/" in cpg_path:
                parts = cpg_path.split("/playground/")
                if len(parts) >= 2:
                    container_cpg_path = f"/playground/{parts[-1]}"

            logger.info(
                f"Loading CPG {cpg_path} (container: {container_cpg_path}) "
                f"into Joern server for {codebase_hash} (port {port}, timeout {timeout}s)"
            )

            success = client.load_cpg(container_cpg_path, project_name=codebase_hash, timeout=timeout)
            # Capture the failure cause BEFORE terminate_server drops the client,
            # so reload_with_retry can tell a transient miss from an empty build.
            self._last_load_cause = getattr(client, "last_load_outcome", None)

            if success:
                logger.info(f"CPG loaded successfully for {codebase_hash}")
                return True

            # importCpg failed, verified empty, or timed out — kill the server
            # so a stuck JVM doesn't spin at 100% CPU on overlay computation.
            # (A sub-second failure here is a load/verify failure, not a stuck
            # overlay; the client log above carries the specific cause.)
            logger.error(
                f"Failed to load CPG for {codebase_hash} (timeout={timeout}s) — "
                f"terminating server"
            )
            self.terminate_server(codebase_hash)
            return False

        except Exception as e:
            logger.error(f"Error loading CPG for {codebase_hash}: {e}")
            # A manager-level error (no server, network) is transient, not empty.
            self._last_load_cause = "error"
            self.terminate_server(codebase_hash)
            return False

    def get_server_port(self, codebase_hash: str) -> Optional[int]:
        port = self._ports.get(codebase_hash)
        if port is None and self._redis_pool:
            # Discovery: a worker another process started (registry is authority).
            port = self._redis_pool.get_port(codebase_hash)
        return port

    def is_server_running(self, codebase_hash: str) -> bool:
        port = self.get_server_port(codebase_hash)
        if not port:
            return False
        return self._port_healthy(port)

    def terminate_server(self, codebase_hash: str) -> bool:
        try:
            # In Redis pool mode a server may have been spawned by ANOTHER
            # process, so "known" means present locally OR in the shared registry.
            known_remotely = bool(self._redis_pool) and self._redis_pool.get_port(codebase_hash) is not None
            if codebase_hash not in self._exec_ids and not known_remotely:
                logger.warning(f"No server found for codebase {codebase_hash}")
                return False

            port = self._ports.get(codebase_hash)
            logger.info(f"Terminating Joern server for {codebase_hash} on port {port} (mode={self.worker_mode})")

            try:
                if self.worker_mode == "pool":
                    # Removing the container kills its JVM and frees the host port.
                    name = (
                        self._worker_containers.get(codebase_hash)
                        or (self._redis_pool.get_worker(codebase_hash) if self._redis_pool else None)
                        or self._worker_name(codebase_hash)
                    )
                    self._remove_worker_container(name)
                else:
                    container = self.docker_client.containers.get(self.container_name)
                    kill_cmd = ["bash", "-c",
                        f"pkill -f 'joern.*--server-port {port}' || true; "
                        f"sleep 3; pkill -9 -f 'joern.*--server-port {port}' || true"]
                    # detach=True: don't block (the `sleep 3` would otherwise hold
                    # the admission lock during eviction). Any JVM still holding
                    # the port is force-killed by _ensure_port_free before the
                    # next spawn rebinds it, so a backgrounded kill is safe.
                    container.exec_run(cmd=kill_cmd, detach=True)
            except Exception as e:
                logger.warning(f"Error stopping Joern server: {e}")

            self._cleanup_server(codebase_hash)
            return True

        except Exception as e:
            logger.error(f"Error terminating Joern server for {codebase_hash}: {e}")
            return False

    def terminate_all_servers(self) -> None:
        logger.info("Terminating all Joern servers")
        codebases = list(self._exec_ids.keys())
        for codebase_hash in codebases:
            self.terminate_server(codebase_hash)
        logger.info("All Joern servers terminated")

    def get_running_servers(self) -> Dict[str, int]:
        """Believed-live server map (hash -> host port). A status/health summary.

        Returns the registry WITHOUT a blocking per-port TCP probe. This is called
        from /health and the 60s status log; probing every server serially (up to
        1s each on a hung port) made those calls block for tens of seconds once a
        few dozen servers were active. The watchdog reaps genuinely-dead servers
        within 30s, so a just-died entry self-heals shortly — and the Redis pool
        branch already returns its registry unverified, so this matches it. Use
        is_server_running(hash) when an authoritative per-server liveness check is
        actually needed (e.g. the spawn fast path).
        """
        if self._redis_pool:
            # Global view across all processes (registry is authority).
            return dict(self._redis_pool.running_servers())
        with self._state_lock:
            return dict(self._ports)

    def get_memory_stats(self, include_container_rss: bool = True) -> dict:
        """Snapshot the memory-admission ledger for /health and status logs."""
        if self._redis_pool:
            reserved = self._redis_pool.total_reserved_mb()
            reserved_servers = self._redis_pool.count()
        else:
            with self._state_lock:
                reservations = dict(self._reservations)
            reserved = sum(reservations.values())
            reserved_servers = len(reservations)
        budget = self._memory_budget_mb
        stats = {
            "mode": "memory" if budget > 0 else "count",
            "ledger": "redis" if self._redis_pool else "in-process",
            "budget_mb": budget,
            "reserved_mb": reserved,
            "free_mb": max(0, budget - reserved) if budget > 0 else None,
            "utilization_pct": round(reserved / budget * 100, 1) if budget > 0 else None,
            "rss_threshold_mb": self._rss_limit_mb(),
            "reserved_servers": reserved_servers,
        }
        if include_container_rss:
            stats["container_rss_mb"] = round(self._container_memory_mb(), 1)
            # Clarify what that RSS covers: in pool mode it's only the build
            # container (query servers are separate, individually-capped
            # containers); in shared mode it's builds + all query servers.
            stats["rss_scope"] = "build_container" if self.worker_mode == "pool" else "shared_container"
        return stats

    # watchdog (C1)

    def start_watchdog(self) -> None:
        self._watchdog_task = asyncio.create_task(self._watchdog_loop())
        logger.info("Joern server watchdog started")

    # idle reaper

    def start_reaper(self) -> None:
        """Start the background idle-worker reaper (no-op if disabled)."""
        if self._idle_ttl_seconds <= 0:
            logger.info("Idle reaper disabled (idle_ttl_seconds <= 0)")
            return
        self._reaper_task = asyncio.create_task(self._reaper_loop())
        logger.info(
            f"Joern idle reaper started (offload after {self._idle_ttl_seconds}s idle, "
            f"scan every {self._reaper_interval}s)"
        )

    def _idle_candidates(self) -> list:
        """Hashes that haven't served a query within the idle TTL."""
        if self._redis_pool:
            return self._redis_pool.idle(self._idle_ttl_seconds)
        cutoff = time.time() - self._idle_ttl_seconds
        with self._state_lock:
            # Only consider live servers; a missing _last_touch (e.g. just spawned,
            # not yet queried) is stamped on spawn via _touch, so default to "now".
            return [h for h in list(self._ports.keys())
                    if self._last_touch.get(h, time.time()) <= cutoff]

    async def _reaper_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            try:
                await asyncio.sleep(self._reaper_interval)
                idle = self._idle_candidates()
                if not idle:
                    continue
                logger.info(
                    f"Idle reaper: offloading {len(idle)} worker(s) idle "
                    f">{self._idle_ttl_seconds}s: {', '.join(idle)}"
                )
                for codebase_hash in idle:
                    # _evict (terminate container + mark SLEEPING) can block on the
                    # Docker API, so run it off the event loop. The next query for
                    # this codebase auto-reactivates it (query_executor auto-wake).
                    try:
                        await loop.run_in_executor(None, self._evict, codebase_hash)
                    except Exception as e:
                        logger.warning(f"Idle reaper: failed to offload {codebase_hash}: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Reaper loop error: {e}", exc_info=True)

    async def _watchdog_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(30)
                for codebase_hash, port in list(self._ports.items()):
                    # Skip servers still inside their startup window — their JVM
                    # may not have bound the port yet, and killing it here is the
                    # race that caused booting servers to be reaped under load.
                    if codebase_hash in self._spawning:
                        continue
                    if not await self._is_server_healthy(port, codebase_hash):
                        logger.warning(f"Joern server {codebase_hash}:{port} is dead, respawning")
                        self.terminate_server(codebase_hash)
                        if self._restart_callback and self.codebase_tracker:
                            # Route through the shared dedup registry so a
                            # watchdog respawn and a user-triggered restart can't
                            # race each other on spawn_server + load_cpg.
                            info = self.codebase_tracker.get_codebase(codebase_hash)
                            if info and info.cpg_path:
                                scheduled = self._restart_callback(codebase_hash, info.cpg_path)
                                if not scheduled:
                                    logger.debug(
                                        f"Watchdog: restart already in-flight for {codebase_hash}"
                                    )
                            else:
                                logger.warning(
                                    f"Watchdog: cannot respawn {codebase_hash}: no CPG path in DB"
                                )
                        else:
                            # Fallback when callback hasn't been wired yet (e.g. during startup).
                            asyncio.create_task(self._respawn_server(codebase_hash))
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Watchdog loop error: {e}", exc_info=True)

    async def _is_server_healthy(self, port: int, codebase_hash: str = "") -> bool:
        conn_host, conn_port = self._joern_endpoint(codebase_hash, port)
        import requests as _requests
        loop = asyncio.get_running_loop()
        try:
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: _requests.get(f"http://{conn_host}:{conn_port}", timeout=5),
                ),
                timeout=8,
            )
            return response.status_code in [200, 404]
        except Exception:
            return False

    async def _respawn_server(self, codebase_hash: str) -> None:
        if not self.codebase_tracker:
            return
        try:
            info = self.codebase_tracker.get_codebase(codebase_hash)
            if not info or not info.cpg_path:
                logger.warning(f"Cannot respawn {codebase_hash}: no CPG path found")
                return
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self.reactivate, codebase_hash, info.cpg_path)
            logger.info(f"Watchdog: respawned server for {codebase_hash}")
        except Exception as e:
            logger.error(f"Watchdog: failed to respawn {codebase_hash}: {e}", exc_info=True)

    def _wait_for_server(self, port: int, timeout: int = 30, codebase_hash: str = "") -> bool:
        import requests
        conn_host, conn_port = self._joern_endpoint(codebase_hash, port)
        url = f"http://{conn_host}:{conn_port}"
        deadline = time.time() + timeout

        # Poll until the HTTP server responds. We don't do a prior TCP-only check
        # because a pre-existing stale JVM could make the port look "open" before
        # our freshly spawned process has even started.
        while time.time() < deadline:
            try:
                response = requests.get(url, timeout=2)
                if response.status_code in [200, 404]:
                    sleep_time = self.config.joern.server_init_sleep_time if self.config else 3.0
                    time.sleep(sleep_time)
                    return True
            except Exception as e:
                logger.debug(f"HTTP check on {url} failed: {e}")
            time.sleep(1)

        return False

    def _wait_host_port_free(self, port: int, wait: float = 6.0) -> None:
        """Wait (briefly) for a host port to be free before republishing it.

        Pool mode publishes the worker on 127.0.0.1:<port>; a just-removed
        container can leave that mapping in TIME_WAIT for a moment. Best-effort:
        if it's still occupied after ``wait`` we proceed anyway — Docker's publish
        will raise and the caller terminates+retries — but in practice the port
        frees within a second or two.
        """
        import socket
        host = self.config.joern.server_host if self.config else "localhost"
        deadline = time.time() + wait

        def _open() -> bool:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((host, port))
                s.close()
                return result == 0
            except Exception:
                return False

        if not _open():
            return
        logger.warning(f"Host port {port} still occupied before worker start — waiting up to {wait}s")
        while time.time() < deadline:
            time.sleep(0.25)
            if not _open():
                return
        logger.error(f"Host port {port} still occupied after {wait}s — worker publish may fail")

    def _ensure_port_free(self, container, port: int, wait: int = 8) -> None:
        """Kill any process still holding *port* inside the container, then wait for it to close."""
        import socket
        host = self.config.joern.server_host if self.config else "localhost"

        def _port_open() -> bool:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((host, port))
                s.close()
                return result == 0
            except Exception:
                return False

        if not _port_open():
            return  # Nothing to do

        logger.warning(f"Port {port} still in use before spawn — force-killing stale process")
        try:
            # pkill by name only kills the shell wrapper (e.g. joern bash script);
            # the JVM child it spawned survives as an orphan and keeps holding the port.
            # Kill by TCP port directly so we hit the actual process that owns the socket.
            # fuser and lsof cover different distros; the ||true suppresses "no process" exits.
            container.exec_run(
                cmd=["bash", "-c",
                     f"fuser -k {port}/tcp 2>/dev/null; "
                     f"lsof -ti :{port} 2>/dev/null | xargs -r kill -9 2>/dev/null; "
                     f"true"],
                stream=False,
            )
        except Exception as e:
            logger.warning(f"Error force-killing process on port {port}: {e}")

        deadline = time.time() + 20
        while time.time() < deadline:
            if not _port_open():
                logger.info(f"Port {port} is now free")
                return
            time.sleep(0.5)

        logger.error(f"Port {port} still occupied after 20s — spawn may fail with BindException")

    def _release_reservation(self, codebase_hash: str) -> None:
        with self._state_lock:
            self._reservations.pop(codebase_hash, None)

    def _cleanup_server(self, codebase_hash: str) -> None:
        with self._state_lock:
            self._exec_ids.pop(codebase_hash, None)
            self._ports.pop(codebase_hash, None)
            self._reservations.pop(codebase_hash, None)
            self._worker_containers.pop(codebase_hash, None)
            self._lru.pop(codebase_hash, None)
            self._last_touch.pop(codebase_hash, None)
            # Release the port even when _ports never got set: spawn can fail
            # between allocate_port() and the _ports assignment (e.g. the worker
            # image is missing), which would otherwise leak the port.
            if self.port_manager.get_port(codebase_hash) is not None:
                self.port_manager.release_port(codebase_hash)
                logger.debug(f"Released port for {codebase_hash}")
        # Release shared (cross-process) state too. Idempotent; covers eviction
        # of a worker another process spawned and spawn-failure cleanup.
        if self._redis_pool:
            self._redis_pool.release(codebase_hash)
        if codebase_hash in self._clients:
            client = self._clients[codebase_hash]
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Error closing HTTP session for {codebase_hash}: {e}")
            del self._clients[codebase_hash]
