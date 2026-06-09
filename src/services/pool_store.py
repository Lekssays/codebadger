"""
Redis-backed shared pool state for multi-process pool mode (Phase 3c).

In pool mode every CPG runs in its own container named `codebadger-joern-<hash>`
publishing a host port, so any process on the host can discover and connect to a
worker another process started. What can't be shared via the OS is the
*bookkeeping* — the memory reservation ledger, the warm-worker registry, the LRU
order, and free-port selection — so several stateless API/scheduler processes
can coordinate spawn/evict without over-committing memory or double-spawning.

This store keeps that bookkeeping in Redis:
  - reservations  HASH  hash -> reserved MB        (global memory ledger)
  - registry      HASH  hash -> host port          (which CPGs are live + where)
  - workers       HASH  hash -> container name
  - lru           ZSET  hash -> last-touch score   (global eviction order)
  - admit lock           one global lock for the make-room+allocate+reserve step
  - spawn lock     per-hash lock so two processes never spawn the same CPG

JoernServerManager uses it only when worker_mode=pool and REDIS_URL is set; the
single-process path is unchanged. The local manager still caches the servers IT
spawned (for HTTP client routing); Redis is the cross-process source of truth for
admission and discovery.
"""

import logging
import time
from contextlib import contextmanager
from typing import Dict, Iterable, Iterator, Optional

logger = logging.getLogger(__name__)

_RESV = "cb:pool:resv"
_REG = "cb:pool:reg"
_WORKER = "cb:pool:worker"
_LRU = "cb:pool:lru"
_ADMIT_LOCK = "cb:pool:admit"


class RedisPoolStore:
    def __init__(self, redis_url: str, admit_lock_timeout: int = 120, spawn_lock_timeout: int = 660):
        import redis  # lazy: only required when REDIS_URL is set
        self.r = redis.Redis.from_url(redis_url, decode_responses=True)
        self.r.ping()  # fail fast on a bad URL
        self._admit_timeout = admit_lock_timeout
        self._spawn_timeout = spawn_lock_timeout
        logger.info(f"RedisPoolStore connected ({redis_url.split('@')[-1]})")

    # locks

    @contextmanager
    def admit_lock(self) -> Iterator[None]:
        """Global lock for the atomic make-room + allocate-port + reserve step."""
        lock = self.r.lock(_ADMIT_LOCK, timeout=self._admit_timeout,
                            blocking=True, blocking_timeout=self._admit_timeout)
        if not lock.acquire():
            raise TimeoutError("Could not acquire pool admit lock")
        try:
            yield
        finally:
            try:
                lock.release()
            except Exception:
                pass

    @contextmanager
    def spawn_lock(self, codebase_hash: str) -> Iterator[None]:
        """Per-CPG lock so only one process spawns a given CPG at a time."""
        lock = self.r.lock(f"cb:pool:spawn:{codebase_hash}", timeout=self._spawn_timeout,
                            blocking=True, blocking_timeout=self._spawn_timeout)
        if not lock.acquire():
            raise TimeoutError(f"Could not acquire spawn lock for {codebase_hash}")
        try:
            yield
        finally:
            try:
                lock.release()
            except Exception:
                pass

    # reservations

    def total_reserved_mb(self) -> int:
        return sum(int(v) for v in self.r.hvals(_RESV))

    def reserve(self, codebase_hash: str, mb: int) -> None:
        self.r.hset(_RESV, codebase_hash, mb)

    def claim(self, codebase_hash: str, port: int, mb: int) -> None:
        """Atomically reserve memory + register the port + touch LRU.

        One MULTI/EXEC transaction so a crash can't leave a half-claimed entry
        (reserved + in LRU but unregistered), which would otherwise be a stale
        ledger row that make-room re-picks forever. Must be called under
        admit_lock() after allocate_port().
        """
        pipe = self.r.pipeline(transaction=True)
        pipe.hset(_RESV, codebase_hash, mb)
        pipe.hset(_REG, codebase_hash, port)
        pipe.zadd(_LRU, {codebase_hash: time.time()})
        pipe.execute()

    # registry / ports

    def set_port(self, codebase_hash: str, port: int) -> None:
        self.r.hset(_REG, codebase_hash, port)

    def get_port(self, codebase_hash: str) -> Optional[int]:
        v = self.r.hget(_REG, codebase_hash)
        return int(v) if v is not None else None

    def all_ports(self) -> Dict[str, int]:
        return {k: int(v) for k, v in self.r.hgetall(_REG).items()}

    def set_worker(self, codebase_hash: str, name: str) -> None:
        self.r.hset(_WORKER, codebase_hash, name)

    def get_worker(self, codebase_hash: str) -> Optional[str]:
        return self.r.hget(_WORKER, codebase_hash)

    def allocate_port(self, port_min: int, port_max: int) -> Optional[int]:
        """Lowest free port in range not already in the registry.

        Must be called under admit_lock() and followed by set_port() so two
        processes can't pick the same port.
        """
        taken = set(self.all_ports().values())
        for port in range(port_min, port_max + 1):
            if port not in taken:
                return port
        return None

    def release(self, codebase_hash: str) -> None:
        """Drop all shared state for a CPG (evicted/terminated).

        One MULTI/EXEC transaction so a crash mid-release can't orphan part of
        the entry (e.g. registry cleared but reservation/LRU left behind, which
        make-room would then spin on). Idempotent."""
        pipe = self.r.pipeline(transaction=True)
        pipe.hdel(_RESV, codebase_hash)
        pipe.hdel(_REG, codebase_hash)
        pipe.hdel(_WORKER, codebase_hash)
        pipe.zrem(_LRU, codebase_hash)
        pipe.execute()

    # LRU

    def touch(self, codebase_hash: str) -> None:
        self.r.zadd(_LRU, {codebase_hash: time.time()})

    def oldest(self, exclude: Iterable[str] = ()) -> Optional[str]:
        excl = set(exclude)
        for h in self.r.zrange(_LRU, 0, -1):
            if h not in excl:
                return h
        return None

    def idle(self, ttl_seconds: int) -> list:
        """Hashes whose last-touch is older than ``ttl_seconds`` (idle workers).

        The LRU ZSET is scored by ``time.time()`` of the last touch, so a range
        query [0, now - ttl] returns exactly the workers that haven't served a
        query within the window — the reaper's eviction candidates.
        """
        if ttl_seconds <= 0:
            return []
        cutoff = time.time() - ttl_seconds
        return list(self.r.zrangebyscore(_LRU, 0, cutoff))

    def count(self) -> int:
        return self.r.hlen(_REG)

    def running_servers(self) -> Dict[str, int]:
        return self.all_ports()
