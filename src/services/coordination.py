"""
Cross-process coordination primitives (Phase 3c).

The query path serializes work per CPG so two requests never hammer the same
Joern JVM at once. In a single process that's a threading.Semaphore; to run
*multiple* stateless API worker processes against one Joern pool, that lock must
hold across processes — hence a Redis-backed implementation.

`InProcessCoordinator` preserves the original single-process behavior and is the
default. `RedisCoordinator` (selected when REDIS_URL is set) uses a Redis lock
with an expiry, so a crashed holder's lock auto-releases instead of deadlocking.

This is the first coordination primitive; the reservation ledger and warm-worker
registry that a full scheduler/stateless-API split needs will layer on the same
abstraction.
"""

import logging
import threading
from contextlib import contextmanager
from typing import Dict, Iterator, Optional

logger = logging.getLogger(__name__)


class QueryLockTimeout(Exception):
    """Raised when a per-CPG query lock can't be acquired in time."""


class InProcessCoordinator:
    """Default coordinator: per-CPG locks live in this process only."""

    def __init__(self):
        self._codebase_locks: Dict[str, threading.Semaphore] = {}
        self._locks_mutex = threading.Lock()

    def _get_codebase_lock(self, codebase_hash: str) -> threading.Semaphore:
        with self._locks_mutex:
            if codebase_hash not in self._codebase_locks:
                self._codebase_locks[codebase_hash] = threading.Semaphore(1)
            return self._codebase_locks[codebase_hash]

    @contextmanager
    def codebase_query_lock(self, codebase_hash: str) -> Iterator[None]:
        lock = self._get_codebase_lock(codebase_hash)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()

    @property
    def backend(self) -> str:
        return "in-process"


class RedisCoordinator:
    """Redis-backed coordinator: per-CPG query lock holds across processes/hosts.

    lock_timeout: the lock auto-expires after this many seconds so a crashed
        holder can't deadlock the CPG (set comfortably above the max query time).
    blocking_timeout: how long a waiting query blocks for the lock before giving
        up with QueryLockTimeout (surfaced as SERVER_BUSY).
    """

    def __init__(self, redis_url: str, lock_timeout: int = 660, blocking_timeout: int = 660):
        import redis  # imported lazily so redis is only required when REDIS_URL is set
        self._redis = redis.Redis.from_url(redis_url)
        self._redis.ping()  # fail fast on a bad URL
        self._lock_timeout = lock_timeout
        self._blocking_timeout = blocking_timeout
        logger.info(f"RedisCoordinator connected ({redis_url.split('@')[-1]})")

    @contextmanager
    def codebase_query_lock(self, codebase_hash: str) -> Iterator[None]:
        lock = self._redis.lock(
            f"codebadger:qlock:{codebase_hash}",
            timeout=self._lock_timeout,
            blocking=True,
            blocking_timeout=self._blocking_timeout,
        )
        if not lock.acquire():
            raise QueryLockTimeout(
                f"Could not acquire query lock for {codebase_hash} within "
                f"{self._blocking_timeout}s — another request holds this CPG"
            )
        try:
            yield
        finally:
            try:
                lock.release()
            except Exception:
                # Lock may have already expired (timeout) — safe to ignore.
                pass

    @property
    def backend(self) -> str:
        return "redis"


def make_coordinator(redis_url: Optional[str], lock_timeout: int = 660):
    """Build the coordinator: Redis when redis_url is set, else in-process.

    Falls back to in-process (with a warning) if Redis can't be reached, so a
    misconfigured REDIS_URL degrades to single-process rather than failing boot.
    """
    if not redis_url:
        return InProcessCoordinator()
    try:
        return RedisCoordinator(redis_url, lock_timeout=lock_timeout, blocking_timeout=lock_timeout)
    except Exception as e:
        logger.warning(f"Could not initialize Redis coordinator ({e}); falling back to in-process")
        return InProcessCoordinator()
