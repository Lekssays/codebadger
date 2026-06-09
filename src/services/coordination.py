"""
Cross-process coordination primitives.

The query path serializes work per CPG so two requests never hammer the same
Joern JVM at once. To run multiple stateless API worker processes against one
Joern pool, that lock must hold across processes — so coordination is
Redis-backed.

`RedisCoordinator` uses a Redis lock with an expiry, so a crashed holder's lock
auto-releases instead of deadlocking.
"""

import logging
from contextlib import contextmanager
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


class QueryLockTimeout(Exception):
    """Raised when a per-CPG query lock can't be acquired in time."""


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

    def ping(self) -> dict:
        """Liveness probe for /health: round-trip PING with latency (ms)."""
        import time
        start = time.monotonic()
        try:
            self._redis.ping()
            return {"ok": True, "latency_ms": round((time.monotonic() - start) * 1000, 2),
                    "backend": "redis"}
        except Exception as e:
            return {"ok": False, "error": str(e), "backend": "redis"}


def make_coordinator(redis_url: Optional[str], lock_timeout: int = 660):
    """Build the Redis-backed coordinator.

    Raises if ``redis_url`` is empty or Redis can't be reached, so a missing or
    misconfigured Redis fails the server's boot loudly (the caller's lifespan
    catches it, logs, and exits non-zero).
    """
    if not redis_url:
        raise RuntimeError(
            "REDIS_URL is required. Start Redis with `docker compose up -d` or set REDIS_URL."
        )
    return RedisCoordinator(redis_url, lock_timeout=lock_timeout, blocking_timeout=lock_timeout)
