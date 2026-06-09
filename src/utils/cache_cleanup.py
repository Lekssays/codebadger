"""Periodic cache cleanup scheduler for CodeBadger"""

import logging
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)


class CacheCleanupScheduler:
    """Runs periodic cache cleanup in a background thread.
    
    The scheduler uses a daemon thread to periodically clean up expired
    cache entries from the database. It can be started and stopped
    gracefully, and also supports on-demand cleanup.
    
    Example:
        >>> scheduler = CacheCleanupScheduler(db_manager, cleanup_interval_seconds=3600)
        >>> scheduler.start()
        >>> # ... later ...
        >>> scheduler.stop()
    """

    def __init__(
        self,
        db_manager,
        cleanup_interval_seconds: int = 3600,
        max_age_seconds: int = 3600
    ):
        """Initialize the cache cleanup scheduler.
        
        Args:
            db_manager: PostgresDBManager instance for database operations
            cleanup_interval_seconds: How often to run cleanup (default: 3600 = 1 hour)
            max_age_seconds: Maximum age of cache entries to keep (default: 3600 = 1 hour)
        """
        self.db_manager = db_manager
        self.cleanup_interval = cleanup_interval_seconds
        self.max_age = max_age_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start the cleanup scheduler in a background thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Cache cleanup scheduler is already running")
            return  # Already running
        
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="CacheCleanupScheduler")
        self._thread.start()
        logger.info(
            f"Cache cleanup scheduler started (interval: {self.cleanup_interval}s, max_age: {self.max_age}s)"
        )

    def stop(self, timeout: float = 5.0):
        """Stop the cleanup scheduler.
        
        Args:
            timeout: Maximum time to wait for thread to stop (default: 5.0 seconds)
        """
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._thread = None
        logger.info("Cache cleanup scheduler stopped")

    def is_running(self) -> bool:
        """Check if the scheduler is currently running."""
        return self._thread is not None and self._thread.is_alive()

    def _cleanup_loop(self):
        """Main cleanup loop - runs in background thread."""
        while not self._stop_event.is_set():
            try:
                deleted = self.db_manager.cleanup_expired_cache(self.max_age)
                if deleted > 0:
                    logger.info(f"Cache cleanup: removed {deleted} expired entries")
            except Exception as e:
                logger.error(f"Error during cache cleanup: {e}")
            
            # Wait for next interval or stop signal
            self._stop_event.wait(self.cleanup_interval)

    def run_cleanup_now(self) -> int:
        """Run cleanup immediately (for testing or manual trigger).
        
        Returns:
            Number of deleted entries
        """
        try:
            return self.db_manager.cleanup_expired_cache(self.max_age)
        except Exception as e:
            logger.error(f"Error during manual cache cleanup: {e}")
            return 0
