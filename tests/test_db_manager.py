"""Tests for DBManager cache TTL functionality and CacheCleanupScheduler"""

import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest

from src.utils.db_manager import DBManager
from src.utils.cache_cleanup import CacheCleanupScheduler


class TestCacheTTL:
    """Test cache TTL enforcement in DBManager"""

    def test_get_cached_output_returns_fresh_entry(self):
        """Fresh cache entries should be returned"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            db.cache_tool_output("test_tool", "hash1", {"key": "value"}, {"result": "data"})
            
            result = db.get_cached_tool_output("test_tool", "hash1", {"key": "value"}, cache_ttl=300)
            assert result == {"result": "data"}

    def test_get_cached_output_returns_none_for_expired(self):
        """Expired cache entries should return None"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            db.cache_tool_output("test_tool", "hash1", {"key": "value"}, {"result": "data"})
            
            # Use TTL of 0 to simulate expired entry
            result = db.get_cached_tool_output("test_tool", "hash1", {"key": "value"}, cache_ttl=0)
            assert result is None

    def test_get_cached_output_default_ttl(self):
        """Default TTL should be 300 seconds"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            db.cache_tool_output("test_tool", "hash1", {"key": "value"}, {"result": "data"})
            
            # With default TTL, fresh entry should be returned
            result = db.get_cached_tool_output("test_tool", "hash1", {"key": "value"})
            assert result == {"result": "data"}

    def test_get_cached_output_missing_entry(self):
        """Non-existent cache entry should return None"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            
            result = db.get_cached_tool_output("nonexistent", "hash1", {"key": "value"})
            assert result is None

    def test_get_cached_output_different_params(self):
        """Different parameters should not match cached entry"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            db.cache_tool_output("test_tool", "hash1", {"key": "value1"}, {"result": "data"})
            
            result = db.get_cached_tool_output("test_tool", "hash1", {"key": "value2"}, cache_ttl=300)
            assert result is None


class TestUpdateCodebase:
    """Test the atomic, row-locked update_codebase metadata merge."""

    def _save(self, db, **overrides):
        data = {
            "hash": "h1",
            "source_type": "github",
            "source_path": "u/r",
            "language": "c",
            "joern_port": 13371,
            "metadata": {"status": "ready"},
        }
        data.update(overrides)
        db.save_codebase(data)

    def test_merge_preserves_existing_metadata_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            self._save(db, metadata={"status": "ready", "a": 1})

            assert db.update_codebase("h1", {"metadata": {"b": 2}}) is True

            meta = db.get_codebase("h1")["metadata"]
            assert meta == {"status": "ready", "a": 1, "b": 2}

    def test_update_only_writes_given_fields(self):
        """A metadata-only update must not clobber untouched scalar columns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            self._save(db, joern_port=13371)

            db.update_codebase("h1", {"metadata": {"x": 1}})

            row = db.get_codebase("h1")
            assert row["joern_port"] == 13371  # left intact
            assert row["metadata"]["x"] == 1

    def test_set_scalar_field(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            self._save(db, joern_port=13371)

            db.update_codebase("h1", {"joern_port": None})

            assert db.get_codebase("h1")["joern_port"] is None

    def test_returns_false_for_missing_row(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            assert db.update_codebase("nope", {"metadata": {"a": 1}}) is False

    def test_concurrent_merges_do_not_lose_keys(self):
        """Regression for the read-modify-write race: N threads each merge a
        distinct metadata key concurrently; all keys must survive. Under the old
        Python-side get/merge/save this dropped keys; the BEGIN IMMEDIATE
        transaction serializes the writers so none are lost."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            self._save(db, metadata={})

            n = 24
            barrier = threading.Barrier(n)
            errors = []

            def worker(i):
                try:
                    barrier.wait()  # release all threads at once to maximize contention
                    db.update_codebase("h1", {"metadata": {f"k{i}": i}})
                except Exception as e:  # pragma: no cover - surfaced via assert below
                    errors.append(e)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert not errors, errors
            meta = db.get_codebase("h1")["metadata"]
            assert meta == {f"k{i}": i for i in range(n)}


class TestCleanupExpiredCache:
    """Test cleanup_expired_cache method"""

    def test_cleanup_removes_old_entries(self):
        """cleanup_expired_cache should remove old entries"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            
            # Insert entry
            db.cache_tool_output("test_tool", "hash1", {"key": "value"}, {"result": "data"})
            
            # Cleanup with max_age=0 should remove the entry
            deleted = db.cleanup_expired_cache(max_age_seconds=0)
            assert deleted == 1
            
            # Verify entry is gone (use high TTL to not trigger expiry check)
            result = db.get_cached_tool_output("test_tool", "hash1", {"key": "value"}, cache_ttl=86400)
            assert result is None

    def test_cleanup_preserves_fresh_entries(self):
        """cleanup_expired_cache should not remove fresh entries"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            
            db.cache_tool_output("test_tool", "hash1", {"key": "value"}, {"result": "data"})
            
            # Cleanup with max_age=3600 should not remove the entry
            deleted = db.cleanup_expired_cache(max_age_seconds=3600)
            assert deleted == 0
            
            # Verify entry still exists
            result = db.get_cached_tool_output("test_tool", "hash1", {"key": "value"}, cache_ttl=3600)
            assert result == {"result": "data"}

    def test_cleanup_multiple_entries(self):
        """cleanup_expired_cache should handle multiple entries"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            
            # Insert multiple entries
            for i in range(5):
                db.cache_tool_output("test_tool", f"hash{i}", {"idx": i}, {"result": i})
            
            # Cleanup with max_age=0 should remove all
            deleted = db.cleanup_expired_cache(max_age_seconds=0)
            assert deleted == 5


class TestGetCacheStats:
    """Test get_cache_stats method"""

    def test_cache_stats_empty(self):
        """Empty cache should return 0 entries"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            
            stats = db.get_cache_stats()
            assert stats["total_entries"] == 0

    def test_cache_stats_with_entries(self):
        """Cache stats should count entries"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            
            for i in range(3):
                db.cache_tool_output("test_tool", f"hash{i}", {"idx": i}, {"result": i})
            
            stats = db.get_cache_stats()
            assert stats["total_entries"] == 3


class TestCacheCleanupScheduler:
    """Test CacheCleanupScheduler"""

    def test_scheduler_starts_and_stops(self):
        """Scheduler should start and stop cleanly"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            scheduler = CacheCleanupScheduler(db, cleanup_interval_seconds=60, max_age_seconds=60)
            
            assert not scheduler.is_running()
            
            scheduler.start()
            assert scheduler.is_running()
            
            scheduler.stop()
            assert not scheduler.is_running()

    def test_scheduler_double_start(self):
        """Starting scheduler twice should be harmless"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            scheduler = CacheCleanupScheduler(db, cleanup_interval_seconds=60, max_age_seconds=60)
            
            scheduler.start()
            scheduler.start()  # Second start should be no-op
            assert scheduler.is_running()
            
            scheduler.stop()

    def test_run_cleanup_now(self):
        """run_cleanup_now should trigger immediate cleanup"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            scheduler = CacheCleanupScheduler(db, cleanup_interval_seconds=3600, max_age_seconds=0)
            
            # Add entries
            db.cache_tool_output("test_tool", "hash1", {"key": "value"}, {"result": "data"})
            
            # Run cleanup manually (max_age=0 means all entries are expired)
            deleted = scheduler.run_cleanup_now()
            assert deleted == 1

    def test_cleanup_respects_max_age(self):
        """Scheduler cleanup should respect max_age_seconds"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DBManager(f"{tmpdir}/test.db")
            scheduler = CacheCleanupScheduler(db, cleanup_interval_seconds=3600, max_age_seconds=3600)
            
            # Add entry
            db.cache_tool_output("test_tool", "hash1", {"key": "value"}, {"result": "data"})
            
            # Cleanup should not remove fresh entry
            deleted = scheduler.run_cleanup_now()
            assert deleted == 0
            
            # Entry should still exist
            result = db.get_cached_tool_output("test_tool", "hash1", {"key": "value"}, cache_ttl=3600)
            assert result == {"result": "data"}
