"""
Tests for logging configuration
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from unittest.mock import MagicMock, patch

import pytest

from src.utils.logging import get_logger, get_run_log_path, setup_logging


@pytest.fixture
def restore_root_logging():
    """Snapshot/restore the real root logger so tests don't leak handlers."""
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    yield
    for h in root.handlers[:]:
        root.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass
    for h in saved_handlers:
        root.addHandler(h)
    root.setLevel(saved_level)


def _handlers_by_type(root, cls):
    return [h for h in root.handlers if isinstance(h, cls)]


class TestSetupLogging:
    """Test logging setup against the real root logger (no over-mocking)."""

    def test_default_level_and_stream_handler(self, tmp_path, restore_root_logging):
        setup_logging(log_dir=str(tmp_path))
        root = logging.getLogger()
        assert root.level == logging.INFO
        streams = [h for h in root.handlers if isinstance(h, logging.StreamHandler)
                   and not isinstance(h, RotatingFileHandler)]
        assert streams, "expected a stdout StreamHandler"
        assert streams[0].level == logging.INFO

    def test_custom_level(self, tmp_path, restore_root_logging):
        setup_logging("DEBUG", log_dir=str(tmp_path))
        assert logging.getLogger().level == logging.DEBUG

    def test_invalid_level_defaults_to_info(self, tmp_path, restore_root_logging):
        setup_logging("INVALID", log_dir=str(tmp_path))
        assert logging.getLogger().level == logging.INFO

    def test_removes_existing_handlers(self, tmp_path, restore_root_logging):
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
        sentinel_a, sentinel_b = logging.NullHandler(), logging.NullHandler()
        root.addHandler(sentinel_a)
        root.addHandler(sentinel_b)

        setup_logging(log_dir=str(tmp_path))

        # The two pre-existing handlers are gone; only the fresh stream+file remain.
        assert sentinel_a not in root.handlers
        assert sentinel_b not in root.handlers

    def test_library_noise_reduction(self, tmp_path, restore_root_logging):
        setup_logging(log_dir=str(tmp_path))
        assert logging.getLogger("docker").level == logging.WARNING
        assert logging.getLogger("urllib3").level == logging.WARNING
        assert logging.getLogger("git").level == logging.WARNING

    def test_formatter_has_expected_fields(self, tmp_path, restore_root_logging):
        setup_logging(log_dir=str(tmp_path))
        root = logging.getLogger()
        for part in ("%(asctime)s", "%(name)s", "%(levelname)s", "%(message)s"):
            assert all(part in h.formatter._fmt for h in root.handlers if h.formatter)

    def test_file_logging_writes_run_file(self, tmp_path, restore_root_logging):
        setup_logging(log_dir=str(tmp_path))
        logging.getLogger("codebadger.test").info("marker-line-xyz")
        path = get_run_log_path()
        assert path and os.path.exists(path)
        assert "marker-line-xyz" in open(path, encoding="utf-8").read()
        # A stable latest symlink points at the current run file.
        latest = os.path.join(str(tmp_path), "codebadger-latest.log")
        assert os.path.realpath(latest) == os.path.realpath(path)

    def test_file_logging_can_be_disabled(self, tmp_path, restore_root_logging):
        setup_logging(log_dir=str(tmp_path), log_to_file=False)
        root = logging.getLogger()
        assert not _handlers_by_type(root, RotatingFileHandler)

    def test_reinit_does_not_stack_handlers(self, tmp_path, restore_root_logging):
        setup_logging(log_dir=str(tmp_path))
        setup_logging(log_dir=str(tmp_path))
        root = logging.getLogger()
        # Exactly one stdout stream + one rotating file after a re-init.
        assert len(_handlers_by_type(root, RotatingFileHandler)) == 1
        streams = [h for h in root.handlers if isinstance(h, logging.StreamHandler)
                   and not isinstance(h, RotatingFileHandler)]
        assert len(streams) == 1


class TestGetLogger:
    """Test logger retrieval"""

    def test_get_logger(self):
        """Test getting a logger instance"""
        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            logger = get_logger("test.module")

            mock_get_logger.assert_called_once_with("test.module")
            assert logger == mock_logger

    def test_get_logger_different_names(self):
        """Test getting loggers with different names"""
        with patch("logging.getLogger") as mock_get_logger:
            mock_logger1 = MagicMock()
            mock_logger2 = MagicMock()
            mock_get_logger.side_effect = [mock_logger1, mock_logger2]

            logger1 = get_logger("module1")
            logger2 = get_logger("module2")

            assert mock_get_logger.call_count == 2
            mock_get_logger.assert_any_call("module1")
            mock_get_logger.assert_any_call("module2")
            assert logger1 == mock_logger1
            assert logger2 == mock_logger2
