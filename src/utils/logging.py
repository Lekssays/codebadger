"""
Logging configuration
"""

import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from typing import Optional

# Path of the per-run log file, set by setup_logging() so the rest of the app
# (and /health) can report where logs are being written.
_run_log_path: Optional[str] = None


def setup_logging(
    log_level: str = "INFO",
    log_dir: Optional[str] = "logs",
    log_to_file: bool = True,
    log_max_bytes: int = 50 * 1024 * 1024,
    log_backup_count: int = 5,
):
    """Configure root logging with a stdout stream and an optional per-run file.

    Each run writes to ``<log_dir>/codebadger-<YYYYmmdd-HHMMSS>-<pid>.log`` (size
    rotated) so a long ``screen`` session can be inspected after the fact instead
    of scrolling a single firehose. A stable ``<log_dir>/codebadger-latest.log``
    symlink always points at the current run's file. Idempotent: re-running
    replaces handlers rather than stacking duplicates.
    """
    global _run_log_path
    level = getattr(logging, log_level.upper(), logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers so re-init (e.g. lifespan restart) doesn't stack.
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Per-run rotating file handler
    if log_to_file and log_dir:
        try:
            os.makedirs(log_dir, exist_ok=True)
            run_stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
            _run_log_path = os.path.join(log_dir, f"codebadger-{run_stamp}-{os.getpid()}.log")
            file_handler = RotatingFileHandler(
                _run_log_path,
                maxBytes=log_max_bytes,
                backupCount=log_backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            _update_latest_symlink(log_dir, _run_log_path)
            root_logger.info(f"File logging enabled: {_run_log_path}")
        except Exception as e:
            # Never let a logging-setup failure take down the server.
            root_logger.warning(f"Could not enable file logging in {log_dir!r}: {e}")

    # Reduce noise from libraries
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("git").setLevel(logging.WARNING)

    # FastMCP keeps its own logger; route it through our handlers (propagate to
    # root) instead of a separate rich console, so its records land in the file
    # too. Best-effort — the import path is version-dependent.
    try:
        from fastmcp.utilities.logging import configure_logging as _fastmcp_configure_logging

        _fastmcp_configure_logging(level=log_level.upper())
    except Exception:
        pass
    for name in ("fastmcp", "FastMCP"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True


def get_run_log_path() -> Optional[str]:
    """Absolute path of the current run's log file, or None if file logging is off."""
    return os.path.abspath(_run_log_path) if _run_log_path else None


def _update_latest_symlink(log_dir: str, target: str) -> None:
    """Point <log_dir>/codebadger-latest.log at the current run file (best-effort)."""
    link = os.path.join(log_dir, "codebadger-latest.log")
    try:
        if os.path.islink(link) or os.path.exists(link):
            os.remove(link)
        os.symlink(os.path.basename(target), link)
    except Exception:
        pass


def get_logger(name: str) -> logging.Logger:
    """Get logger instance"""
    return logging.getLogger(name)
