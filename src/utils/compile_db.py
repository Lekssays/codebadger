"""compile_commands.json handling for c2cpg `--compilation-database`.

A compilation database gives c2cpg the exact per-file compiler flags
(-I/-D/-std/...), which is the highest-fidelity way to resolve headers and
#ifdef-gated code. The catch: CodeBadger copies source into
/playground/codebases/<hash>/, so the absolute `directory`/`file` paths a build
machine wrote into the DB no longer exist in the container. We rebase those
paths from the original source root onto the container source root so c2cpg can
find every translation unit.

Pure helpers here (no FS side effects in `rebase_entries`) so they're unit
testable; the load/rewrite/write wrapper does the IO.
"""

import json
import logging
import os
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# Build dirs where a compilation database is conventionally emitted. Searched
# (plus the source root) before a bounded walk, so the common case is cheap.
_COMPILE_DB_NAME = "compile_commands.json"
_COMMON_BUILD_DIRS = ("", "build", "out", "_build", "cmake-build-debug",
                      "cmake-build-release", "Debug", "Release", "bin")


def find_compile_db(codebase_dir: str, max_depth: int = 3) -> Optional[str]:
    """Locate a compile_commands.json in a copied source tree.

    Checks conventional build-dir locations first, then a depth-bounded walk.
    When several exist, prefers the LARGEST (most entries ≈ best coverage),
    tie-broken by shallowest path. Returns the path RELATIVE to codebase_dir, or
    None. Never raises.
    """
    try:
        root = os.path.realpath(codebase_dir)
        candidates = []  # (size, depth, relpath)

        def consider(abs_path):
            try:
                if os.path.isfile(abs_path):
                    rel = os.path.relpath(abs_path, root)
                    depth = rel.count(os.sep)
                    candidates.append((os.path.getsize(abs_path), depth, rel))
            except OSError:
                pass

        for d in _COMMON_BUILD_DIRS:
            consider(os.path.join(root, d, _COMPILE_DB_NAME))

        if not candidates:
            for dirpath, dirnames, filenames in os.walk(root):
                depth = os.path.relpath(dirpath, root).count(os.sep) if dirpath != root else 0
                if depth >= max_depth:
                    dirnames[:] = []
                    continue
                # skip VCS/asset dirs for speed
                dirnames[:] = [x for x in dirnames if x not in
                               {".git", ".svn", ".hg", "node_modules", ".cache"}]
                if _COMPILE_DB_NAME in filenames:
                    consider(os.path.join(dirpath, _COMPILE_DB_NAME))

        if not candidates:
            return None
        # Largest first; shallowest as tie-break.
        candidates.sort(key=lambda c: (-c[0], c[1]))
        return candidates[0][2]
    except Exception as e:
        logger.debug(f"find_compile_db failed under {codebase_dir}: {e}")
        return None


def _rebase_path(path: str, host_root: str, container_root: str) -> str:
    """Map an absolute path under host_root onto container_root.

    Relative paths are returned unchanged (c2cpg resolves them against the
    entry's `directory`). A path not under host_root is returned unchanged.
    """
    if not path or not os.path.isabs(path):
        return path
    norm = os.path.normpath(path)
    root = os.path.normpath(host_root) if host_root else ""
    if root and (norm == root or norm.startswith(root + os.sep)):
        suffix = norm[len(root):].lstrip(os.sep)
        return os.path.join(container_root, suffix) if suffix else container_root
    return path


def rebase_entries(entries: List[dict], host_root: Optional[str],
                   container_root: str) -> Tuple[List[dict], int]:
    """Rebase `directory`/`file` fields of compile-db entries.

    Returns (rewritten_entries, rebased_count). When host_root is None we only
    normalise; relative entries pass through untouched.
    """
    out, rebased = [], 0
    for entry in entries:
        e = dict(entry)
        for key in ("directory", "file"):
            if key in e and isinstance(e[key], str) and host_root:
                new = _rebase_path(e[key], host_root, container_root)
                if new != e[key]:
                    rebased += 1
                e[key] = new
        out.append(e)
    return out, rebased


def prepare_container_compile_db(
    db_host_path: str,
    host_root: Optional[str],
    container_root: str,
    out_host_path: str,
) -> Optional[Tuple[str, int, int]]:
    """Load a compile_commands.json, rebase its paths, write a container-usable
    copy to out_host_path.

    Returns (out_host_path, entry_count, rebased_count) on success, or None if
    the DB is missing / unparseable / empty. Best-effort; never raises.
    """
    try:
        with open(db_host_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        logger.warning(f"compile_commands: could not read/parse {db_host_path}: {e}")
        return None
    if not isinstance(data, list) or not data:
        logger.warning(f"compile_commands: {db_host_path} is not a non-empty JSON array")
        return None
    rewritten, rebased = rebase_entries(data, host_root, container_root)
    try:
        with open(out_host_path, "w", encoding="utf-8") as f:
            json.dump(rewritten, f)
    except OSError as e:
        logger.warning(f"compile_commands: could not write rebased DB to {out_host_path}: {e}")
        return None
    return out_host_path, len(rewritten), rebased
