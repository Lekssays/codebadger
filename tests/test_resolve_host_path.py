"""Tests for resolve_host_path(require_local_access=...).

The containerized MCP can't see a host source path on its own filesystem, so the local
existence/is-dir checks must be skippable (the copy is then done via a host-daemon helper).
String-level security checks must still apply in both modes."""

import pytest

from src.exceptions import ValidationError
from src.utils.validators import resolve_host_path


@pytest.fixture(autouse=True)
def _no_allowlist(monkeypatch):
    # No ALLOWED_SOURCE_ROOTS restriction in these tests.
    monkeypatch.setenv("ALLOWED_SOURCE_ROOTS", "")


def test_existing_dir_default_mode(tmp_path):
    resolved = resolve_host_path(str(tmp_path))
    assert resolved == str(tmp_path.resolve())


def test_missing_path_raises_in_default_mode(tmp_path):
    ghost = tmp_path / "does_not_exist"
    with pytest.raises(ValidationError, match="does not exist"):
        resolve_host_path(str(ghost))


def test_missing_path_allowed_when_local_access_not_required(tmp_path):
    """Containerized MCP path: existence check deferred to the daemon helper."""
    ghost = tmp_path / "does_not_exist"
    resolved = resolve_host_path(str(ghost), require_local_access=False)
    assert resolved == str(ghost)  # canonical, even though it doesn't exist here


def test_relative_path_rejected_in_both_modes():
    for require in (True, False):
        with pytest.raises(ValidationError, match="absolute"):
            resolve_host_path("relative/path", require_local_access=require)


def test_control_characters_rejected_in_both_modes():
    for require in (True, False):
        with pytest.raises(ValidationError):
            resolve_host_path("/tmp/with\x00null", require_local_access=require)


def test_blocked_prefix_rejected_even_without_local_access():
    with pytest.raises(ValidationError):
        resolve_host_path("/etc/passwd_dir", require_local_access=False)


def test_allowed_source_roots_enforced_without_local_access(tmp_path, monkeypatch):
    """Containment guard still applies when existence checking is skipped."""
    monkeypatch.setenv("ALLOWED_SOURCE_ROOTS", str(tmp_path / "allowed"))
    outside = tmp_path / "elsewhere" / "src"
    with pytest.raises(ValidationError, match="allowed source roots"):
        resolve_host_path(str(outside), require_local_access=False)
