"""Tests for JoernServerClient.load_cpg robustness (#5: 'No projects loaded').

These cover the failure mode where importCpg derives the project name from the
filename (always ``cpg.bin``), collides, and leaves no project open so the
verify query returns "No projects loaded". The client must:
  * import under an explicit, collision-free project name,
  * poll the verify query (absorb the import->register race),
  * re-import once on a no-project verdict,
  * distinguish an empty build (0 methods) from a load failure.
"""

import pytest

from src.services.joern_client import JoernServerClient, _safe_project_name


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    # The verify poll sleeps between attempts; skip the wait in tests.
    monkeypatch.setattr("src.services.joern_client.time.sleep", lambda *_: None)


def _client():
    # Construct without touching the network (session is created lazily/locally).
    return JoernServerClient(host="localhost", port=9999)


def _ok(stdout):
    return {"success": True, "stdout": stdout, "stderr": ""}


def _fail(stderr):
    return {"success": False, "stdout": "", "stderr": stderr}


# ── _safe_project_name ────────────────────────────────────────────────────────

def test_safe_project_name_strips_path_and_bin():
    assert _safe_project_name("/playground/cpgs/abc123def4567890/cpg.bin") == "cpg"


def test_safe_project_name_from_hash():
    assert _safe_project_name("abc123def4567890") == "abc123def4567890"


def test_safe_project_name_sanitizes_illegal_chars():
    assert _safe_project_name("we ird/na-me.bin") == "na_me"


# ── load_cpg ─────────────────────────────────────────────────────────────────

def test_load_uses_explicit_project_name_not_filename(monkeypatch):
    client = _client()
    seen = {}

    def fake_exec(query, timeout=600):
        if "importCpg" in query:
            seen["import"] = query
            return _ok("")
        return _ok("val res0: Int = 42")

    monkeypatch.setattr(client, "execute_query", fake_exec)
    assert client.load_cpg("/playground/cpgs/deadbeefdeadbeef/cpg.bin",
                           project_name="deadbeefdeadbeef") is True
    # The import must name the project after the hash, never the colliding "cpg.bin".
    assert 'importCpg("/playground/cpgs/deadbeefdeadbeef/cpg.bin", "deadbeefdeadbeef")' in seen["import"]
    assert 'open("deadbeefdeadbeef")' in seen["import"]


def test_load_success_first_try(monkeypatch):
    client = _client()
    monkeypatch.setattr(
        client, "execute_query",
        lambda q, timeout=600: _ok("") if "importCpg" in q else _ok("val res0: Int = 7"),
    )
    assert client.load_cpg("/p/cpgs/h/cpg.bin", project_name="h") is True


def test_no_projects_then_reimport_succeeds(monkeypatch):
    client = _client()
    state = {"import_calls": 0}

    def fake_exec(query, timeout=600):
        if "importCpg" in query:
            state["import_calls"] += 1
            return _ok("")
        # First import never registers a project; after the re-import it does.
        if state["import_calls"] < 2:
            return _ok("io.joern.console.Error: No projects loaded")
        return _ok("val res0: Int = 12")

    monkeypatch.setattr(client, "execute_query", fake_exec)
    assert client.load_cpg("/p/cpgs/h/cpg.bin", project_name="h") is True
    assert state["import_calls"] == 2  # re-imported exactly once


def test_persistent_no_projects_fails_after_one_reimport(monkeypatch):
    client = _client()
    state = {"import_calls": 0}

    def fake_exec(query, timeout=600):
        if "importCpg" in query:
            state["import_calls"] += 1
            return _ok("")
        return _ok("io.joern.console.Error: No projects loaded")

    monkeypatch.setattr(client, "execute_query", fake_exec)
    assert client.load_cpg("/p/cpgs/h/cpg.bin", project_name="h") is False
    assert state["import_calls"] == 2  # initial + exactly one re-import, no more


def test_empty_cpg_is_failure_not_retried(monkeypatch):
    client = _client()
    state = {"import_calls": 0}

    def fake_exec(query, timeout=600):
        if "importCpg" in query:
            state["import_calls"] += 1
            return _ok("")
        return _ok("val res0: Int = 0")  # project open but 0 methods

    monkeypatch.setattr(client, "execute_query", fake_exec)
    assert client.load_cpg("/p/cpgs/h/cpg.bin", project_name="h") is False
    # An empty build is not a no-project race — do not re-import.
    assert state["import_calls"] == 1


def test_load_recovers_when_verify_succeeds_after_import_error(monkeypatch):
    client = _client()

    def fake_exec(query, timeout=600):
        if "importCpg" in query:
            return _fail("Connection reset by peer")
        return _ok("val res0: Int = 5")  # but the CPG actually loaded

    monkeypatch.setattr(client, "execute_query", fake_exec)
    assert client.load_cpg("/p/cpgs/h/cpg.bin", project_name="h") is True
