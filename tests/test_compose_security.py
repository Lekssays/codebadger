"""Guards on docker-compose security posture.

These parse the committed docker-compose.yml directly (no Docker required) so a
regression that re-exposes an internal service on all interfaces fails in CI.
"""

import os

import pytest
import yaml

COMPOSE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docker-compose.yml")


@pytest.fixture(scope="module")
def compose():
    with open(COMPOSE_PATH) as f:
        return yaml.safe_load(f)


@pytest.mark.parametrize(
    "service_name",
    ["codebadger-joern-server", "codebadger-postgres", "codebadger-redis"],
)
def test_internal_services_bind_loopback(compose, service_name):
    """Joern REPL, Postgres, and Redis must never publish on all interfaces.

    Joern runs an unauthenticated Scala REPL; Postgres/Redis hold all run state.
    Publishing any of these without a 127.0.0.1 host-ip prefix would expose them
    to the network and bypass the MCP's validation layer. The ${VAR:-default}
    substitutions embed colons, so we match the loopback prefix rather than
    splitting on ':'.
    """
    service = compose["services"][service_name]
    published = service.get("ports", [])
    assert published, f"{service_name} has no published ports to check"
    for mapping in published:
        assert isinstance(mapping, str), f"unexpected long-form port entry: {mapping!r}"
        assert mapping.startswith("127.0.0.1:"), (
            f"{service_name} publishes {mapping!r} on a non-loopback interface; "
            f"prefix it with 127.0.0.1:"
        )
