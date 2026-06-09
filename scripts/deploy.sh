#!/usr/bin/env bash
#
# One-command deploy for the full CodeBadger stack:
#   MCP server + Joern + Postgres + Redis, via docker compose.
#
# Usage:
#   scripts/deploy.sh [up|down|restart|logs|status]   (default: up)
#
# `up` builds the images, brings the stack up, and waits for /health to report
# the server is serving. It exports an ABSOLUTE PLAYGROUND_HOST_PATH so that pool
# worker containers (started by the MCP via the host Docker daemon) bind the
# correct host directory.
set -euo pipefail

# Repo root = parent of this script's dir, regardless of CWD.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Absolute path so the daemon resolves pool sibling-container bind mounts correctly.
export PLAYGROUND_HOST_PATH="${PLAYGROUND_HOST_PATH:-$ROOT/playground}"

MCP_PORT="${MCP_PORT:-4242}"
HEALTH_URL="http://localhost:${MCP_PORT}/health"
CMD="${1:-up}"

# docker compose v2 (plugin) or legacy docker-compose.
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: Docker Compose not found." >&2
  echo "Install Docker Engine + the Compose plugin: https://docs.docker.com/engine/install/" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: cannot talk to the Docker daemon (is it running? do you have permission?)." >&2
  exit 1
fi

wait_for_health() {
  echo "Waiting for the MCP server to come up at ${HEALTH_URL} ..."
  for _ in $(seq 1 60); do
    # /health returns 200 for up/partial, 503 for down. Accept either response so
    # we can print the dependency detail even when something is degraded.
    if body="$(curl -fsS "$HEALTH_URL" 2>/dev/null)" || body="$(curl -sS "$HEALTH_URL" 2>/dev/null)"; then
      if echo "$body" | grep -q '"status"'; then
        echo "$body" | (python3 -m json.tool 2>/dev/null || cat)
        status="$(echo "$body" | sed -n 's/.*"status"[： :]*"\([a-z]*\)".*/\1/p' | head -1)"
        case "$status" in
          up)      echo "✅ CodeBadger is up."; return 0 ;;
          partial) echo "⚠️  CodeBadger is partial — see dependencies above."; return 0 ;;
        esac
      fi
    fi
    sleep 2
  done
  echo "❌ MCP server did not become healthy in time. Check: ${COMPOSE[*]} logs codebadger-mcp" >&2
  return 1
}

case "$CMD" in
  up)
    mkdir -p "$PLAYGROUND_HOST_PATH" "$ROOT/logs"
    echo "Playground (host): $PLAYGROUND_HOST_PATH"
    "${COMPOSE[@]}" up -d --build
    wait_for_health
    ;;
  down)
    "${COMPOSE[@]}" down
    ;;
  restart)
    "${COMPOSE[@]}" restart codebadger-mcp
    wait_for_health
    ;;
  logs)
    shift || true
    "${COMPOSE[@]}" logs -f "${@:-codebadger-mcp}"
    ;;
  status)
    "${COMPOSE[@]}" ps
    curl -fsS "$HEALTH_URL" | (python3 -m json.tool 2>/dev/null || cat) || true
    ;;
  *)
    echo "Usage: $0 [up|down|restart|logs|status]" >&2
    exit 2
    ;;
esac
