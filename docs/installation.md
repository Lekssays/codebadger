# Installation

There are two ways to run codebadger:

- **A — Full stack with Docker (recommended).** One command brings up the MCP
  server + Joern + Postgres + Redis as containers. Best for production and the
  quickest way to get a working server.
- **B — Local development.** Run the backing services in Docker and the MCP server
  from your Python checkout, for iterating on the server itself.

---

## A. Full stack with Docker (recommended)

### 1. Prerequisites

- **Docker Engine** + the **Compose v2 plugin** — install: <https://docs.docker.com/engine/install/>
- Permission to use the Docker socket (deploy user in the `docker` group, or root)
- A host **dedicated to codebadger** — the MCP container mounts the Docker socket
  (root-equivalent on the host; see [Deployment → Trust boundary](deployment.md#quick-start-full-stack))

```bash
docker --version && docker compose version
```

### 2. Get the code

```bash
git clone http://github.com/lekssays/codebadger && cd codebadger
```

### 3. Configure for your host

```bash
cp .env.example .env
```

Edit `.env` and set at least:

- `PLAYGROUND_HOST_PATH` — **absolute** path to `./playground` (e.g. `/opt/codebadger/playground`). Required so per-CPG worker containers, started via the host daemon, bind the right directory.
- `MCP_HOST` — `0.0.0.0` to expose on all interfaces, or `127.0.0.1` if a reverse proxy fronts it.

Then size memory for your host (RAM is the binding constraint) and copy the
suggested values into `.env`:

```bash
python scripts/recommend_config.py     # prints JOERN_MEM_LIMIT / JOERN_MEMORY_BUDGET_MB
```

> No Python on the host? Skip this and start with the `.env.example` defaults
> (`JOERN_MEMORY_BUDGET_MB=0` auto-derives from host RAM); tune later.

### 4. Deploy

```bash
./scripts/deploy.sh        # builds images, starts the stack, waits for /health
```

### 5. Verify

```bash
./scripts/deploy.sh status
curl -s http://localhost:4242/health | python3 -m json.tool
# -> {"status":"up","mcp":"codebadger","dependencies":{"joern":"up","postgres":"up","redis":"up",...}}
```

The MCP endpoint is at `http://<host>:4242/mcp`, health at `/health`.

See [Deployment](deployment.md) for day-2 operations (logs, restart, upgrade,
backups), worker modes, and scaling to large batches.

---

## B. Local development (MCP on the host)

Run the backing services in containers but the MCP server from your checkout.

### 1. Prerequisites

- Docker Engine + Compose v2 (as above)
- **Python 3.10+** (3.13 recommended)

```bash
docker --version && docker compose version && python --version
```

### 2. Install Python dependencies

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 3. Start the backing services only

`--scale codebadger-mcp=0` brings up Joern + Postgres + Redis without the MCP
container, so it doesn't collide with the one you run on the host:

```bash
docker compose up -d --scale codebadger-mcp=0
docker compose ps        # codebadger-joern-server / -postgres / -redis up
```

### 4. Create your config

```bash
cp config.example.yaml config.yaml
```

### 5. Start the MCP server

It defaults to the Compose Postgres (`localhost:55432`) and Redis
(`localhost:56379`) and creates the Postgres schema on first start, so no extra
env is needed:

```bash
python main.py
```

> Postgres and Redis are required — the server exits with a clear error if either
> is unreachable. `main.py` does **not** read `.env`; set `JOERN_MEM_LIMIT` etc. in
> your shell if you need to override them.

### 6. Verify

```bash
curl -s http://localhost:4242/health | python3 -m json.tool
```

---

## Next steps

- Connect a client and run your first analysis → [Usage](usage.md)
- Production deployment, scaling, worker modes → [Deployment](deployment.md)
- Tune memory, ports, telemetry → [Configuration](configuration.md)

## Reset / cleanup

```bash
bash cleanup.sh        # clears codebases, CPGs, and Postgres/Redis state
docker compose down    # stop & remove containers (playground/ + pgdata/ persist)
```
