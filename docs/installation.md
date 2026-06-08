# Installation

## Prerequisites

- **Docker** and **Docker Compose**
- **Python 3.10+** (3.13 recommended)

```bash
docker --version && docker compose version && python --version
```

## Local setup

```bash
# 1. Install Python dependencies (a venv is recommended)
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Build and start the Joern container
docker compose up -d

# 3. Create your config from the template
cp config.example.yaml config.yaml

# 4. Start the MCP server
python main.py
```

The server listens on `http://localhost:4242` (MCP endpoint at `/mcp`, health at
`/health`). On startup it prints a memory-aware config recommendation for your
host - see [Deployment](deployment.md#sizing-for-your-host).

Verify it's up:

```bash
curl -s http://localhost:4242/health | python -m json.tool
docker compose ps
```

## Next steps

- Connect a client and run your first analysis → [Usage](usage.md).
- Going to production or running big batches → [Deployment](deployment.md).
- Tune memory, ports, telemetry → [Configuration](configuration.md).

## Reset / cleanup

```bash
bash cleanup.sh      # clears codebases, CPGs, and Postgres/Redis state
docker compose down  # stop containers
```
