# Deployment

## Topologies

```mermaid
flowchart TB
    subgraph single[Single process - default]
        M1[main.py] --> S1[(SQLite<br/>catalog + cache + queue)]
        M1 --> J1[codebadger-joern-server]
    end
    subgraph multi[Multi-process - shared state]
        M2[main.py #1] --> PG[(Postgres<br/>catalog + cache + findings + jobs)]
        M3[main.py #2] --> PG
        M2 --> R[(Redis<br/>pool ledger + locks)]
        M3 --> R
        M2 --> W[Joern workers]
        M3 --> W
    end
```

The default single-process setup needs only the Joern container. To run several
API/scheduler processes against one shared catalog and queue, add **Postgres**
(state) and **Redis** (coordination). Both sit behind Compose **profiles**, so a
plain `docker compose up -d` will *not* start them - you must pass the profile.

```bash
docker compose up -d                                       # Joern only (default)
docker compose --profile postgres up -d                    # + Postgres (host port 55432)
docker compose --profile redis up -d                       # + Redis (host port 56379)
docker compose --profile postgres --profile redis up -d    # Joern + Postgres + Redis together
```

Verify all three are up, then tear down (profiles needed for `down` too):

```bash
docker compose --profile postgres --profile redis ps
docker compose --profile postgres --profile redis down
```

> Postgres publishes on **55432** and Redis on **56379** (non-default ports) to
> avoid clashing with system services; override with `POSTGRES_PORT` / `REDIS_PORT`.

Point the server at them (it creates the Postgres schema on first start):

```bash
DATABASE_URL=postgresql://codebadger:codebadger@localhost:55432/codebadger \
REDIS_URL=redis://localhost:56379/0 \
CPG_QUEUE_BACKEND=durable python main.py
```

`DATABASE_URL` moves the **entire store** - catalog, tool cache, findings, *and*
the job queue (`FOR UPDATE SKIP LOCKED`) - to Postgres. `REDIS_URL` makes the
per-CPG query lock and (in `pool` mode) the shared pool state cross-process.

## Sizing for your host

RAM, not CPU, is the binding constraint - each Joern server is a JVM with its own
heap. Print the memory-aware recommendation before launching:

```bash
python scripts/recommend_config.py                       # autodetect this host
python scripts/recommend_config.py --compare config.yaml # flag risky drift
python scripts/recommend_config.py --worker-mode pool    # values for pool mode
python scripts/recommend_config.py --mem 256 --cores 96  # plan another host
```

The same block logs at startup (disable with `RECOMMEND_ON_STARTUP=false`). The
model reserves ~15% of RAM for OS/Docker/DB, splits the rest between a
CPG-generation reserve and a query pool, and sizes concurrency so heaps fit the
query budget. Leave `memory_budget_mb` / `rss_eviction_threshold_mb` at `0` to
auto-derive.

### CPG size tiers

`importCpg` runs overlay passes that need roughly as much RAM as the CPG `.bin`
is large. The scheduler sizes each server's heap to the CPG's tier:

| Tier | CPG `.bin` | Heap (`-Xmx`) | Reserve | Example |
|------|-----------|---------------|---------|---------|
| S | ≤ 1 GB | 2 GB | 3 GB | libsoup, small libxml2 modules |
| M | ≤ 4 GB | 6 GB | 8 GB | ImageMagick, php, wireshark dissectors |
| L | ≤ 12 GB | 16 GB | 20 GB | full wireshark, large php |
| XL | > 12 GB | 28 GB | 32 GB | v8 (keep 1–2 concurrent) |

## `shared` vs `pool` mode

`JOERN_WORKER_MODE` controls where query servers run:

```mermaid
flowchart LR
    subgraph shared[shared default]
        direction TB
        C1[codebadger-joern-server] --> P1[build + all query servers<br/>as processes in ONE container]
    end
    subgraph pool[pool]
        direction TB
        C2[codebadger-joern-server<br/>builds only] -.-> X[ ]
        C2 --> WK1[worker container<br/>cgroup-capped]
        C2 --> WK2[worker container<br/>cgroup-capped]
    end
```

- **`shared`** (default) - every query server is a process inside the single
  `codebadger-joern-server` container. Set its `mem_limit` to the whole Joern budget.
- **`pool`** - each CPG's query server runs in its **own cgroup-capped container**,
  so an OOM kills just that worker, not every server. Here the
  `codebadger-joern-server` container *only builds* CPGs, so cap it at the **build
  reserve** and let the worker pool use the rest via `memory_budget_mb`.

> **Pool-mode invariant:** `build container mem_limit + memory_budget_mb ≤ Joern
> budget`. If the build container is left at the full budget, the startup guard
> clamps the worker budget (and warns) to prevent host over-commit - so set
> `JOERN_MEM_LIMIT` to the build reserve (e.g. `30g`) in **both** `docker-compose`
> and the manager's environment. `main.py` does not read `.env`.

Pool state (reservation ledger, warm-worker registry, global LRU, per-CPG spawn
lock) lives in Redis when `REDIS_URL` is set, so multiple processes coordinate
spawn/eviction without over-committing - and any process can serve a CPG another
started. See [Architecture → Memory-aware admission](architecture.md#memory-aware-admission).

## Scaling: large batches

Driving hundreds of CPGs (e.g. a CVE corpus):

- **Use the durable queue:** `CPG_QUEUE_BACKEND=durable` (DB-backed jobs table)
  survives restarts, dedups, and applies backpressure instead of silently dropping.
  Put it on Postgres for multi-process operation.
- **Handle backpressure:** `generate_cpg` returns `queue_full` when saturated and
  the HTTP layer returns `503` past `MAX_MCP_CONNECTIONS`. Your driver must
  **retry** and **poll `get_cpg_status`**, not fire everything at once.
- **Generate ahead, query on demand:** pre-build the set, then query. Idle servers
  sleep and wake on demand, so you don't pay generation and query memory at once.
- **Cap the container:** always set a `mem_limit` on `codebadger-joern-server` so a
  runaway analysis can't take down the host.

### Large repositories

For huge codebases, analyze a **sub-component** (e.g. `/path/to/v8/src/parsing`)
rather than the repo root. Default exclusion patterns already skip tests, docs,
vendored deps, and build output. Raise `CPG_GENERATION_TIMEOUT` for the very
largest frontends.
