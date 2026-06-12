# Configuration

codebadger reads `config.yaml` and overlays environment variables. **An env var
is only honored where `config.yaml` uses a `${VAR:default}` placeholder** - so
the YAML is the source of truth for which knobs are env-overridable. At startup
the server logs the *effective* config and warns when an env var you set was
ignored.

```bash
cp config.example.yaml config.yaml   # start from the template
```

## Key settings

| Setting (`config.yaml`) | Env var | Default | Purpose |
|---|---|---|---|
| `server.host` / `server.port` | `MCP_HOST` / `MCP_PORT` | `127.0.0.1` / `4242` | MCP listen address. |
| `joern.java_opts` | `JOERN_JAVA_OPTS` | `-Xmx4G …` | Per-query-server JVM heap. |
| `joern.memory_budget_mb` | `JOERN_MEMORY_BUDGET_MB` | `0` (auto) | Query-pool RAM ceiling; the real concurrency limit. |
| `joern.rss_eviction_threshold_mb` | - | `0` (auto) | Evict LRU above this container RSS (backstop). |
| `joern.worker_mode` | `JOERN_WORKER_MODE` | `shared` | `shared` or `pool` - see [Deployment](deployment.md#shared-vs-pool-mode). |
| `cpg.generation_timeout` | - | `1800` | Max seconds for a CPG build. |
| `cpg.build_workers` | `CPG_BUILD_WORKERS` | `4` | Concurrent CPG builds. Auto-clamped at startup so `build_workers × build_heap` fits the build container's memory cap (prevents OOM-killed builds). |
| `cpg.queue_backend` | `CPG_QUEUE_BACKEND` | `durable` | `durable` (Postgres-backed) or `memory` (throwaway single-process). |
| `cpg.ephemeral_source` | `CPG_EPHEMERAL_SOURCE` | `true` | Delete the source snapshot once the CPG is built (the CPG is the only persisted artifact). Set `false` to keep snapshots for build debugging. |
| `cpg.max_repo_size_mb` | `MAX_REPO_SIZE_MB` | `1024` | Soft cap before `generate_cpg` requires `force`. |
| `joern.verify_timeout_seconds` | `JOERN_VERIFY_TIMEOUT_SECONDS` | `60` | Per-poll read timeout for the post-import readiness probe (bounded by the load timeout). Replaces the old hard-coded 15s that condemned valid CPGs under load. |
| `joern.load_max_attempts` | `JOERN_LOAD_MAX_ATTEMPTS` | `3` | Reload-from-disk retries for a *transient* load failure before marking a codebase failed; an empty/broken build is never retried. |
| `query.timeout` | `QUERY_TIMEOUT` | `30` | CPGQL query timeout (seconds). |
| `query.cache_ttl` | `QUERY_CACHE_TTL` | `300` | Tool-result cache TTL (seconds). |
| - | `DATABASE_URL` | Compose Postgres (`…@localhost:55432/codebadger`) | **Required.** Postgres DSN for the whole store. Boot fails if unreachable. |
| - | `REDIS_URL` | Compose Redis (`redis://localhost:56379/0`) | **Required.** Redis for cross-process coordination + pool ledger. Boot fails if unreachable. |
| - | `JOERN_IDLE_TTL_SECONDS` | `600` | Offload a Joern worker idle this long; next query reactivates it. |

Memory-related settings are deliberately `0` (auto-derive from host RAM). Run
`python scripts/recommend_config.py` to see what they resolve to and why - see
[Deployment → Sizing](deployment.md#sizing-for-your-host).

## Telemetry (OpenTelemetry)

Disabled by default (zero overhead). When enabled, every MCP tool call is traced,
plus spans for CPG generation, server management, and query execution.

```yaml
telemetry:
  enabled: true
  service_name: codebadger
  otlp_endpoint: http://localhost:4317
  otlp_protocol: grpc        # or "http/protobuf"
```

Or via env: `OTEL_ENABLED=true OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317`.

Local trace viewer (Jaeger UI at `http://localhost:16686`):

```bash
docker run -d --name jaeger -p 16686:16686 -p 4317:4317 jaegertracing/all-in-one:latest
OTEL_ENABLED=true python main.py
```

| Span | Description |
|------|-------------|
| `tools/call {name}` | Every MCP tool invocation (automatic). |
| `cpg.generate` | Full CPG generation pipeline. |
| `cpg.joern_cli_exec` | Joern CLI execution inside Docker. |
| `cpg.spawn_server` / `cpg.load_cpg` | Server creation / CPG load. |
| `query.execute` | CPGQL query execution with timing. |
