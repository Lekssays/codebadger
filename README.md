# 🦡 codebadger

A containerized Model Context Protocol (MCP) server providing static code analysis using Joern's Code Property Graph (CPG) technology with support for Java, C/C++, JavaScript, Python, Go, Kotlin, C#, Ghidra, Jimple, PHP, Ruby, and Swift.

## Prerequisites

Before you begin, make sure you have:

- **Docker** and **Docker Compose** installed
- **Python 3.10+** (Python 3.13 recommended)
- **pip** (Python package manager)

To verify your setup:

```bash
docker --version
docker-compose --version
python --version
```

## Quick Start

### 1. Install Python Dependencies

```bash
# Create a virtual environment (optional but recommended)
python -m venv venv

# Install dependencies
pip install -r requirements.txt
```

### 2. Start the Docker Services (Joern)

```bash
docker compose up -d
```

This starts:
- **Joern Server**: Static code analysis engine (runs CPG generation and queries)

Verify services are running:

```bash
docker compose ps
```

### 3. Start the MCP Server

```bash
# Start the server
python main.py &
```

The MCP server will be available at `http://localhost:4242`.

### 4. Stop All Services

```bash
# Stop MCP server (Ctrl+C in terminal)

# Stop Docker services
docker-compose down
# Optional: Clean up everything
bash cleanup.sh
```

## Cleanup Script

Use the provided cleanup script to reset your environment:

```bash
bash cleanup.sh
```

This will:
- Stop and remove Docker containers
- Kill orphaned Joern/MCP processes
- Clear Python cache (`__pycache__`, `.pytest_cache`)
- Optionally clear the playground directory (CPGs and cached codebases)

## Integrations 

### GitHub Copilot Integration

Edit the MCP configuration file for VS Code (GitHub Copilot):

**Path:**

```
~/.config/Code/User/mcp.json
```

**Example configuration:**

```json
{
  "inputs": [],
  "servers": {
    "codebadger": {
      "url": "http://localhost:4242/mcp",
      "type": "http"
    }
  }
}
```

<!-- Removed malformed duplicate GitHub Copilot JSON example -->
---

### Claude Code Integration

To integrate `codebadger` into **Claude Desktop**, edit:

**Path:**

```
Claude → Settings → Developer → Edit Config → claude_desktop_config.json
```

Add the following:

```json
{
  "mcpServers": {
    "codebadger": {
      "url": "http://localhost:4242/mcp",
      "type": "http"
    }
  }
}
```

## Available Tools

### Core
- `generate_cpg`: Generate a Code Property Graph (CPG) for a codebase (local path or GitHub URL).
- `get_cpg_status`: Check whether a CPG exists and retrieve status metadata.
- `run_cpgql_query`: Execute a raw CPGQL query against a CPG and return structured results.
- `get_cpgql_syntax_help`: Show CPGQL syntax helpers, tips, and common error fixes.

### Code browsing
- `list_methods`: List methods/functions with optional regex/file filters.
- `list_files`: Show source files as a paginated tree view.
- `get_method_source`: Retrieve the source code for a named method.
- `list_calls`: List call sites between functions (caller → callee).
- `get_call_graph`: Build a human-readable call graph (incoming or outgoing).
- `list_parameters`: Get parameter names, types, and order for a method.
- `get_codebase_summary`: High-level metrics (files, methods, calls, language).
- `get_code_snippet`: Return a file snippet by start/end line numbers.

### Semantic analysis
- `get_cfg`: Produce a control-flow graph (nodes and edges) for a method.
- `get_type_definition`: Inspect struct/class types and their members.
- `get_macro_expansion`: Heuristically detect likely macro-expanded calls.

### Taint & vulnerability analysis
- `find_taint_sources`: Find likely external input points (sources).
- `find_taint_sinks`: Locate dangerous sinks where tainted data can flow.
- `find_taint_flows`: Detect dataflows from sources to sinks (taint analysis).
- `get_program_slice`: Build backward/forward program slices for a call.
- `get_variable_flow`: Trace data dependencies for a variable at a location.
- `find_bounds_checks`: Search for bounds-checks near a buffer access.
- `find_use_after_free`: Heuristic detection of use-after-free patterns.
- `find_double_free`: Detect potential double-free issues.
- `find_null_pointer_deref`: Find likely null pointer dereferences.
- `find_integer_overflow`: Detect integer overflow patterns.

### Export & reporting
- `store_findings`: Parse and store analysis findings into the database.
- `export_sarif`: Export high-confidence findings in SARIF format.

## Contributing & Tests

Thanks for contributing! Here's a quick guide to get started with running tests and contributing code.

### Prerequisites

- Python 3.10+ (3.13 is used in CI)
- Docker and Docker Compose (for integration tests)

### Local Development Setup

1. Create a virtual environment and install dependencies

```bash
python -m venv venv
pip install -r requirements.txt
```

2. Start Docker services (for integration tests)

```bash
docker-compose up -d
```

3. Run unit tests

```bash
pytest tests/ -q
```

4. Run integration tests (requires Docker Compose running)

```bash
# Start MCP server in background
python main.py &

# Run integration tests
pytest tests/integration -q

# Stop MCP server
pkill -f "python main.py"
```

<!-- Removed duplicate run/cleanup instructions -->

5. Run all tests

```bash
pytest tests/ -q
```

6. Cleanup after testing

```bash
bash cleanup.sh
docker-compose down
```

### Code Contributions

Please follow these guidelines when contributing:

1. Follow repository conventions
2. Write tests for behavioral changes
3. Ensure all tests pass before submitting PR
4. Include a clear changelog in your PR description
5. Update documentation if needed

## Configuration

The MCP server can be configured via environment variables or `config.yaml`.

### Environment Variables

Key settings (optional - defaults shown):

```bash
# Server
MCP_HOST=0.0.0.0
MCP_PORT=4242

# Joern
JOERN_BINARY_PATH=joern
JOERN_JAVA_OPTS="-Xmx4G -Xms2G -XX:+UseG1GC -Dfile.encoding=UTF-8"

# CPG Generation
CPG_GENERATION_TIMEOUT=600
MAX_REPO_SIZE_MB=500

# Query
QUERY_TIMEOUT=30
QUERY_CACHE_ENABLED=true
QUERY_CACHE_TTL=300

# Telemetry (OpenTelemetry)
OTEL_ENABLED=false
OTEL_SERVICE_NAME=codebadger
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
```

### Config File

Create a `config.yaml` from `config.example.yaml`:

```bash
cp config.example.yaml config.yaml
```

Then customize as needed.

## Telemetry (OpenTelemetry)

CodeBadger has built-in OpenTelemetry support for distributed tracing. When enabled, all MCP tool calls are automatically traced, plus custom spans for CPG generation, Joern server management, and query execution.

### Quick Start

1. Install the telemetry dependencies (included in `requirements.txt`):

```bash
pip install opentelemetry-sdk opentelemetry-exporter-otlp
```

2. Enable via environment variables:

```bash
export OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
python main.py
```

Or via `config.yaml`:

```yaml
telemetry:
  enabled: true
  service_name: codebadger
  otlp_endpoint: http://localhost:4317
  otlp_protocol: grpc  # or "http/protobuf"
```

### Local Development with Jaeger

```bash
# Start Jaeger (provides UI at http://localhost:16686)
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest

# Start CodeBadger with telemetry
OTEL_ENABLED=true python main.py
```

### What Gets Traced

| Span | Description |
|------|-------------|
| `tools/call {name}` | Every MCP tool invocation (automatic via FastMCP) |
| `cpg.generate` | Full CPG generation pipeline |
| `cpg.joern_cli_exec` | Joern CLI command execution inside Docker |
| `cpg.spawn_server` | Joern server instance creation |
| `cpg.load_cpg` | CPG file loading into Joern server |
| `query.execute` | CPGQL query execution with timing and success attributes |

### Configuration Reference

| Setting | Env Variable | Default | Description |
|---------|-------------|---------|-------------|
| `enabled` | `OTEL_ENABLED` | `false` | Enable/disable telemetry |
| `service_name` | `OTEL_SERVICE_NAME` | `codebadger` | Service name in traces |
| `otlp_endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTLP collector endpoint |
| `otlp_protocol` | `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` | Export protocol (`grpc` or `http/protobuf`) |

When telemetry is disabled (default), all tracing is no-op with zero overhead.




