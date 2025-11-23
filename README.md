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
### Core Tools (hash-based)
- `generate_cpg`: Generate a CPG for a codebase (from local path or GitHub URL)
- `get_cpg_status`: Get status and existence of a CPG by `codebase_hash`
- `run_cpgql_query`: Execute CPGQL queries (synchronous)

### Code Browsing Tools
- `get_codebase_summary`: Get codebase overview
- `list_files`: List source files
- `list_methods`: Discover methods/functions
- `get_method_source`: Retrieve method source code
- `list_calls`: Find function call relationships
- `get_call_graph`: Build call graphs
- `list_parameters`: Get parameter information
- `find_literals`: Search for hardcoded values
- `get_code_snippet`: Retrieve code snippets

- `find_taint_sources`: Locate external input points
- `find_taint_sinks`: Locate dangerous sinks
- `find_taint_flows`: Find dataflow paths
- `find_argument_flows`: Find expression reuse
- `check_method_reachability`: Check call graph connections
- `list_taint_paths`: List detailed taint paths
- `get_program_slice`: Build program slices

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
```

### Config File

Create a `config.yaml` from `config.example.yaml`:

```bash
cp config.example.yaml config.yaml
```

Then customize as needed.




