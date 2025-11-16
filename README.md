# 🦡 codebadger-toolkit

A containerized Model Context Protocol (MCP) server providing static code analysis using Joern's Code Property Graph (CPG) technology with support for Java, C/C++, JavaScript, Python, Go, Kotlin, C#, Ghidra, Jimple, PHP, Ruby, and Swift.

## Quick Start

### Build and Run the Container

```bash
docker compose up --build
```

The MCP server will be available at `http://localhost:4242`.

### Stop the Service

```bash
docker compose down
```

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
    "codebadger-toolkit": {
      "url": "http://localhost:4242/mcp",
      "type": "http"
    }
  }
}
```

---

### Claude Code Integration

To integrate `codebadger-toolkit` into **Claude Desktop**, edit:

**Path:**

```
Claude → Settings → Developer → Edit Config → claude_desktop_config.json
```

Add the following:

```json
{
  "mcpServers": {
    "codebadger-toolkit": {
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

### Security Analysis Tools
- `find_taint_sources`: Locate external input points
- `find_taint_sinks`: Locate dangerous sinks
- `find_taint_flows`: Find dataflow paths
- `find_argument_flows`: Find expression reuse
- `check_method_reachability`: Check call graph connections
- `list_taint_paths`: List detailed taint paths
- `get_program_slice`: Build program slices

## Contributing & Tests

Thanks for contributing! Here's a quick guide to get started with running tests and contributing code.

Prerequisites
- Python 3.10+ (3.13 is used in CI)
- Docker and Docker Compose (for integration tests)

Local development
1. Create a virtual environment and install dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Run unit tests

```bash
pytest -q
```

3. Run integration tests (requires Docker Compose)

```bash
docker compose up --build -d
pytest -q tests/integration
docker compose down
```

4. Run all tests

```bash
pytest -q
```

Please follow the repository conventions and open a PR with a clear changelog and tests for changes that affect behavior.

## Configuration

Optional configuration via `config.yaml` (copy from `config.example.yaml`).

Key settings:
- Server host/port
- Redis settings
- Session timeouts
- CPG generation settings


