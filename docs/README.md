# 🦡 codebadger Documentation

codebadger is a containerized **Model Context Protocol (MCP)** server that exposes
[Joern](https://joern.io/) Code Property Graph (CPG) analysis as LLM-callable
tools. It supports Java, C/C++, JavaScript, Python, Go, Kotlin, C#, Ghidra,
Jimple, PHP, Ruby, and Swift.

These docs are for two audiences:

- **Developers** deploying, operating, or extending the server.
- **Security researchers** using the tools to hunt vulnerabilities and build PoCs.

## Contents

| Doc | What's in it |
|-----|--------------|
| [Installation](installation.md) | Prerequisites and a 5-minute local setup. |
| [Usage](usage.md) | Connecting MCP clients, the tool catalog, and a researcher workflow with examples. |
| [Configuration](configuration.md) | `config.yaml` + environment variable reference, telemetry. |
| [Deployment](deployment.md) | Docker Compose, Postgres/Redis profiles, memory sizing, `shared` vs `pool` mode, large batches. |
| [Architecture](architecture.md) | System design, request flow, memory-aware admission, and design decisions (with diagrams). |
| [Custom Tools](custom-tools.md) | Add your own detectors without touching the core. |
| [Contributing](contributing.md) | Dev setup, running tests, and contribution guidelines. |
| [Roadmap](roadmap.md) | What's shipped and what's next. |

## Quick links

- New here? Start with [Installation](installation.md) → [Usage](usage.md).
- Running a large batch (e.g. hundreds of CVEs)? See [Deployment → Scaling](deployment.md#scaling-large-batches).
- Want to understand *why* it's built this way? See [Architecture](architecture.md).
- Found a bug with codebadger? Add it to [TROPHIES.md](../TROPHIES.md).
