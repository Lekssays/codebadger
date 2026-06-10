# 🦡 codebadger Documentation

codebadger is a containerized **Model Context Protocol (MCP)** server that gives
AI agents and LLMs deep, queryable access to a codebase's structure and data flow
through [Joern](https://joern.io/) Code Property Graphs (CPGs). Point it at a Git
repository, a local path, or a pasted code snippet, and it builds a CPG and
exposes it as LLM-callable tools for running CPGQL queries, tracing data flow and
taint, slicing programs, and hunting vulnerabilities — across Java, C/C++,
JavaScript, Python, Go, Kotlin, C#, Ghidra, Jimple, PHP, Ruby, and Swift. It
serves both general **program analysis** and **vulnerability analysis**, for
**academic research** and **industry** alike.

These docs are for two audiences:

- **Developers** deploying, operating, or extending the server.
- **Security researchers** using the tools to hunt vulnerabilities and build PoCs.

## Contents

| Doc | What's in it |
|-----|--------------|
| [Installation](installation.md) | Prerequisites and a 5-minute local setup. |
| [Usage](usage.md) | Connecting MCP clients, the tool catalog, and a researcher workflow with examples. |
| [Available Tools](available-tools.md) | Every MCP tool by category, with a description of what each does. |
| [Configuration](configuration.md) | `config.yaml` + environment variable reference, telemetry. |
| [Deployment](deployment.md) | Docker Compose, Postgres/Redis profiles, memory sizing, `shared` vs `pool` mode, large batches. |
| [Architecture](architecture.md) | System design, request flow, memory-aware admission, and design decisions (with diagrams). |
| [Security](security.md) | Threat model, trust boundaries, the controls we provide, and production hardening. |
| [Custom Tools](custom-tools.md) | Add your own detectors without touching the core. |
| [Contributing](contributing.md) | Dev setup, running tests, and contribution guidelines. |
| [Roadmap](roadmap.md) | What's shipped and what's next. |

## Quick links

- New here? Start with [Installation](installation.md) → [Usage](usage.md).
- Running a large batch (e.g. hundreds of CVEs)? See [Deployment → Scaling](deployment.md#scaling-large-batches).
- Want to understand *why* it's built this way? See [Architecture](architecture.md).
- Found a bug with codebadger? Add it to [TROPHIES.md](../TROPHIES.md).
