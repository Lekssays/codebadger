# 🦡 codebadger

**codebadger** is a containerized **Model Context Protocol (MCP)** server that
gives AI agents and LLMs deep, queryable access to a codebase's structure and
data flow through [Joern](https://joern.io/) Code Property Graphs (CPGs).

Point it at a Git repository, a local path, or even a pasted code snippet, and
codebadger builds a CPG and exposes it over MCP — so an assistant can run CPGQL
queries, trace data flow and taint, slice programs, and hunt for vulnerabilities
across Java, C/C++, JavaScript, Python, Go, Kotlin, C#, Ghidra, Jimple, PHP,
Ruby, and Swift.

It's a general-purpose foundation for both **program analysis** (understanding
code structure, call graphs, and data flow) and **vulnerability analysis**
(taint tracking, bug hunting, and PoC development) — useful for **academic
research** as well as **industry** security and engineering work. It's built to
scale to large analysis batches with per-CPG worker pools, memory-aware
scheduling, and a Postgres/Redis backend.

## News

codebadger and its paper - *Bridging Code Property Graphs and Language Models for
Program Analysis* - were accepted at the **Software Vulnerability Management
Workshop @ ICSE 2026**. 🎉

## Documentation

Everything a developer or security researcher needs lives in **[docs/](docs/)**:

| Doc | What's in it |
|-----|--------------|
| [Installation](docs/installation.md) | Prerequisites and a 5-minute local setup. |
| [Usage](docs/usage.md) | Connecting MCP clients, the tool catalog, and a researcher workflow. |
| [Available Tools](docs/available-tools.md) | Every MCP tool by category, with a description of what each does. |
| [Configuration](docs/configuration.md) | `config.yaml` / env reference, telemetry. |
| [Deployment](docs/deployment.md) | Postgres/Redis, memory sizing, `shared` vs `pool`, large batches. |
| [Architecture](docs/architecture.md) | System design and diagrams. |
| [Security](docs/security.md) | Threat model, trust boundaries, and production hardening. |
| [Custom Tools](docs/custom-tools.md) | Add your own detectors. |
| [Contributing](docs/contributing.md) | Dev setup, tests, and guidelines. |
| [Roadmap](docs/roadmap.md) | What's shipped and what's next. |

## Found a vulnerability using codebadger?

We'd love to hear about it - open a PR adding it to [TROPHIES.md](TROPHIES.md)
(CVE ID, project, one-line description, date).

## Citation

```bibtex
@inproceedings{lekssays2026bridging,
  title={Bridging Code Property Graphs and Language Models for Program Analysis},
  author={Lekssays, Ahmed},
  booktitle={Proceedings of the 2026 IEEE/ACM 4th International Workshop on Software Vulnerability Management},
  pages={33--40},
  year={2026}
}
```
