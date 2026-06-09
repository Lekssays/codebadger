# 🦡 codebadger

A containerized **Model Context Protocol (MCP)** server providing static code
analysis via [Joern](https://joern.io/) Code Property Graphs (CPG), with support
for Java, C/C++, JavaScript, Python, Go, Kotlin, C#, Ghidra, Jimple, PHP, Ruby,
and Swift.

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
