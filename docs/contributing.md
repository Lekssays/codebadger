# Contributing

## Development setup

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
docker compose up -d        # Joern container, needed for integration tests
```

See [Installation](installation.md) for prerequisites.

## Running tests

```bash
pytest tests/ -q            # unit tests
```

Integration tests need the Joern container running and the MCP server up:

```bash
python main.py &            # start the server in the background
pytest tests/integration -q
pkill -f "python main.py"   # stop it
```

Some `tests/test_postgres_*` cases are skipped unless a live Postgres is
available - export a DSN to run them:

```bash
CODEBADGER_TEST_PG_DSN=postgresql://codebadger:codebadger@localhost:55432/codebadger pytest tests/test_postgres_db_manager.py -q
```

## Guidelines

- Follow existing repository conventions.
- Add tests for behavioral changes.
- Ensure all tests pass before opening a PR.
- Write a clear PR description.
- Update the relevant doc under [docs/](README.md) when behavior changes.

Adding a new detector? See [Custom Tools](custom-tools.md) - no core changes needed.
