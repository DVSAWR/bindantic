# Contributing to bindantic

## Development Setup

1. Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`
2. Clone repository: `git clone https://github.com/DVSAWR/bindantic.git`
3. Install dependencies: `make install-dev`
4. Install pre-commit hooks: `make pre-commit`

## Development Workflow

1. Create a feature branch
2. Make your changes
3. Run tests: `make test`
4. Run all checks: `make check-all`
5. Commit using conventional commits
6. Create a Pull Request

## Code Style

- Use type annotations everywhere
- Follow PEP 8 (enforced by ruff)
- Use descriptive variable names