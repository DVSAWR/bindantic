.PHONY: help install-dev test lint format format-check type-check check-all clean pre-commit

GREEN_BOLD = \033[1;32m
CYAN_BOLD = \033[1;36m
RESET = \033[0m

help:
	@echo "$(GREEN_BOLD)USAGE:$(RESET)"
	@echo "  make $(CYAN_BOLD)<COMMAND>$(RESET)"
	@echo "$(GREEN_BOLD)COMMANDS:$(RESET)"
	@echo "  $(CYAN_BOLD)install-dev$(RESET)    - Install development dependencies"
	@echo "  $(CYAN_BOLD)test$(RESET)           - Run tests with coverage"
	@echo "  $(CYAN_BOLD)test-fast$(RESET)      - Run tests quickly without coverage"
	@echo "  $(CYAN_BOLD)lint$(RESET)           - Run ruff linter and fix automatically"
	@echo "  $(CYAN_BOLD)format$(RESET)         - Format code with ruff format"
	@echo "  $(CYAN_BOLD)format-check$(RESET)   - Check formatting without making changes"
	@echo "  $(CYAN_BOLD)type-check$(RESET)     - Run mypy type checking"
	@echo "  $(CYAN_BOLD)check-all$(RESET)      - Run all checks (lint, format-check, type-check, test)"
	@echo "  $(CYAN_BOLD)clear$(RESET)          - Clean up temporary files"
	@echo "  $(CYAN_BOLD)pre-commit$(RESET)     - Install pre-commit hooks"
	@echo ""

install-dev:
	uv pip install -e ".[dev]"

test:
	uv run pytest tests/ -v --cov=bindantic --cov-report=term-missing --cov-report=html

test-fast:
	uv run pytest tests/ -v

lint:
	uv run ruff check . --fix

format:
	uv run ruff format .

format-check:
	uv run ruff format --check .

type-check:
	uv run mypy bindantic/

check-all: format-check lint type-check test

clear:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type f -name ".coverage" -delete
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name "dist" -exec rm -rf {} +
	find . -type d -name "build" -exec rm -rf {} +

pre-commit:
	uv run pre-commit install