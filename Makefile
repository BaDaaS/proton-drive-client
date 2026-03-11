.PHONY: help
help: ## Ask for help!
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; \
		{printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Install dependencies
	uv sync

.PHONY: check-format
check-format: ## Check code formatting
	uv run ruff format --check .

.PHONY: format
format: ## Format code
	uv run ruff format .

.PHONY: lint
lint: ## Run linter
	uv run ruff check .

.PHONY: lint-fix
lint-fix: ## Run linter with auto-fix
	uv run ruff check --fix .

.PHONY: typecheck
typecheck: ## Run type checker
	uv run mypy src/ tests/

.PHONY: test
test: ## Run tests
	uv run pytest -v

.PHONY: check
check: check-format lint typecheck test ## Run all checks
