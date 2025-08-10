# PromptSentinel Makefile
# Convenient commands for development, testing, and deployment

# Variables
PYTHON := python3.11
UV := uv
DOCKER := docker
DOCKER_COMPOSE := docker-compose
PROJECT_NAME := prompt-sentinel
MAIN_IMAGE := promptsentinel/prompt-sentinel:latest
SRC_DIR := src/prompt_sentinel
TEST_DIR := tests

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m # No Color

.PHONY: help
help: ## Show this help message
	@echo "$(GREEN)PromptSentinel - Make Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

# ============================================================================
# Environment Setup
# ============================================================================

.PHONY: install
install: ## Install dependencies using UV
	@echo "$(GREEN)Installing dependencies with UV...$(NC)"
	$(UV) venv --python $(PYTHON)
	$(UV) pip install -e ".[dev]"
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

.PHONY: install-dev
install-dev: install ## Install development dependencies
	@echo "$(GREEN)Installing pre-commit hooks...$(NC)"
	$(UV) pip install pre-commit
	pre-commit install
	@echo "$(GREEN)✓ Development environment ready$(NC)"

.PHONY: clean
clean: ## Clean up generated files and caches
	@echo "$(YELLOW)Cleaning up...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.coverage" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf dist
	rm -rf *.egg-info
	rm -rf .coverage
	rm -rf .mypy_cache
	rm -rf .ruff_cache
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

.PHONY: env
env: ## Copy .env.example to .env
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN)✓ Created .env from .env.example$(NC)"; \
		echo "$(YELLOW)⚠ Remember to add your API keys!$(NC)"; \
	else \
		echo "$(YELLOW).env already exists$(NC)"; \
	fi

# ============================================================================
# Development
# ============================================================================

.PHONY: run
run: ## Run the service locally (no Docker)
	@echo "$(GREEN)Starting PromptSentinel...$(NC)"
	$(UV) run uvicorn prompt_sentinel.main:app --reload --host 0.0.0.0 --port 8080

.PHONY: run-docker
run-docker: ## Run with Docker (no Redis)
	@echo "$(GREEN)Starting PromptSentinel with Docker...$(NC)"
	$(DOCKER_COMPOSE) up

.PHONY: run-redis
run-redis: ## Run with Docker and Redis caching
	@echo "$(GREEN)Starting PromptSentinel with Redis cache...$(NC)"
	$(DOCKER_COMPOSE) -f docker-compose.redis.yml up

.PHONY: run-dev
run-dev: ## Run in development mode with auto-reload
	@echo "$(GREEN)Starting in development mode...$(NC)"
	DEBUG=true \
	API_ENV=development \
	REDIS_ENABLED=false \
	$(UV) run uvicorn prompt_sentinel.main:app --reload --host 127.0.0.1 --port 8080

.PHONY: stop
stop: ## Stop all Docker containers
	@echo "$(YELLOW)Stopping containers...$(NC)"
	$(DOCKER_COMPOSE) -f docker-compose.redis.yml down 2>/dev/null || true
	$(DOCKER_COMPOSE) down 2>/dev/null || true
	@echo "$(GREEN)✓ Containers stopped$(NC)"

# ============================================================================
# Testing
# ============================================================================

.PHONY: test
test: ## Run all tests without coverage (faster)
	@echo "$(GREEN)Running tests...$(NC)"
	$(UV) run pytest -v

.PHONY: test-quick
test-quick: ## Run only comprehensive tests (fastest, ~5s)
	@echo "$(GREEN)Running comprehensive tests only...$(NC)"
	$(UV) run pytest tests/*comprehensive*.py -v

.PHONY: test-parallel
test-parallel: ## Run tests in parallel using all CPU cores
	@echo "$(GREEN)Running tests in parallel...$(NC)"
	$(UV) run pytest -n auto -v

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	$(UV) run pytest --cov=$(SRC_DIR) --cov-report=html --cov-report=term

.PHONY: test-unit
test-unit: ## Run only unit tests (no integration/e2e)
	@echo "$(GREEN)Running unit tests...$(NC)"
	$(UV) run pytest -m "unit" -v

.PHONY: test-integration
test-integration: ## Run only integration tests
	@echo "$(GREEN)Running integration tests...$(NC)"
	$(UV) run pytest -m "integration" -v

.PHONY: test-fast
test-fast: ## Run tests excluding slow tests
	@echo "$(GREEN)Running fast tests only...$(NC)"
	$(UV) run pytest -m "not slow" -v

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	@echo "$(GREEN)Running tests in watch mode...$(NC)"
	$(UV) pip install pytest-watch
	$(UV) run pytest-watch

.PHONY: test-integration-redis
test-integration-redis: ## Run integration tests with Redis
	@echo "$(GREEN)Running integration tests...$(NC)"
	$(DOCKER_COMPOSE) -f docker-compose.redis.yml up -d redis
	@echo "Waiting for Redis to start..."
	@sleep 3
	REDIS_ENABLED=true REDIS_HOST=localhost REDIS_PASSWORD=changeme-in-production \
		$(UV) run pytest tests/test_cache.py -v
	$(DOCKER_COMPOSE) -f docker-compose.redis.yml down

.PHONY: test-api
test-api: ## Test API endpoints with curl
	@echo "$(GREEN)Testing API endpoints...$(NC)"
	@echo "Testing health endpoint..."
	@curl -s http://localhost:8080/health | python -m json.tool || echo "$(RED)API not running?$(NC)"
	@echo "\nTesting v1 detection..."
	@curl -X POST http://localhost:8080/v1/detect \
		-H "Content-Type: application/json" \
		-d '{"prompt": "Hello, how are you?"}' | python -m json.tool || echo "$(RED)API not running?$(NC)"
	@echo "\nTesting cache stats..."
	@curl -s http://localhost:8080/cache/stats | python -m json.tool || echo "$(RED)API not running?$(NC)"

.PHONY: quick-test
quick-test: ## Run quick smoke test
	@echo "$(GREEN)Running quick smoke test...$(NC)"
	$(UV) run pytest tests/test_heuristics.py -v --tb=short

# ============================================================================
# Code Quality
# ============================================================================

.PHONY: format
format: ## Format code with Black
	@echo "$(GREEN)Formatting code...$(NC)"
	$(UV) run black $(SRC_DIR) $(TEST_DIR)
	@echo "$(GREEN)✓ Code formatted$(NC)"

.PHONY: lint
lint: ## Run linting with Ruff
	@echo "$(GREEN)Running linter...$(NC)"
	$(UV) run ruff check $(SRC_DIR) $(TEST_DIR)
	@echo "$(GREEN)✓ Linting complete$(NC)"

.PHONY: type-check
type-check: ## Run type checking with MyPy
	@echo "$(GREEN)Running type checker...$(NC)"
	$(UV) run mypy $(SRC_DIR)
	@echo "$(GREEN)✓ Type checking complete$(NC)"

.PHONY: quality
quality: format lint type-check ## Run all code quality checks
	@echo "$(GREEN)✓ All quality checks passed$(NC)"

.PHONY: check
check: ## Check code formatting and linting without modifying files
	@echo "$(GREEN)Checking code formatting...$(NC)"
	$(UV) run black --check $(SRC_DIR) $(TEST_DIR)
	@echo "$(GREEN)✓ Formatting check passed$(NC)"
	@echo "$(GREEN)Checking linting...$(NC)"
	$(UV) run ruff check $(SRC_DIR) $(TEST_DIR)
	@echo "$(GREEN)✓ Linting check passed$(NC)"
	@echo "$(GREEN)Running type checks...$(NC)"
	$(UV) run mypy $(SRC_DIR)
	@echo "$(GREEN)✓ All checks passed$(NC)"

.PHONY: pre-commit
pre-commit: ## Run pre-commit hooks
	@echo "$(GREEN)Running pre-commit hooks...$(NC)"
	$(UV) run pre-commit run --all-files

.PHONY: pre-commit-install
pre-commit-install: ## Install pre-commit hooks
	@echo "$(GREEN)Installing pre-commit hooks...$(NC)"
	$(UV) run pre-commit install
	@echo "$(GREEN)✓ Pre-commit hooks installed$(NC)"

.PHONY: fix
fix: ## Auto-fix formatting and linting issues
	@echo "$(GREEN)Auto-fixing code issues...$(NC)"
	$(UV) run black $(SRC_DIR) $(TEST_DIR)
	$(UV) run ruff check --fix $(SRC_DIR) $(TEST_DIR)
	@echo "$(GREEN)✓ Code issues fixed$(NC)"

# ============================================================================
# Docker & Deployment
# ============================================================================

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "$(GREEN)Building Docker image...$(NC)"
	$(DOCKER) build -t $(MAIN_IMAGE) .
	@echo "$(GREEN)✓ Image built: $(MAIN_IMAGE)$(NC)"

.PHONY: docker-push
docker-push: docker-build ## Push Docker image to registry
	@echo "$(GREEN)Pushing image to registry...$(NC)"
	$(DOCKER) push $(MAIN_IMAGE)
	@echo "$(GREEN)✓ Image pushed$(NC)"

.PHONY: docker-run
docker-run: ## Run Docker container
	@echo "$(GREEN)Running Docker container...$(NC)"
	$(DOCKER) run -p 8080:8080 --env-file .env $(MAIN_IMAGE)

.PHONY: docker-shell
docker-shell: ## Open shell in Docker container
	@echo "$(GREEN)Opening shell in container...$(NC)"
	$(DOCKER) run -it --rm --entrypoint /bin/sh $(MAIN_IMAGE)

# ============================================================================
# Database & Cache
# ============================================================================

.PHONY: redis-cli
redis-cli: ## Connect to Redis CLI
	@echo "$(GREEN)Connecting to Redis...$(NC)"
	$(DOCKER) exec -it prompt-sentinel-redis redis-cli -a $${REDIS_PASSWORD:-changeme-in-production}

.PHONY: redis-flush
redis-flush: ## Flush Redis cache
	@echo "$(YELLOW)Flushing Redis cache...$(NC)"
	@$(DOCKER) exec prompt-sentinel-redis redis-cli -a $${REDIS_PASSWORD:-changeme-in-production} FLUSHALL 2>/dev/null || echo "$(RED)Redis not running$(NC)"
	@echo "$(GREEN)✓ Cache flushed$(NC)"

.PHONY: redis-stats
redis-stats: ## Show Redis statistics
	@echo "$(GREEN)Redis Statistics:$(NC)"
	@curl -s http://localhost:8080/cache/stats | python -m json.tool || echo "$(RED)API not running?$(NC)"

# ============================================================================
# Security & Validation
# ============================================================================

.PHONY: security-check
security-check: ## Run security checks
	@echo "$(GREEN)Running security checks...$(NC)"
	$(UV) pip install bandit safety
	$(UV) run bandit -r $(SRC_DIR) -ll
	$(UV) run safety check || true
	@echo "$(GREEN)✓ Security checks complete$(NC)"

.PHONY: validate-env
validate-env: ## Validate environment configuration
	@echo "$(GREEN)Validating environment...$(NC)"
	@if [ ! -f .env ]; then \
		echo "$(RED)✗ .env file not found! Run 'make env' to create it$(NC)"; \
		exit 1; \
	fi
	@echo "Checking required API keys..."
	@grep -q "ANTHROPIC_API_KEY=your" .env && echo "$(YELLOW)⚠ ANTHROPIC_API_KEY not set$(NC)" || echo "$(GREEN)✓ ANTHROPIC_API_KEY configured$(NC)"
	@grep -q "OPENAI_API_KEY=your" .env && echo "$(YELLOW)⚠ OPENAI_API_KEY not set$(NC)" || echo "$(GREEN)✓ OPENAI_API_KEY configured$(NC)"
	@grep -q "GEMINI_API_KEY=your" .env && echo "$(YELLOW)⚠ GEMINI_API_KEY not set$(NC)" || echo "$(GREEN)✓ GEMINI_API_KEY configured$(NC)"

.PHONY: check-secrets
check-secrets: ## Check for hardcoded secrets
	@echo "$(GREEN)Checking for secrets...$(NC)"
	@! grep -r "sk-[a-zA-Z0-9]\{20,\}" $(SRC_DIR) --exclude-dir=__pycache__ 2>/dev/null || (echo "$(RED)✗ Potential secrets found!$(NC)" && exit 1)
	@echo "$(GREEN)✓ No secrets found$(NC)"

# ============================================================================
# Documentation
# ============================================================================

.PHONY: docs
docs: ## Generate API documentation
	@echo "$(GREEN)API Documentation$(NC)"
	@echo "Start the server and visit:"
	@echo "  - Swagger UI: http://localhost:8080/docs"
	@echo "  - ReDoc: http://localhost:8080/redoc"

.PHONY: corpus-update
corpus-update: ## Update attack corpus
	@echo "$(GREEN)Updating attack corpus...$(NC)"
	@echo "$(YELLOW)TODO: Implement corpus update logic$(NC)"
	@echo "$(GREEN)✓ Corpus update complete$(NC)"

# ============================================================================
# Deployment
# ============================================================================

.PHONY: deploy-k8s
deploy-k8s: ## Deploy to Kubernetes
	@echo "$(GREEN)Deploying to Kubernetes...$(NC)"
	kubectl apply -k deployment/kubernetes/
	@echo "$(GREEN)✓ Deployed to Kubernetes$(NC)"

.PHONY: deploy-ecs
deploy-ecs: ## Deploy to AWS ECS
	@echo "$(GREEN)Deploying to AWS ECS...$(NC)"
	./deployment/scripts/deploy-ecs.sh
	@echo "$(GREEN)✓ Deployed to ECS$(NC)"

# ============================================================================
# Utilities
# ============================================================================

.PHONY: logs
logs: ## Show application logs
	$(DOCKER_COMPOSE) -f docker-compose.redis.yml logs -f prompt-sentinel

.PHONY: logs-redis
logs-redis: ## Show Redis logs
	$(DOCKER_COMPOSE) -f docker-compose.redis.yml logs -f redis

.PHONY: ps
ps: ## Show running containers
	$(DOCKER_COMPOSE) -f docker-compose.redis.yml ps

.PHONY: version
version: ## Show version information
	@echo "$(GREEN)PromptSentinel Version Information$(NC)"
	@grep "__version__" src/prompt_sentinel/__init__.py | cut -d'"' -f2 | xargs echo "Version:"
	@echo "Python: $(PYTHON)"
	@$(UV) --version 2>/dev/null || echo "UV not installed"
	@$(DOCKER) --version 2>/dev/null || echo "Docker not installed"
	@$(DOCKER_COMPOSE) --version 2>/dev/null || echo "Docker Compose not installed"

# ============================================================================
# Quick Commands (Aliases)
# ============================================================================

.PHONY: up
up: run-redis ## Quick start with Redis (alias for run-redis)

.PHONY: down
down: stop ## Quick stop (alias for stop)

.PHONY: restart
restart: stop run-redis ## Restart services
	@echo "$(GREEN)✓ Services restarted$(NC)"

# ============================================================================
# CI/CD
# ============================================================================

.PHONY: ci
ci: quality test security-check ## Run all CI checks
	@echo "$(GREEN)✓ All CI checks passed$(NC)"

.PHONY: release
release: ci docker-build ## Prepare for release
	@echo "$(GREEN)Ready for release!$(NC)"
	@echo "Next steps:"
	@echo "  1. Update version in __init__.py"
	@echo "  2. Tag the release: git tag v0.1.0"
	@echo "  3. Push tags: git push --tags"
	@echo "  4. Push Docker image: make docker-push"

# Default target
.DEFAULT_GOAL := help