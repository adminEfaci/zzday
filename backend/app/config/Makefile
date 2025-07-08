.PHONY: help install dev-install format format-check lint lint-fix type-check test test-unit test-integration test-e2e coverage \
        clean run run-prod migrate migrate-wait rollback seed build docker-build docker-up docker-down docker-restart \
        docker-logs db-shell redis-cli generate-migration check-all ci init-project celery celery-beat \
        security-scan docs docs-serve validate-env backup restore logs health-check benchmark profile \
        load-test api-docs schema-check deps-audit container-scan secrets-check performance-test \
        stress-test smoke-test deploy-staging deploy-prod rollback-deployment monitoring-setup \
        validate-config generate-openapi export-env import-env version release git-hooks \
        analyze-code complexity-report security-audit compliance-check disaster-recovery

# --- Configuration ---
PYTHON := python3.11
UV := uv
APP_MODULE := app
TEST_PATH := tests
DOCKER_COMPOSE_FILE := docker/docker-compose.yml
ENV_FILE := .env
BACKUP_DIR := backups
LOGS_DIR := logs
DOCS_DIR := docs
REPORTS_DIR := reports

# Environment detection
ENV ?= development
ifeq ($(ENV),production)
    COMPOSE_FILE := docker/docker-compose.prod.yml
    GUNICORN_WORKERS := 8
else ifeq ($(ENV),staging)
    COMPOSE_FILE := docker/docker-compose.staging.yml
    GUNICORN_WORKERS := 4
else
    COMPOSE_FILE := $(DOCKER_COMPOSE_FILE)
    GUNICORN_WORKERS := 2
endif

# Version management
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# --- Helper functions ---

define load_env
	@if [ -f $(ENV_FILE) ]; then \
		echo "🔧 Loading environment variables from $(ENV_FILE)"; \
		set -a; . $(ENV_FILE); set +a; \
	else \
		echo "⚠️  No $(ENV_FILE) file found."; \
	fi
endef

define create_dir
	@mkdir -p $(1)
endef

define check_command
	@command -v $(1) >/dev/null 2>&1 || { echo "❌ $(1) is required but not installed. Aborting."; exit 1; }
endef

define success_msg
	@echo "✅ $(1)"
endef

define info_msg
	@echo "ℹ️  $(1)"
endef

define warning_msg
	@echo "⚠️  $(1)"
endef

define error_msg
	@echo "❌ $(1)"
endef

# --- Help ---

help: ## Show this help message with enhanced formatting
	@echo "🚀 EzzDay Backend - Development Makefile"
	@echo "========================================"
	@echo "Environment: $(ENV)"
	@echo "Version: $(VERSION)"
	@echo "Build: $(BUILD_DATE)"
	@echo ""
	@echo "📋 Available Commands:"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "; category=""} \
		/^# --- .* ---/ {category=substr($$0, 6, length($$0)-10); next} \
		/^[a-zA-Z_-]+:.*?## / { \
			if (category) {printf "\n🔹 %s:\n", category; category=""} \
			printf "  %-25s %s\n", $$1, $$2 \
		}' $(MAKEFILE_LIST)
	@echo ""
	@echo "💡 Usage: make [target] [ENV=environment]"
	@echo "   Examples:"
	@echo "     make run                    # Development mode"
	@echo "     make deploy ENV=staging     # Deploy to staging"
	@echo "     make check-all ENV=prod     # Production checks"

# --- Installation & Setup ---

install: ## Install production dependencies only
	$(call info_msg,"Installing production dependencies...")
	$(UV) sync --no-group dev --no-group test
	$(call success_msg,"Production dependencies installed")

dev-install: validate-env ## Install all dependencies including dev and setup pre-commit hooks
	$(call info_msg,"Installing development environment...")
	$(UV) sync
	$(UV) run pre-commit install
	$(UV) run pre-commit install --hook-type commit-msg
	$(call success_msg,"Development environment ready")

validate-env: ## Validate development environment and required tools
	$(call info_msg,"Validating development environment...")
	$(call check_command,python3.11)
	$(call check_command,uv)
	$(call check_command,docker)
	$(call check_command,docker-compose)
	$(call check_command,git)
	@$(PYTHON) -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11+ required'"
	$(call success_msg,"Environment validation passed")

# --- Code Quality & Security ---

format: ## Format code with black and isort (in-place)
	$(call info_msg,"Formatting codebase...")
	$(UV) run black $(APP_MODULE) $(TEST_PATH)
	$(UV) run isort $(APP_MODULE) $(TEST_PATH)
	$(call success_msg,"Code formatting completed")

format-check: ## Check code formatting (no changes)
	$(call info_msg,"Checking code formatting...")
	$(UV) run black --check $(APP_MODULE) $(TEST_PATH)
	$(UV) run isort --check-only $(APP_MODULE) $(TEST_PATH)

lint: ## Run comprehensive linting with ruff
	$(call info_msg,"Linting codebase...")
	$(UV) run ruff check $(APP_MODULE) $(TEST_PATH) --output-format=github

lint-fix: ## Auto-fix lint issues with ruff
	$(call info_msg,"Auto-fixing lint issues...")
	$(UV) run ruff check --fix $(APP_MODULE) $(TEST_PATH)

type-check: ## Run static type checking with mypy
	$(call info_msg,"Running type checks...")
	$(UV) run mypy $(APP_MODULE) --html-report $(REPORTS_DIR)/mypy

security-scan: ## Run security vulnerability scanning
	$(call create_dir,$(REPORTS_DIR))
	$(call info_msg,"Running security scans...")
	$(UV) run bandit -r $(APP_MODULE) -f json -o $(REPORTS_DIR)/bandit.json
	$(UV) run safety check --json --output $(REPORTS_DIR)/safety.json
	$(UV) run semgrep --config=auto $(APP_MODULE) --json --output=$(REPORTS_DIR)/semgrep.json
	$(call success_msg,"Security scan completed - reports in $(REPORTS_DIR)/")

deps-audit: ## Audit dependencies for security vulnerabilities
	$(call info_msg,"Auditing dependencies...")
	$(UV) pip list --format=json > $(REPORTS_DIR)/dependencies.json
	$(UV) run pip-audit --format=json --output=$(REPORTS_DIR)/pip-audit.json
	$(call success_msg,"Dependency audit completed")

secrets-check: ## Check for accidentally committed secrets
	$(call info_msg,"Scanning for secrets...")
	$(UV) run detect-secrets scan --all-files --baseline .secrets.baseline
	$(call success_msg,"Secrets scan completed")

# --- Testing & Quality Assurance ---

test: ## Run all tests (unit + integration) with coverage
	$(call info_msg,"Running all tests...")
	$(UV) run pytest -n auto --cov=$(APP_MODULE) --cov-report=xml:$(REPORTS_DIR)/coverage.xml

test-unit: ## Run only unit tests
	$(call info_msg,"Running unit tests...")
	$(UV) run pytest $(TEST_PATH)/unit -v --junitxml=$(REPORTS_DIR)/unit-tests.xml

test-integration: ## Run only integration tests
	$(call info_msg,"Running integration tests...")
	$(UV) run pytest $(TEST_PATH)/integration -v --junitxml=$(REPORTS_DIR)/integration-tests.xml

test-e2e: docker-up ## Run end-to-end tests against running services
	$(call info_msg,"Running E2E tests...")
	sleep 10  # Wait for services to be ready
	$(UV) run pytest $(TEST_PATH)/e2e -v --junitxml=$(REPORTS_DIR)/e2e-tests.xml

coverage: ## Generate comprehensive coverage reports
	$(call create_dir,$(REPORTS_DIR))
	$(call info_msg,"Generating coverage reports...")
	$(UV) run pytest --cov=$(APP_MODULE) \
		--cov-report=term \
		--cov-report=html:$(REPORTS_DIR)/coverage_html \
		--cov-report=xml:$(REPORTS_DIR)/coverage.xml \
		--cov-report=json:$(REPORTS_DIR)/coverage.json
	$(call success_msg,"Coverage reports generated in $(REPORTS_DIR)/")

smoke-test: ## Run smoke tests to verify basic functionality
	$(call info_msg,"Running smoke tests...")
	$(UV) run pytest $(TEST_PATH)/smoke -v --tb=short

performance-test: ## Run performance and load tests
	$(call info_msg,"Running performance tests...")
	$(UV) run pytest $(TEST_PATH)/performance -v --benchmark-json=$(REPORTS_DIR)/benchmark.json

# --- Database Operations ---

migrate: ## Run Alembic migrations to latest version
	$(call load_env)
	$(call info_msg,"Running database migrations...")
	$(UV) run alembic upgrade head
	$(call success_msg,"Migrations completed")

migrate-wait: ## Wait for DB and retry migrations (max 10 attempts)
	$(call load_env)
	$(call info_msg,"Waiting for DB and running migrations...")
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		$(UV) run alembic upgrade head && break || \
		(echo "Migration failed, retrying in 5 seconds... (attempt $$i/10)"; sleep 5); \
	done

rollback: ## Rollback last migration
	$(call load_env)
	$(call warning_msg,"Rolling back last migration...")
	$(UV) run alembic downgrade -1

generate-migration: ## Create new Alembic migration with autogenerated changes
	$(call load_env)
	@read -p "📝 Enter migration message: " msg; \
	$(UV) run alembic revision --autogenerate -m "$$msg"

seed: ## Seed database with initial data
	$(call load_env)
	$(call info_msg,"Seeding database...")
	$(UV) run python -m app.scripts.seed_database

backup: ## Create database backup with timestamp
	$(call create_dir,$(BACKUP_DIR))
	$(call load_env)
	$(call info_msg,"Creating database backup...")
	@TIMESTAMP=$$(date +%Y%m%d_%H%M%S); \
	docker-compose -f $(COMPOSE_FILE) exec -T postgres \
		pg_dump -U ezzday -d ezzday > $(BACKUP_DIR)/backup_$$TIMESTAMP.sql
	$(call success_msg,"Backup created in $(BACKUP_DIR)/")

restore: ## Restore database from latest backup
	$(call load_env)
	$(call warning_msg,"Restoring database from backup...")
	@LATEST=$$(ls -t $(BACKUP_DIR)/backup_*.sql 2>/dev/null | head -1); \
	if [ -z "$$LATEST" ]; then \
		echo "❌ No backup files found in $(BACKUP_DIR)/"; \
		exit 1; \
	fi; \
	echo "Restoring from: $$LATEST"; \
	docker-compose -f $(COMPOSE_FILE) exec -T postgres \
		psql -U ezzday -d ezzday < "$$LATEST"

# --- Application Lifecycle ---

run: validate-config ## Run FastAPI application locally with auto-reload
	$(call load_env)
	$(call info_msg,"Starting development server...")
	$(UV) run uvicorn $(APP_MODULE).main:app \
		--reload \
		--host 0.0.0.0 \
		--port 8000 \
		--log-level debug

run-prod: validate-config ## Run application in production mode
	$(call load_env)
	$(call info_msg,"Starting production server with $(GUNICORN_WORKERS) workers...")
	$(UV) run gunicorn $(APP_MODULE).main:app \
		-w $(GUNICORN_WORKERS) \
		-k uvicorn.workers.UvicornWorker \
		--bind 0.0.0.0:8000 \
		--access-logfile $(LOGS_DIR)/access.log \
		--error-logfile $(LOGS_DIR)/error.log \
		--log-level info \
		--timeout 120 \
		--keepalive 5

celery: ## Run Celery worker with monitoring
	$(call load_env)
	$(call create_dir,$(LOGS_DIR))
	$(call info_msg,"Starting Celery worker...")
	$(UV) run celery -A app.core.tasks.celery worker \
		--loglevel=info \
		--logfile=$(LOGS_DIR)/celery.log \
		--pidfile=$(LOGS_DIR)/celery.pid

celery-beat: ## Run Celery beat scheduler
	$(call load_env)
	$(call create_dir,$(LOGS_DIR))
	$(call info_msg,"Starting Celery beat...")
	$(UV) run celery -A app.core.tasks.celery beat \
		--loglevel=info \
		--logfile=$(LOGS_DIR)/celery-beat.log \
		--pidfile=$(LOGS_DIR)/celery-beat.pid

# --- Docker Operations ---

docker-build: ## Build Docker image with build args and caching
	$(call info_msg,"Building Docker image...")
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--cache-from ezzday-backend:latest \
		-t ezzday-backend:$(VERSION) \
		-t ezzday-backend:latest \
		-f docker/Dockerfile .
	$(call success_msg,"Docker image built: ezzday-backend:$(VERSION)")

docker-up: ## Start all Docker services with environment-specific compose
	$(call info_msg,"Starting Docker services for $(ENV) environment...")
	docker-compose -f $(COMPOSE_FILE) up -d
	$(call success_msg,"Services started - use 'make docker-logs' to monitor")

docker-down: ## Stop and remove all Docker services
	$(call info_msg,"Stopping Docker services...")
	docker-compose -f $(COMPOSE_FILE) down --remove-orphans

docker-restart: docker-down docker-up ## Restart all Docker services

docker-logs: ## Follow logs for all Docker services with timestamps
	docker-compose -f $(COMPOSE_FILE) logs -f --timestamps

container-scan: ## Scan Docker images for security vulnerabilities
	$(call info_msg,"Scanning container for vulnerabilities...")
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy image ezzday-backend:latest \
		--format json --output $(REPORTS_DIR)/container-scan.json

# --- Database/Redis Tools ---

db-shell: ## Open interactive Postgres shell
	docker-compose -f $(COMPOSE_FILE) exec postgres \
		psql -U ezzday -d ezzday

redis-cli: ## Open Redis CLI
	docker-compose -f $(COMPOSE_FILE) exec redis redis-cli

# --- Monitoring & Health ---

health-check: ## Check health of all services
	$(call info_msg,"Checking service health...")
	@echo "🔍 API Health:"
	@curl -f http://localhost:8000/health 2>/dev/null || echo "❌ API not responding"
	@echo "🔍 Database:"
	@docker-compose -f $(COMPOSE_FILE) exec postgres \
		pg_isready -U ezzday -d ezzday || echo "❌ Database not ready"
	@echo "🔍 Redis:"
	@docker-compose -f $(COMPOSE_FILE) exec redis \
		redis-cli ping || echo "❌ Redis not responding"

logs: ## Collect and analyze application logs
	$(call create_dir,$(LOGS_DIR))
	$(call info_msg,"Collecting logs...")
	docker-compose -f $(COMPOSE_FILE) logs --no-color > $(LOGS_DIR)/all-services.log
	$(call success_msg,"Logs collected in $(LOGS_DIR)/")

benchmark: ## Run application performance benchmarks
	$(call info_msg,"Running performance benchmarks...")
	$(UV) run python -m app.scripts.benchmark \
		--output $(REPORTS_DIR)/benchmark.json

profile: ## Profile application performance
	$(call info_msg,"Profiling application...")
	$(UV) run python -m cProfile -o $(REPORTS_DIR)/profile.stats \
		-m app.main

# --- Load Testing ---

load-test: ## Run load tests against the API
	$(call info_msg,"Running load tests...")
	$(UV) run locust -f tests/load/locustfile.py \
		--host=http://localhost:8000 \
		--users=100 \
		--spawn-rate=10 \
		--run-time=60s \
		--html=$(REPORTS_DIR)/load-test.html

stress-test: ## Run stress tests to find breaking points
	$(call info_msg,"Running stress tests...")
	$(UV) run locust -f tests/stress/stress_test.py \
		--host=http://localhost:8000 \
		--users=1000 \
		--spawn-rate=50 \
		--run-time=300s \
		--html=$(REPORTS_DIR)/stress-test.html

# --- Documentation ---

docs: ## Generate API documentation
	$(call create_dir,$(DOCS_DIR))
	$(call info_msg,"Generating documentation...")
	$(UV) run sphinx-build -b html docs/source $(DOCS_DIR)/html
	$(call success_msg,"Documentation generated in $(DOCS_DIR)/html/")

docs-serve: docs ## Serve documentation locally
	$(call info_msg,"Serving documentation at http://localhost:8080")
	$(UV) run python -m http.server 8080 -d $(DOCS_DIR)/html

api-docs: ## Generate OpenAPI documentation
	$(call load_env)
	$(call info_msg,"Generating OpenAPI documentation...")
	$(UV) run python -c "
import json
from app.main import app
with open('$(DOCS_DIR)/openapi.json', 'w') as f:
    json.dump(app.openapi(), f, indent=2)
"
	$(call success_msg,"OpenAPI spec generated in $(DOCS_DIR)/openapi.json")

generate-openapi: api-docs ## Alias for api-docs

# --- Code Analysis ---

analyze-code: ## Run comprehensive code analysis
	$(call create_dir,$(REPORTS_DIR))
	$(call info_msg,"Running code analysis...")
	$(UV) run radon cc $(APP_MODULE) --json > $(REPORTS_DIR)/complexity.json
	$(UV) run radon mi $(APP_MODULE) --json > $(REPORTS_DIR)/maintainability.json
	$(UV) run vulture $(APP_MODULE) --json > $(REPORTS_DIR)/dead-code.json
	$(call success_msg,"Code analysis completed")

complexity-report: ## Generate complexity report
	$(call info_msg,"Generating complexity report...")
	$(UV) run radon cc $(APP_MODULE) --show-complexity --min B

# --- Configuration & Validation ---

validate-config: ## Validate application configuration
	$(call load_env)
	$(call info_msg,"Validating configuration...")
	$(UV) run python -c "
from app.core.config import settings
print('✅ Configuration valid')
print(f'Environment: {settings.ENVIRONMENT}')
print(f'Debug: {settings.DEBUG}')
"

export-env: ## Export environment template
	$(call info_msg,"Exporting environment template...")
	@echo "# EzzDay Backend Environment Configuration" > .env.template
	@echo "# Generated on $(BUILD_DATE)" >> .env.template
	@echo "" >> .env.template
	@grep -E "^[A-Z_]+=" $(ENV_FILE) | sed 's/=.*/=/' >> .env.template || true
	$(call success_msg,"Environment template exported to .env.template")

import-env: ## Import environment from template
	@if [ ! -f .env.template ]; then \
		$(call error_msg,"No .env.template found"); \
		exit 1; \
	fi
	@cp .env.template $(ENV_FILE)
	$(call warning_msg,"Please edit $(ENV_FILE) with actual values")

# --- Deployment ---

deploy-staging: check-all docker-build ## Deploy to staging environment
	$(call info_msg,"Deploying to staging...")
	ENV=staging $(MAKE) docker-up migrate
	$(call success_msg,"Staging deployment completed")

deploy-prod: security-audit docker-build ## Deploy to production environment
	$(call warning_msg,"Deploying to production...")
	@read -p "⚠️  Are you sure you want to deploy to production? (y/N): " confirm; \
	if [ "$$confirm" != "y" ]; then exit 1; fi
	ENV=production $(MAKE) docker-up migrate
	$(call success_msg,"Production deployment completed")

rollback-deployment: ## Rollback to previous deployment
	$(call warning_msg,"Rolling back deployment...")
	docker-compose -f $(COMPOSE_FILE) pull
	$(MAKE) docker-restart
	$(MAKE) rollback

# --- Version Management ---

version: ## Show current version information
	@echo "📋 Version Information:"
	@echo "  Version: $(VERSION)"
	@echo "  Build Date: $(BUILD_DATE)"
	@echo "  Git Commit: $(GIT_COMMIT)"
	@echo "  Environment: $(ENV)"

release: ## Create a new release tag
	@read -p "📦 Enter release version (e.g., v1.2.3): " version; \
	git tag -a "$$version" -m "Release $$version"; \
	git push origin "$$version"
	$(call success_msg,"Release $$version created")

# --- Git Hooks ---

git-hooks: ## Setup enhanced git hooks
	$(call info_msg,"Setting up git hooks...")
	@echo '#!/bin/sh\nmake format lint type-check' > .git/hooks/pre-commit
	@echo '#!/bin/sh\nmake test-unit' > .git/hooks/pre-push
	@chmod +x .git/hooks/pre-commit .git/hooks/pre-push
	$(call success_msg,"Git hooks installed")

# --- Compliance & Auditing ---

security-audit: security-scan deps-audit secrets-check ## Run comprehensive security audit
	$(call info_msg,"Running comprehensive security audit...")
	$(call success_msg,"Security audit completed - check $(REPORTS_DIR)/ for reports")

compliance-check: ## Run compliance checks (GDPR, security standards)
	$(call info_msg,"Running compliance checks...")
	$(UV) run python -m app.scripts.compliance_check
	$(call success_msg,"Compliance check completed")

# --- Quality Gates ---

check-all: format-check lint type-check security-scan test coverage ## Run all quality checks
	$(call success_msg,"All quality checks passed! ✨")

ci: validate-env check-all ## Run full CI pipeline locally
	$(call success_msg,"CI pipeline completed successfully! 🚀")

schema-check: ## Validate database schema consistency
	$(call load_env)
	$(call info_msg,"Checking database schema...")
	$(UV) run alembic check
	$(call success_msg,"Schema validation passed")

# --- Disaster Recovery ---

disaster-recovery: ## Create complete backup for disaster recovery
	$(call create_dir,$(BACKUP_DIR)/disaster-recovery)
	$(call info_msg,"Creating disaster recovery backup...")
	$(MAKE) backup
	@cp -r $(LOGS_DIR) $(BACKUP_DIR)/disaster-recovery/ 2>/dev/null || true
	@cp $(ENV_FILE) $(BACKUP_DIR)/disaster-recovery/.env.backup 2>/dev/null || true
	@tar -czf $(BACKUP_DIR)/disaster-recovery-$(shell date +%Y%m%d_%H%M%S).tar.gz \
		$(BACKUP_DIR)/disaster-recovery/
	$(call success_msg,"Disaster recovery backup created")

# --- Cleanup ---

clean: ## Remove caches, artifacts, and temporary files
	$(call info_msg,"Cleaning project...")
	@find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "*.egg-info" -prune -exec rm -rf {} +
	@rm -rf .coverage htmlcov .pytest_cache .mypy_cache .ruff_cache
	@rm -rf $(REPORTS_DIR)/* $(LOGS_DIR)/*
	@docker system prune -f
	$(call success_msg,"Cleanup completed")

# --- Project Initialization ---

init-project: validate-env dev-install git-hooks docker-up migrate seed ## Initialize complete development environment
	$(call success_msg,"🎉 Project initialized! Use 'make run' to start development")

monitoring-setup: ## Setup monitoring and observability tools
	$(call info_msg,"Setting up monitoring...")
	docker-compose -f docker/docker-compose.monitoring.yml up -d
	$(call success_msg,"Monitoring stack available at http://localhost:3000 (Grafana)")

# --- Default Target ---

.DEFAULT_GOAL := help