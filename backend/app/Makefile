# EzzDay Backend - Makefile
# Development and deployment automation

.PHONY: help install dev-setup test lint format clean build docker-build docker-push deploy

# Default target
help:
	@echo "EzzDay Backend - Available Commands:"
	@echo "  install       Install dependencies"
	@echo "  dev-setup     Setup development environment"
	@echo "  test          Run all tests"
	@echo "  test-unit     Run unit tests only"
	@echo "  test-integration  Run integration tests"
	@echo "  lint          Run linting and formatting checks"
	@echo "  format        Auto-format code"
	@echo "  security      Run security scans"
	@echo "  clean         Clean build artifacts"
	@echo "  build         Build production image"
	@echo "  dev           Start development environment"
	@echo "  dev-down      Stop development environment"
	@echo "  prod          Start production environment"
	@echo "  backup        Run database backup"
	@echo "  migrate       Run database migrations"
	@echo "  seed          Seed development data"
	@echo "  logs          Show application logs"
	@echo "  shell         Enter application shell"
	@echo "  psql          Connect to database"
	@echo "  redis-cli     Connect to Redis"
	@echo "  dagger-ci     Run CI pipeline with Dagger"
	@echo "  dagger-cd     Run CD pipeline with Dagger"

# Installation and setup
install:
	@echo "Installing dependencies..."
	pip install uv
	uv pip install -r app/config/requirements/dev.txt

dev-setup: install
	@echo "Setting up development environment..."
	cp app/config/.env.example app/config/.env.dev
	pre-commit install
	docker-compose up -d db redis rabbitmq
	sleep 10
	make migrate
	make seed

# Testing
test:
	@echo "Running all tests..."
	docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit

test-unit:
	@echo "Running unit tests..."
	pytest app/tests/unit/ -v --cov=app --cov-report=term-missing

test-integration:
	@echo "Running integration tests..."
	pytest app/tests/integration/ -v

test-e2e:
	@echo "Running E2E tests..."
	pytest app/tests/e2e/ -v

test-performance:
	@echo "Running performance tests..."
	docker-compose -f docker-compose.test.yml --profile performance up --build

# Code quality
lint:
	@echo "Running linting checks..."
	black --check app/
	isort --check-only app/
	flake8 app/
	mypy app/
	bandit -r app/ -x app/tests/

format:
	@echo "Auto-formatting code..."
	black app/
	isort app/

security:
	@echo "Running security scans..."
	safety check
	bandit -r app/ -x app/tests/ -f json -o reports/bandit-report.json

# Build and deployment
clean:
	@echo "Cleaning build artifacts..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/ .coverage htmlcov/ .pytest_cache/

build:
	@echo "Building production image..."
	docker build -t ezzday/backend:latest -f Dockerfile .

build-dev:
	@echo "Building development image..."
	docker build -t ezzday/backend:dev -f Dockerfile.dev .

# Docker Compose operations
dev:
	@echo "Starting development environment..."
	docker-compose up --build

dev-detached:
	@echo "Starting development environment (detached)..."
	docker-compose up -d --build

dev-down:
	@echo "Stopping development environment..."
	docker-compose down

dev-clean:
	@echo "Cleaning development environment..."
	docker-compose down -v --rmi all

prod:
	@echo "Starting production environment..."
	docker-compose -f docker-compose.prod.yml up -d --build

prod-down:
	@echo "Stopping production environment..."
	docker-compose -f docker-compose.prod.yml down

# Database operations
migrate:
	@echo "Running database migrations..."
	docker-compose exec app alembic upgrade head

migrate-create:
	@echo "Creating new migration..."
	@read -p "Migration message: " msg; \
	docker-compose exec app alembic revision --autogenerate -m "$$msg"

migrate-downgrade:
	@echo "Downgrading database..."
	docker-compose exec app alembic downgrade -1

seed:
	@echo "Seeding development data..."
	docker-compose exec app python scripts/seed_data.py

backup:
	@echo "Running database backup..."
	./scripts/backup.sh

# Utility commands
logs:
	@echo "Showing application logs..."
	docker-compose logs -f app

logs-db:
	@echo "Showing database logs..."
	docker-compose logs -f db

logs-redis:
	@echo "Showing Redis logs..."
	docker-compose logs -f redis

shell:
	@echo "Entering application shell..."
	docker-compose exec app python -c "import IPython; IPython.start_ipython()"

shell-bash:
	@echo "Entering bash shell..."
	docker-compose exec app bash

psql:
	@echo "Connecting to database..."
	docker-compose exec db psql -U ezzday_dev -d ezzday_dev

redis-cli:
	@echo "Connecting to Redis..."
	docker-compose exec redis redis-cli

# Monitoring
stats:
	@echo "Showing container stats..."
	docker stats

health:
	@echo "Checking service health..."
	docker-compose ps
	curl -f http://localhost:8000/health || echo "App health check failed"
	curl -f http://localhost:15672 || echo "RabbitMQ management not accessible"

# Dagger CI/CD
dagger-ci:
	@echo "Running Dagger CI pipeline..."
	cd dagger && python main.py --mode ci

dagger-cd-staging:
	@echo "Running Dagger CD pipeline for staging..."
	cd dagger && python main.py --mode cd --environment staging --tag $(shell git rev-parse --short HEAD)

dagger-cd-prod:
	@echo "Running Dagger CD pipeline for production..."
	cd dagger && python main.py --mode cd --environment production --tag $(shell git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD)

# Git hooks
pre-commit:
	@echo "Running pre-commit hooks..."
	pre-commit run --all-files

# Documentation
docs:
	@echo "Generating API documentation..."
	docker-compose exec app python -c "from app.core.api_docs import generate_docs; generate_docs()"

docs-serve:
	@echo "Serving documentation..."
	cd docs && python -m http.server 8080

# Release management
tag:
	@echo "Creating new tag..."
	@read -p "Tag version (e.g., v1.0.0): " version; \
	git tag -a $$version -m "Release $$version"; \
	git push origin $$version

release: tag dagger-cd-prod
	@echo "Release completed!"

# Environment variables
env-example:
	@echo "Copying environment example..."
	cp app/config/.env.example app/config/.env.dev

env-check:
	@echo "Checking environment configuration..."
	docker-compose config

# Load testing
load-test:
	@echo "Running load tests..."
	docker run --rm -i grafana/k6:latest run - <tests/performance/load-test.js

# Security testing
security-test:
	@echo "Running security tests..."
	docker-compose -f docker-compose.test.yml --profile security up --build

# Monitoring and alerting
prometheus:
	@echo "Opening Prometheus..."
	open http://localhost:9090

grafana:
	@echo "Opening Grafana..."
	open http://localhost:3000

jaeger:
	@echo "Opening Jaeger..."
	open http://localhost:16686

flower:
	@echo "Opening Flower (Celery monitoring)..."
	open http://localhost:5555

mailhog:
	@echo "Opening MailHog..."
	open http://localhost:8025

rabbitmq:
	@echo "Opening RabbitMQ Management..."
	open http://localhost:15672