#!/bin/bash
# EzzDay Backend - Docker Entrypoint Script
# Handles initialization and startup for production containers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check required environment variables
check_env_vars() {
    local required_vars=(
        "DATABASE_URL"
        "REDIS_URL"
        "SECRET_KEY"
        "JWT_SECRET_KEY"
    )
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            log_error "Required environment variable $var is not set"
            exit 1
        fi
    done
    
    log_info "All required environment variables are set"
}

# Wait for services to be ready
wait_for_services() {
    log_info "Waiting for dependent services..."
    
    # Wait for PostgreSQL
    if [ ! -z "$DATABASE_URL" ]; then
        log_info "Waiting for PostgreSQL..."
        python -c "
import os
import time
import psycopg2
from urllib.parse import urlparse

url = urlparse(os.environ['DATABASE_URL'])
max_retries = 30
retry_count = 0

while retry_count < max_retries:
    try:
        conn = psycopg2.connect(
            host=url.hostname,
            port=url.port or 5432,
            user=url.username,
            password=url.password,
            database=url.path[1:]
        )
        conn.close()
        print('PostgreSQL is ready!')
        break
    except Exception as e:
        retry_count += 1
        if retry_count >= max_retries:
            print(f'Failed to connect to PostgreSQL after {max_retries} attempts')
            exit(1)
        time.sleep(2)
"
    fi
    
    # Wait for Redis
    if [ ! -z "$REDIS_URL" ]; then
        log_info "Waiting for Redis..."
        python -c "
import os
import time
import redis
from urllib.parse import urlparse

url = os.environ['REDIS_URL']
max_retries = 30
retry_count = 0

while retry_count < max_retries:
    try:
        if url.startswith('redis-sentinel://'):
            # Handle Redis Sentinel
            from redis.sentinel import Sentinel
            parsed = urlparse(url)
            sentinel = Sentinel([(parsed.hostname, parsed.port or 26379)])
            master = sentinel.master_for(
                os.environ.get('REDIS_SENTINEL_SERVICE', 'mymaster'),
                socket_timeout=0.1,
                password=os.environ.get('REDIS_PASSWORD')
            )
            master.ping()
        else:
            # Handle standard Redis
            r = redis.from_url(url)
            r.ping()
        print('Redis is ready!')
        break
    except Exception as e:
        retry_count += 1
        if retry_count >= max_retries:
            print(f'Failed to connect to Redis after {max_retries} attempts')
            exit(1)
        time.sleep(2)
"
    fi
    
    log_info "All services are ready"
}

# Run database migrations
run_migrations() {
    if [ "$SKIP_MIGRATIONS" != "true" ]; then
        log_info "Running database migrations..."
        alembic upgrade head
        log_info "Database migrations completed"
    else
        log_warn "Skipping database migrations (SKIP_MIGRATIONS=true)"
    fi
}

# Initialize Prometheus metrics directory
init_prometheus() {
    if [ ! -z "$PROMETHEUS_MULTIPROC_DIR" ]; then
        log_info "Initializing Prometheus metrics directory..."
        mkdir -p "$PROMETHEUS_MULTIPROC_DIR"
        # Clean up any stale metrics files
        rm -f "$PROMETHEUS_MULTIPROC_DIR"/*.db
        log_info "Prometheus metrics directory initialized"
    fi
}

# Create required directories
create_directories() {
    log_info "Creating required directories..."
    mkdir -p /app/logs /app/storage /app/tmp
    
    # Ensure proper permissions (if running as root)
    if [ "$(id -u)" = "0" ]; then
        chown -R ezzday:ezzday /app/logs /app/storage /app/tmp
    fi
    
    log_info "Directories created"
}

# Set up signal handlers for graceful shutdown
setup_signal_handlers() {
    log_info "Setting up signal handlers..."
    
    # Handle SIGTERM for graceful shutdown
    trap 'log_info "Received SIGTERM, shutting down gracefully..."; kill -TERM $PID; wait $PID' TERM
    
    # Handle SIGINT (Ctrl+C)
    trap 'log_info "Received SIGINT, shutting down..."; kill -INT $PID; wait $PID' INT
}

# Main execution
main() {
    log_info "Starting EzzDay Backend..."
    log_info "Environment: ${ENVIRONMENT:-production}"
    log_info "Version: ${APP_VERSION:-unknown}"
    
    # Run initialization steps
    check_env_vars
    create_directories
    init_prometheus
    wait_for_services
    run_migrations
    setup_signal_handlers
    
    # Export worker class for Gunicorn
    export GUNICORN_WORKER_CLASS=${GUNICORN_WORKER_CLASS:-uvicorn.workers.UvicornWorker}
    
    # Start the application
    log_info "Starting application server..."
    
    # Execute the command passed to the container
    exec "$@" &
    PID=$!
    
    # Wait for the process to finish
    wait $PID
}

# Run main function
main "$@"