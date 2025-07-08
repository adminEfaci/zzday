#!/bin/bash
# EzzDay Backend - Container Entrypoint Script
# Handles container initialization, database migrations, and service startup

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
ENVIRONMENT=${ENVIRONMENT:-development}
APP_DIR=${APP_DIR:-/app}
PYTHONPATH=${APP_DIR}

# Change to app directory
cd ${APP_DIR}

log_info "Starting EzzDay Backend (Environment: ${ENVIRONMENT})"

# Environment-specific setup
case ${ENVIRONMENT} in
    "production")
        log_info "Production environment detected"
        ;;
    "staging")
        log_info "Staging environment detected"
        ;;
    "development")
        log_info "Development environment detected"
        ;;
    "test")
        log_info "Test environment detected"
        ;;
    *)
        log_warning "Unknown environment: ${ENVIRONMENT}"
        ;;
esac

# Health check function
check_service() {
    local service_name=$1
    local host=$2
    local port=$3
    local timeout=${4:-30}
    
    log_info "Checking ${service_name} connectivity at ${host}:${port}"
    
    if command -v nc >/dev/null 2>&1; then
        if timeout ${timeout} nc -z ${host} ${port}; then
            log_success "${service_name} is available"
            return 0
        else
            log_error "${service_name} is not available at ${host}:${port}"
            return 1
        fi
    else
        log_warning "netcat not available, skipping ${service_name} check"
        return 0
    fi
}

# Wait for database
if [ -n "${DATABASE_URL}" ]; then
    DB_HOST=$(echo ${DATABASE_URL} | sed -n 's/.*@\([^:]*\):.*/\1/p')
    DB_PORT=$(echo ${DATABASE_URL} | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
    
    if [ -n "${DB_HOST}" ] && [ -n "${DB_PORT}" ]; then
        check_service "PostgreSQL Database" ${DB_HOST} ${DB_PORT} 60
    fi
fi

# Wait for Redis
if [ -n "${REDIS_URL}" ]; then
    REDIS_HOST=$(echo ${REDIS_URL} | sed -n 's/redis:\/\/[^@]*@\?\([^:]*\):.*/\1/p')
    REDIS_PORT=$(echo ${REDIS_URL} | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
    
    if [ -n "${REDIS_HOST}" ] && [ -n "${REDIS_PORT}" ]; then
        check_service "Redis" ${REDIS_HOST} ${REDIS_PORT} 30
    fi
fi

# Database operations
run_database_operations() {
    if [ "${ENVIRONMENT}" != "test" ]; then
        log_info "Running database migrations"
        
        # Check if alembic is available
        if python -c "import alembic" 2>/dev/null; then
            # Run migrations
            if alembic upgrade head; then
                log_success "Database migrations completed"
            else
                log_error "Database migration failed"
                exit 1
            fi
        else
            log_warning "Alembic not available, skipping migrations"
        fi
        
        # Run database seeding for development
        if [ "${ENVIRONMENT}" = "development" ]; then
            log_info "Seeding development data"
            if [ -f "${APP_DIR}/scripts/seed_data.py" ]; then
                python ${APP_DIR}/scripts/seed_data.py || log_warning "Data seeding failed"
            fi
        fi
    fi
}

# Application startup
start_application() {
    log_info "Starting application with command: $@"
    
    # Set PYTHONPATH
    export PYTHONPATH=${APP_DIR}:${PYTHONPATH}
    
    # Execute the command
    exec "$@"
}

# Pre-flight checks
pre_flight_checks() {
    log_info "Running pre-flight checks"
    
    # Check Python version
    python_version=$(python --version 2>&1)
    log_info "Python version: ${python_version}"
    
    # Check required environment variables
    required_vars=("DATABASE_URL" "SECRET_KEY")
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            log_error "Required environment variable ${var} is not set"
            exit 1
        fi
    done
    
    # Check file permissions
    if [ ! -w "${APP_DIR}/logs" ]; then
        log_warning "Logs directory is not writable, creating it"
        mkdir -p "${APP_DIR}/logs" || log_error "Cannot create logs directory"
    fi
    
    if [ ! -w "${APP_DIR}/storage" ]; then
        log_warning "Storage directory is not writable, creating it"
        mkdir -p "${APP_DIR}/storage" || log_error "Cannot create storage directory"
    fi
    
    log_success "Pre-flight checks completed"
}

# Signal handlers
cleanup() {
    log_info "Received termination signal, shutting down gracefully"
    
    # Kill child processes
    jobs -p | xargs -r kill
    
    # Wait for processes to terminate
    sleep 2
    
    log_success "Shutdown completed"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Main execution flow
main() {
    log_info "EzzDay Backend Entrypoint Script v1.0"
    
    # Run pre-flight checks
    pre_flight_checks
    
    # Handle database operations (skip for worker processes)
    if [[ "$*" == *"uvicorn"* ]] || [[ "$*" == *"gunicorn"* ]]; then
        run_database_operations
    fi
    
    # Start the application
    start_application "$@"
}

# Execute main function with all arguments
main "$@"