#!/bin/bash
# EzzDay Backend - Health Check Script
# Comprehensive health check for Docker containers

set -e

# Configuration
HEALTH_CHECK_URL=${HEALTH_CHECK_URL:-"http://localhost:8000/health"}
READINESS_CHECK_URL=${READINESS_CHECK_URL:-"http://localhost:8000/ready"}
TIMEOUT=${HEALTH_CHECK_TIMEOUT:-10}
MAX_RETRIES=${HEALTH_CHECK_RETRIES:-3}
ENVIRONMENT=${ENVIRONMENT:-development}

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "[INFO] $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# HTTP health check
check_http_endpoint() {
    local url=$1
    local description=$2
    local expected_status=${3:-200}
    
    log_info "Checking ${description} at ${url}"
    
    if command_exists curl; then
        response=$(curl -s -o /dev/null -w "%{http_code}" --max-time ${TIMEOUT} ${url} 2>/dev/null || echo "000")
        
        if [ "${response}" = "${expected_status}" ]; then
            log_success "${description} is healthy (HTTP ${response})"
            return 0
        else
            log_error "${description} returned HTTP ${response}, expected ${expected_status}"
            return 1
        fi
    elif command_exists wget; then
        if wget --timeout=${TIMEOUT} --tries=1 -q --spider ${url} 2>/dev/null; then
            log_success "${description} is healthy"
            return 0
        else
            log_error "${description} check failed"
            return 1
        fi
    else
        log_warning "Neither curl nor wget available, skipping HTTP check for ${description}"
        return 0
    fi
}

# Database connectivity check
check_database() {
    if [ -z "${DATABASE_URL}" ]; then
        log_warning "DATABASE_URL not set, skipping database check"
        return 0
    fi
    
    log_info "Checking database connectivity"
    
    # Extract database connection details
    DB_HOST=$(echo ${DATABASE_URL} | sed -n 's/.*@\([^:]*\):.*/\1/p')
    DB_PORT=$(echo ${DATABASE_URL} | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
    
    if [ -n "${DB_HOST}" ] && [ -n "${DB_PORT}" ]; then
        if command_exists nc; then
            if timeout ${TIMEOUT} nc -z ${DB_HOST} ${DB_PORT}; then
                log_success "Database connectivity check passed"
                return 0
            else
                log_error "Cannot connect to database at ${DB_HOST}:${DB_PORT}"
                return 1
            fi
        else
            log_warning "netcat not available, skipping database connectivity check"
            return 0
        fi
    else
        log_warning "Could not parse database host/port from DATABASE_URL"
        return 0
    fi
}

# Redis connectivity check
check_redis() {
    if [ -z "${REDIS_URL}" ]; then
        log_warning "REDIS_URL not set, skipping Redis check"
        return 0
    fi
    
    log_info "Checking Redis connectivity"
    
    # Extract Redis connection details
    REDIS_HOST=$(echo ${REDIS_URL} | sed -n 's/redis:\/\/[^@]*@\?\([^:]*\):.*/\1/p')
    REDIS_PORT=$(echo ${REDIS_URL} | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
    
    if [ -n "${REDIS_HOST}" ] && [ -n "${REDIS_PORT}" ]; then
        if command_exists redis-cli; then
            if timeout ${TIMEOUT} redis-cli -h ${REDIS_HOST} -p ${REDIS_PORT} ping >/dev/null 2>&1; then
                log_success "Redis connectivity check passed"
                return 0
            else
                log_error "Cannot connect to Redis at ${REDIS_HOST}:${REDIS_PORT}"
                return 1
            fi
        elif command_exists nc; then
            if timeout ${TIMEOUT} nc -z ${REDIS_HOST} ${REDIS_PORT}; then
                log_success "Redis connectivity check passed (basic)"
                return 0
            else
                log_error "Cannot connect to Redis at ${REDIS_HOST}:${REDIS_PORT}"
                return 1
            fi
        else
            log_warning "Neither redis-cli nor netcat available, skipping Redis check"
            return 0
        fi
    else
        log_warning "Could not parse Redis host/port from REDIS_URL"
        return 0
    fi
}

# Memory usage check
check_memory() {
    if command_exists free; then
        local memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
        log_info "Memory usage: ${memory_usage}%"
        
        # Warning if memory usage > 90%
        if (( $(echo "${memory_usage} > 90" | bc -l) )); then
            log_warning "High memory usage detected: ${memory_usage}%"
            return 1
        else
            log_success "Memory usage is normal: ${memory_usage}%"
            return 0
        fi
    else
        log_warning "free command not available, skipping memory check"
        return 0
    fi
}

# Disk space check
check_disk_space() {
    if command_exists df; then
        local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
        log_info "Disk usage: ${disk_usage}%"
        
        # Warning if disk usage > 85%
        if [ "${disk_usage}" -gt 85 ]; then
            log_warning "High disk usage detected: ${disk_usage}%"
            return 1
        else
            log_success "Disk usage is normal: ${disk_usage}%"
            return 0
        fi
    else
        log_warning "df command not available, skipping disk space check"
        return 0
    fi
}

# Process check
check_process() {
    local process_name=${1:-"python"}
    
    if command_exists pgrep; then
        if pgrep -f "${process_name}" > /dev/null; then
            log_success "Process '${process_name}' is running"
            return 0
        else
            log_error "Process '${process_name}' is not running"
            return 1
        fi
    else
        log_warning "pgrep not available, skipping process check"
        return 0
    fi
}

# Main health check function
run_health_checks() {
    local failed_checks=0
    local total_checks=0
    
    log_info "Starting health checks for EzzDay Backend (Environment: ${ENVIRONMENT})"
    
    # Core application health check
    ((total_checks++))
    if ! check_http_endpoint "${HEALTH_CHECK_URL}" "Application Health Endpoint"; then
        ((failed_checks++))
    fi
    
    # Readiness check (if different from health)
    if [ "${READINESS_CHECK_URL}" != "${HEALTH_CHECK_URL}" ]; then
        ((total_checks++))
        if ! check_http_endpoint "${READINESS_CHECK_URL}" "Application Readiness Endpoint"; then
            ((failed_checks++))
        fi
    fi
    
    # Database connectivity
    ((total_checks++))
    if ! check_database; then
        ((failed_checks++))
    fi
    
    # Redis connectivity
    ((total_checks++))
    if ! check_redis; then
        ((failed_checks++))
    fi
    
    # System resource checks (non-critical in production)
    if [ "${ENVIRONMENT}" != "production" ]; then
        ((total_checks++))
        if ! check_memory; then
            log_warning "Memory check failed, but continuing in ${ENVIRONMENT} environment"
        fi
        
        ((total_checks++))
        if ! check_disk_space; then
            log_warning "Disk space check failed, but continuing in ${ENVIRONMENT} environment"
        fi
        
        ((total_checks++))
        if ! check_process; then
            ((failed_checks++))
        fi
    fi
    
    # Summary
    log_info "Health check summary: $((total_checks - failed_checks))/${total_checks} checks passed"
    
    if [ ${failed_checks} -eq 0 ]; then
        log_success "All health checks passed"
        return 0
    else
        log_error "${failed_checks} health check(s) failed"
        return 1
    fi
}

# Retry logic
main() {
    local attempt=1
    
    while [ ${attempt} -le ${MAX_RETRIES} ]; do
        if [ ${attempt} -gt 1 ]; then
            log_info "Health check attempt ${attempt}/${MAX_RETRIES}"
            sleep 2
        fi
        
        if run_health_checks; then
            exit 0
        fi
        
        ((attempt++))
    done
    
    log_error "Health check failed after ${MAX_RETRIES} attempts"
    exit 1
}

# Execute main function
main "$@"