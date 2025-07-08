#!/bin/bash
# EzzDay Backend - Database Initialization Script
# Sets up initial database schema and data for different environments

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Environment configuration
ENVIRONMENT=${ENVIRONMENT:-development}
POSTGRES_USER=${POSTGRES_USER:-postgres}
POSTGRES_DB=${POSTGRES_DB:-ezzday}

log_info "Initializing EzzDay database for ${ENVIRONMENT} environment"

# Create additional databases if needed
create_databases() {
    log_info "Creating additional databases"
    
    # Create test database if in development
    if [ "${ENVIRONMENT}" = "development" ]; then
        log_info "Creating test database"
        psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
            SELECT 'CREATE DATABASE ezzday_test'
            WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ezzday_test');
EOSQL
        log_success "Test database created or already exists"
    fi
    
    # Create additional schemas
    log_info "Creating schemas"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        -- Identity schema
        CREATE SCHEMA IF NOT EXISTS identity;
        
        -- Audit schema
        CREATE SCHEMA IF NOT EXISTS audit;
        
        -- Integration schema
        CREATE SCHEMA IF NOT EXISTS integration;
        
        -- Notification schema
        CREATE SCHEMA IF NOT EXISTS notification;
        
        -- Analytics schema
        CREATE SCHEMA IF NOT EXISTS analytics;
EOSQL
    log_success "Database schemas created"
}

# Create database extensions
create_extensions() {
    log_info "Creating database extensions"
    
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        -- UUID extension for UUID generation
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
        
        -- pgcrypto for encryption functions
        CREATE EXTENSION IF NOT EXISTS "pgcrypto";
        
        -- btree_gin for improved indexing
        CREATE EXTENSION IF NOT EXISTS "btree_gin";
        
        -- Full text search
        CREATE EXTENSION IF NOT EXISTS "pg_trgm";
        
        -- PostGIS if needed for geolocation
        -- CREATE EXTENSION IF NOT EXISTS "postgis";
        
        -- JSON aggregation functions
        CREATE EXTENSION IF NOT EXISTS "hstore";
EOSQL
    log_success "Database extensions created"
}

# Create database users and permissions
create_users_and_permissions() {
    log_info "Creating database users and setting permissions"
    
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        -- Create application user if not exists
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ezzday_app') THEN
                CREATE ROLE ezzday_app WITH LOGIN PASSWORD 'app_secure_password';
            END IF;
        END
        \$\$;
        
        -- Create read-only user for analytics
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ezzday_readonly') THEN
                CREATE ROLE ezzday_readonly WITH LOGIN PASSWORD 'readonly_password';
            END IF;
        END
        \$\$;
        
        -- Grant permissions to application user
        GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO ezzday_app;
        GRANT USAGE ON ALL SCHEMAS IN DATABASE ${POSTGRES_DB} TO ezzday_app;
        GRANT CREATE ON SCHEMA public TO ezzday_app;
        GRANT ALL PRIVILEGES ON SCHEMA identity TO ezzday_app;
        GRANT ALL PRIVILEGES ON SCHEMA audit TO ezzday_app;
        GRANT ALL PRIVILEGES ON SCHEMA integration TO ezzday_app;
        GRANT ALL PRIVILEGES ON SCHEMA notification TO ezzday_app;
        GRANT ALL PRIVILEGES ON SCHEMA analytics TO ezzday_app;
        
        -- Grant permissions to readonly user
        GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO ezzday_readonly;
        GRANT USAGE ON ALL SCHEMAS IN DATABASE ${POSTGRES_DB} TO ezzday_readonly;
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO ezzday_readonly;
        GRANT SELECT ON ALL TABLES IN SCHEMA identity TO ezzday_readonly;
        GRANT SELECT ON ALL TABLES IN SCHEMA audit TO ezzday_readonly;
        GRANT SELECT ON ALL TABLES IN SCHEMA integration TO ezzday_readonly;
        GRANT SELECT ON ALL TABLES IN SCHEMA notification TO ezzday_readonly;
        GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO ezzday_readonly;
        
        -- Set default privileges for future tables
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO ezzday_readonly;
        ALTER DEFAULT PRIVILEGES IN SCHEMA identity GRANT SELECT ON TABLES TO ezzday_readonly;
        ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT SELECT ON TABLES TO ezzday_readonly;
        ALTER DEFAULT PRIVILEGES IN SCHEMA integration GRANT SELECT ON TABLES TO ezzday_readonly;
        ALTER DEFAULT PRIVILEGES IN SCHEMA notification GRANT SELECT ON TABLES TO ezzday_readonly;
        ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT SELECT ON TABLES TO ezzday_readonly;
EOSQL
    log_success "Database users and permissions configured"
}

# Create status tracking table
create_status_tracking() {
    log_info "Creating database status tracking"
    
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
        -- Create table to track database initialization status
        CREATE TABLE IF NOT EXISTS public.db_init_status (
            id SERIAL PRIMARY KEY,
            environment VARCHAR(50) UNIQUE NOT NULL,
            status VARCHAR(50) NOT NULL DEFAULT 'initializing',
            initialized_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            version VARCHAR(20),
            metadata JSONB
        );
        
        -- Insert initial status
        INSERT INTO public.db_init_status (environment, status, version)
        VALUES ('${ENVIRONMENT}', 'initialized', '1.0.0')
        ON CONFLICT (environment) DO UPDATE SET
            status = 'initialized',
            initialized_at = NOW(),
            version = '1.0.0';
EOSQL
    log_success "Database status tracking created"
}

# Main execution function
main() {
    log_info "Starting database initialization"
    
    # Run initialization steps
    create_extensions
    create_databases
    create_users_and_permissions
    create_status_tracking
    
    log_success "Database initialization completed successfully"
    log_info "Database is ready for application startup"
}

# Execute main function
main "$@"