# EzzDay Backend Environment Configuration

This directory contains environment-specific configuration files for the EzzDay Backend.

## Environment Files

### `.env.dev` - Development Environment
- Used for local development
- Includes development tools and relaxed security policies
- Hot reload enabled
- Debug logging
- Local services (MailHog, console backends)

### `.env.test` - Test Environment
- Used for automated testing
- Fast execution with minimal dependencies
- Mock services and backends
- Relaxed policies for testing
- In-memory storage options

### `.env.staging` - Staging Environment
- Production-like environment for testing
- Real external services
- Production security policies
- Monitoring enabled
- Performance testing

### `.env.prod` - Production Environment
- Production configuration
- All values should be set via environment variables
- Strict security policies
- Full monitoring and logging
- High availability settings

## Usage

### With Docker Compose
```bash
# Development
docker-compose -f app/config/docker/docker-compose.yml up

# Test
docker-compose -f app/config/docker/docker-compose.test.yml up

# Staging
docker-compose -f app/config/docker/docker-compose.staging.yml up

# Production
docker-compose -f app/config/docker/docker-compose.prod.yml up
```

### Direct Usage
```bash
# Load environment file
export $(cat app/config/environments/.env.dev | xargs)

# Or use with python-dotenv
python -c "from dotenv import load_dotenv; load_dotenv('app/config/environments/.env.dev')"
```

## Security Notes

- **Never commit sensitive values to version control**
- Use environment variables or secrets management for production
- The `.env.prod` file uses placeholder variables that must be set externally
- Regularly rotate secrets and API keys

## Configuration Categories

Each environment file includes settings for:

- Application settings (name, version, debug mode)
- Security settings (secrets, CORS, authentication)
- Database configuration (connection strings, pool settings)
- Redis/Cache configuration
- Celery/Queue configuration
- Monitoring and logging
- Email and notification services
- File storage settings
- Rate limiting
- Security policies
- Feature flags
- External integrations

## Adding New Settings

When adding new configuration options:

1. Add to all environment files with appropriate values
2. Document the setting in this README
3. Update the corresponding configuration classes in `app/core/config.py`
4. Add validation if needed
5. Update Docker configurations if required