"""Test database configuration for EzzDay Backend."""

import os
from typing import Any

# Test database configuration
TEST_DB_CONFIG = {
    "default": {
        "host": "localhost",
        "port": 5432,
        "database": "ezzday_test",
        "username": "ezzday_test",
        "password": "test_password",
        "echo": False,
        "pool_size": 5,
        "max_overflow": 10,
    },
    "memory": {
        "url": "sqlite:///memory:",
        "echo": False,
    },
    "file": {
        "url": "sqlite:///./test_ezzday.db",
        "echo": False,
    },
}


def get_test_database_url(config_name: str = "memory") -> str:
    """Get test database URL based on configuration."""
    config = TEST_DB_CONFIG.get(config_name)

    if not config:
        raise ValueError(f"Unknown test database config: {config_name}")

    if "url" in config:
        return config["url"]

    # Build PostgreSQL URL
    return (
        f"postgresql+asyncpg://{config['username']}:{config['password']}"
        f"@{config['host']}:{config['port']}/{config['database']}"
    )


def get_test_redis_url() -> str:
    """Get test Redis URL."""
    return os.getenv("TEST_REDIS_URL", "redis://localhost:6379/10")


def get_test_environment_vars() -> dict[str, Any]:
    """Get test environment variables."""
    return {
        "ENVIRONMENT": "test",
        "DEBUG": "true",
        "LOG_LEVEL": "INFO",
        "DATABASE_URL": get_test_database_url("memory"),
        "REDIS_URL": get_test_redis_url(),
        "JWT_SECRET_KEY": "test-secret-key-for-testing-only",
        "JWT_ALGORITHM": "HS256",
        "JWT_ACCESS_TOKEN_EXPIRE_MINUTES": 30,
        "JWT_REFRESH_TOKEN_EXPIRE_DAYS": 7,
        "RATE_LIMIT_REQUESTS": 1000,
        "RATE_LIMIT_WINDOW": 60,
        "CELERY_BROKER_URL": get_test_redis_url(),
        "CELERY_RESULT_BACKEND": get_test_redis_url(),
    }
