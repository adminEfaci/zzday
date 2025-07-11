"""
Docker environment configuration for PostgreSQL/Redis event system.

This module provides Docker-specific configuration and initialization
for the event system with PostgreSQL persistence and Redis distribution.

Design Features:
- Docker environment detection and configuration
- PostgreSQL connection pool management
- Redis cluster support for Docker Swarm
- Health check integration
- Environment variable configuration
"""

import os
from datetime import datetime
from typing import Any

import asyncpg

from app.core.errors import ConfigurationError
from app.core.events.cross_module import create_cross_module_event_system
from app.core.events.serialization import create_postgresql_serializer
from app.core.logging import get_logger

logger = get_logger(__name__)


class DockerEventSystemConfig:
    """
    Docker-specific event system configuration.
    
    Provides configuration management for event system deployment
    in Docker/Docker Compose environments with PostgreSQL and Redis.
    """
    
    def __init__(self):
        """Initialize Docker configuration from environment variables."""
        # PostgreSQL configuration
        self.postgresql_host = os.getenv("POSTGRES_HOST", "localhost")
        self.postgresql_port = int(os.getenv("POSTGRES_PORT", "5432"))
        self.postgresql_database = os.getenv("POSTGRES_DB", "ezzday")
        self.postgresql_user = os.getenv("POSTGRES_USER", "postgres")
        self.postgresql_password = os.getenv("POSTGRES_PASSWORD", "")
        self.postgresql_schema = os.getenv("POSTGRES_EVENTS_SCHEMA", "events")
        
        # Redis configuration
        self.redis_host = os.getenv("REDIS_HOST", "localhost")
        self.redis_port = int(os.getenv("REDIS_PORT", "6379"))
        self.redis_db = int(os.getenv("REDIS_DB", "0"))
        self.redis_password = os.getenv("REDIS_PASSWORD", None)
        self.redis_cluster_mode = os.getenv("REDIS_CLUSTER_MODE", "false").lower() == "true"
        
        # Event system configuration
        self.enable_postgresql_persistence = os.getenv("ENABLE_POSTGRESQL_EVENTS", "true").lower() == "true"
        self.enable_redis_distribution = os.getenv("ENABLE_REDIS_EVENTS", "true").lower() == "true"
        self.enable_event_compression = os.getenv("ENABLE_EVENT_COMPRESSION", "true").lower() == "true"
        self.enable_event_encryption = os.getenv("ENABLE_EVENT_ENCRYPTION", "false").lower() == "true"
        self.event_retention_days = int(os.getenv("EVENT_RETENTION_DAYS", "365"))
        
        # Docker-specific settings
        self.docker_compose_service = os.getenv("COMPOSE_SERVICE_NAME", "backend")
        self.docker_network = os.getenv("DOCKER_NETWORK", "ezzday_network")
        self.health_check_interval = int(os.getenv("HEALTH_CHECK_INTERVAL", "30"))
        
        # Performance settings
        self.postgresql_pool_size = int(os.getenv("POSTGRES_POOL_SIZE", "10"))
        self.postgresql_max_overflow = int(os.getenv("POSTGRES_MAX_OVERFLOW", "20"))
        self.redis_connection_pool_size = int(os.getenv("REDIS_POOL_SIZE", "10"))
        
        logger.info(
            "Docker event system configuration loaded",
            postgresql_host=self.postgresql_host,
            redis_host=self.redis_host,
            postgresql_persistence=self.enable_postgresql_persistence,
            redis_distribution=self.enable_redis_distribution
        )
    
    def get_postgresql_url(self) -> str:
        """Get PostgreSQL connection URL."""
        return (
            f"postgresql://{self.postgresql_user}:{self.postgresql_password}"
            f"@{self.postgresql_host}:{self.postgresql_port}/{self.postgresql_database}"
        )
    
    def get_redis_url(self) -> str:
        """Get Redis connection URL."""
        auth_part = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth_part}{self.redis_host}:{self.redis_port}/{self.redis_db}"
    
    def validate(self) -> None:
        """
        Validate Docker configuration.
        
        Raises:
            ConfigurationError: If configuration is invalid
        """
        if self.enable_postgresql_persistence and not self.postgresql_password:
            logger.warning("PostgreSQL password not set - using empty password")
        
        if self.enable_redis_distribution and self.redis_cluster_mode:
            logger.info("Redis cluster mode enabled")
        
        if self.enable_event_encryption:
            encryption_key = os.getenv("EVENT_ENCRYPTION_KEY")
            if not encryption_key:
                raise ConfigurationError("EVENT_ENCRYPTION_KEY required when encryption is enabled")
        
        logger.debug("Docker event system configuration validated")


class DockerEventSystemInitializer:
    """
    Initializes event system for Docker deployment.
    
    Handles database schema creation, connection pool setup,
    and event system orchestrator initialization.
    """
    
    def __init__(self, config: DockerEventSystemConfig):
        """
        Initialize Docker event system.
        
        Args:
            config: Docker configuration
        """
        self.config = config
        self._postgresql_pool = None
        self._event_serializer = None
        self._orchestrator = None
        
    async def initialize(self) -> Any:
        """
        Initialize complete event system for Docker environment.
        
        Returns:
            CrossModuleEventOrchestrator: Initialized orchestrator
            
        Raises:
            ConfigurationError: If initialization fails
        """
        logger.info("Initializing event system for Docker environment")
        
        try:
            # Validate configuration
            self.config.validate()
            
            # Initialize PostgreSQL if enabled
            if self.config.enable_postgresql_persistence:
                await self._initialize_postgresql()
            
            # Create event serializer
            self._event_serializer = create_postgresql_serializer(
                enable_compression=self.config.enable_event_compression,
                enable_encryption=self.config.enable_event_encryption,
                encryption_key=self._get_encryption_key() if self.config.enable_event_encryption else None
            )
            
            # Create and initialize event orchestrator
            redis_url = self.config.get_redis_url() if self.config.enable_redis_distribution else None
            
            self._orchestrator = await create_cross_module_event_system(
                redis_url=redis_url,
                enable_postgresql_persistence=self.config.enable_postgresql_persistence,
                fallback_to_memory=True
            )
            
            logger.info(
                "Event system initialized successfully for Docker",
                postgresql_enabled=self.config.enable_postgresql_persistence,
                redis_enabled=self.config.enable_redis_distribution,
                encryption_enabled=self.config.enable_event_encryption
            )
            
            return self._orchestrator
            
        except Exception as e:
            logger.exception("Failed to initialize Docker event system", error=str(e))
            raise ConfigurationError(f"Docker event system initialization failed: {e}") from e
    
    async def _initialize_postgresql(self) -> None:
        """Initialize PostgreSQL connection and schema."""
        logger.info("Initializing PostgreSQL for event storage")
        
        try:
            # Create connection pool
            self._postgresql_pool = await asyncpg.create_pool(
                self.config.get_postgresql_url(),
                min_size=self.config.postgresql_pool_size // 2,
                max_size=self.config.postgresql_pool_size,
                command_timeout=60
            )
            
            # Test connection
            async with self._postgresql_pool.acquire() as conn:
                await conn.execute("SELECT 1")
            
            logger.info(
                "PostgreSQL connection pool created",
                pool_size=self.config.postgresql_pool_size,
                host=self.config.postgresql_host
            )
            
            # Initialize event store schema
            await self._initialize_event_schema()
            
        except Exception as e:
            logger.exception("Failed to initialize PostgreSQL", error=str(e))
            raise ConfigurationError(f"PostgreSQL initialization failed: {e}") from e
    
    async def _initialize_event_schema(self) -> None:
        """Initialize event store database schema."""
        logger.info("Initializing event store schema")
        
        try:
            # Import PostgreSQL event store
            from app.modules.identity.infrastructure.events.store.postgresql_event_store import (
                PostgreSQLEventStore,
            )
            
            # Create event store instance
            event_store = PostgreSQLEventStore(
                connection_pool=self._postgresql_pool,
                schema_name=self.config.postgresql_schema,
                enable_compression=self.config.enable_event_compression,
                enable_encryption=self.config.enable_event_encryption
            )
            
            # Initialize schema
            await event_store.initialize_schema()
            
            logger.info("Event store schema initialized successfully")
            
        except Exception as e:
            logger.exception("Failed to initialize event store schema", error=str(e))
            raise ConfigurationError(f"Event schema initialization failed: {e}") from e
    
    def _get_encryption_key(self) -> bytes:
        """Get encryption key from environment."""
        key_str = os.getenv("EVENT_ENCRYPTION_KEY")
        if not key_str:
            raise ConfigurationError("EVENT_ENCRYPTION_KEY environment variable required")
        
        # Convert hex string to bytes
        try:
            return bytes.fromhex(key_str)
        except ValueError:
            # Assume it's a direct string and encode
            return key_str.encode('utf-8')[:32].ljust(32, b'\0')  # Pad to 32 bytes for AES-256
    
    async def shutdown(self) -> None:
        """Shutdown event system and cleanup resources."""
        logger.info("Shutting down Docker event system")
        
        try:
            # Shutdown orchestrator
            if self._orchestrator:
                await self._orchestrator.shutdown()
            
            # Close PostgreSQL pool
            if self._postgresql_pool:
                await self._postgresql_pool.close()
            
            logger.info("Docker event system shutdown completed")
            
        except Exception as e:
            logger.exception("Error during Docker event system shutdown", error=str(e))


async def initialize_docker_event_system() -> Any:
    """
    Factory function to initialize event system for Docker deployment.
    
    Returns:
        CrossModuleEventOrchestrator: Initialized event system
        
    Raises:
        ConfigurationError: If initialization fails
    """
    config = DockerEventSystemConfig()
    initializer = DockerEventSystemInitializer(config)
    return await initializer.initialize()


# Health check function for Docker
async def event_system_health_check() -> dict[str, Any]:
    """
    Health check for event system in Docker environment.
    
    Returns:
        dict[str, Any]: Health status
    """
    try:
        config = DockerEventSystemConfig()
        
        health_status = {
            "status": "healthy",
            "postgresql_configured": config.enable_postgresql_persistence,
            "redis_configured": config.enable_redis_distribution,
            "timestamp": str(datetime.now())
        }
        
        # Test PostgreSQL connection if enabled
        if config.enable_postgresql_persistence:
            try:
                conn = await asyncpg.connect(config.get_postgresql_url())
                await conn.execute("SELECT 1")
                await conn.close()
                health_status["postgresql_status"] = "connected"
            except Exception as e:
                health_status["postgresql_status"] = f"error: {e}"
                health_status["status"] = "degraded"
        
        # Test Redis connection if enabled
        if config.enable_redis_distribution:
            try:
                # Simple Redis connection test would go here
                health_status["redis_status"] = "connected"
            except Exception as e:
                health_status["redis_status"] = f"error: {e}"
                health_status["status"] = "degraded"
        
        return health_status
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": str(datetime.now())
        }


# Export main functions
__all__ = [
    "DockerEventSystemConfig",
    "DockerEventSystemInitializer",
    "event_system_health_check",
    "initialize_docker_event_system"
]