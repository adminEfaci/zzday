"""Database connection pool configuration for Identity infrastructure.

This module provides connection pooling configuration to improve database
performance and reliability according to CAP theorem requirements.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import QueuePool
from sqlalchemy.engine.events import PoolEvents

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class ConnectionPoolConfig:
    """Configuration for database connection pool."""
    
    def __init__(
        self,
        pool_size: int = 20,
        max_overflow: int = 30,
        pool_timeout: int = 30,
        pool_recycle: int = 3600,
        pool_pre_ping: bool = True,
        pool_reset_on_return: str = "commit",
    ):
        """Initialize connection pool configuration.
        
        Args:
            pool_size: Number of connections to maintain in the pool
            max_overflow: Maximum number of connections that can overflow the pool
            pool_timeout: Timeout for getting connection from pool
            pool_recycle: Recycle connections older than this (seconds)
            pool_pre_ping: Test connections before use
            pool_reset_on_return: How to reset connections when returned to pool
        """
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_recycle = pool_recycle
        self.pool_pre_ping = pool_pre_ping
        self.pool_reset_on_return = pool_reset_on_return
        
        # Health monitoring
        self.connection_failures = 0
        self.connection_timeouts = 0
        self.pool_overflows = 0
        self.last_health_check = datetime.utcnow()
        
        # Connection pool statistics
        self.total_connections_created = 0
        self.total_connections_closed = 0
        self.active_connections = 0
        self.pool_hits = 0
        self.pool_misses = 0


class ConnectionPoolManager:
    """Manager for database connection pool with health monitoring."""
    
    def __init__(self, config: ConnectionPoolConfig):
        """Initialize connection pool manager.
        
        Args:
            config: Connection pool configuration
        """
        self.config = config
        self.engine = None
        self.session_maker = None
        self._initialized = False
        
    async def initialize(self, database_url: str) -> None:
        """Initialize the connection pool.
        
        Args:
            database_url: Database connection URL
        """
        if self._initialized:
            return
            
        try:
            # Create async engine with connection pooling
            self.engine = create_async_engine(
                database_url,
                poolclass=QueuePool,
                pool_size=self.config.pool_size,
                max_overflow=self.config.max_overflow,
                pool_timeout=self.config.pool_timeout,
                pool_recycle=self.config.pool_recycle,
                pool_pre_ping=self.config.pool_pre_ping,
                pool_reset_on_return=self.config.pool_reset_on_return,
                echo=False,  # Set to True for SQL debugging
            )
            
            # Create session maker
            self.session_maker = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )
            
            # Set up event listeners for monitoring
            self._setup_event_listeners()
            
            # Test the connection
            await self._test_connection()
            
            self._initialized = True
            
            logger.info(
                "Database connection pool initialized",
                pool_size=self.config.pool_size,
                max_overflow=self.config.max_overflow,
                pool_timeout=self.config.pool_timeout,
            )
            
        except Exception as e:
            logger.exception("Failed to initialize connection pool", error=str(e))
            self.config.connection_failures += 1
            raise
    
    def _setup_event_listeners(self) -> None:
        """Set up SQLAlchemy event listeners for monitoring."""
        
        @event.listens_for(self.engine.sync_engine, "connect")
        def on_connect(dbapi_connection, connection_record):
            """Handle connection creation."""
            self.config.total_connections_created += 1
            self.config.active_connections += 1
            
            logger.debug(
                "Database connection created",
                connection_id=id(dbapi_connection),
                active_connections=self.config.active_connections,
            )
        
        @event.listens_for(self.engine.sync_engine, "checkout")
        def on_checkout(dbapi_connection, connection_record, connection_proxy):
            """Handle connection checkout from pool."""
            self.config.pool_hits += 1
            
            logger.debug(
                "Connection checked out from pool",
                connection_id=id(dbapi_connection),
                pool_hits=self.config.pool_hits,
            )
        
        @event.listens_for(self.engine.sync_engine, "checkin")
        def on_checkin(dbapi_connection, connection_record):
            """Handle connection checkin to pool."""
            logger.debug(
                "Connection returned to pool",
                connection_id=id(dbapi_connection),
            )
        
        @event.listens_for(self.engine.sync_engine, "close")
        def on_close(dbapi_connection, connection_record):
            """Handle connection closure."""
            self.config.total_connections_closed += 1
            self.config.active_connections -= 1
            
            logger.debug(
                "Database connection closed",
                connection_id=id(dbapi_connection),
                active_connections=self.config.active_connections,
            )
        
        @event.listens_for(self.engine.sync_engine, "invalidate")
        def on_invalidate(dbapi_connection, connection_record, exception):
            """Handle connection invalidation."""
            self.config.connection_failures += 1
            
            logger.warning(
                "Database connection invalidated",
                connection_id=id(dbapi_connection),
                error=str(exception) if exception else "Unknown",
                connection_failures=self.config.connection_failures,
            )
    
    async def _test_connection(self) -> None:
        """Test database connection."""
        try:
            async with self.get_session() as session:
                from app.core.constants import HEALTH_CHECK_QUERY
                from sqlalchemy import text
                result = await session.execute(text(HEALTH_CHECK_QUERY))
                result.scalar()
                
        except Exception as e:
            logger.exception("Connection test failed", error=str(e))
            self.config.connection_failures += 1
            raise
    
    @asynccontextmanager
    async def get_session(self) -> AsyncSession:
        """Get database session from pool.
        
        Yields:
            AsyncSession: Database session
            
        Raises:
            RuntimeError: If pool not initialized
            Exception: If session creation fails
        """
        if not self._initialized:
            raise RuntimeError("Connection pool not initialized")
            
        session = None
        try:
            session = self.session_maker()
            yield session
            
        except asyncio.TimeoutError:
            self.config.connection_timeouts += 1
            logger.warning(
                "Database connection timeout",
                timeouts=self.config.connection_timeouts,
            )
            raise
            
        except Exception as e:
            self.config.connection_failures += 1
            logger.exception(
                "Database session error",
                error=str(e),
                failures=self.config.connection_failures,
            )
            
            if session:
                try:
                    await session.rollback()
                except Exception as rollback_error:
                    logger.exception(
                        "Failed to rollback session",
                        rollback_error=str(rollback_error),
                    )
            raise
            
        finally:
            if session:
                try:
                    await session.close()
                except Exception as close_error:
                    logger.exception(
                        "Failed to close session",
                        close_error=str(close_error),
                    )
    
    async def get_pool_status(self) -> Dict[str, Any]:
        """Get current pool status.
        
        Returns:
            Dict containing pool statistics
        """
        pool = self.engine.pool if self.engine else None
        
        return {
            "initialized": self._initialized,
            "pool_size": self.config.pool_size,
            "max_overflow": self.config.max_overflow,
            "current_checked_in": pool.checkedin() if pool else 0,
            "current_checked_out": pool.checkedout() if pool else 0,
            "current_overflow": pool.overflow() if pool else 0,
            "total_connections_created": self.config.total_connections_created,
            "total_connections_closed": self.config.total_connections_closed,
            "active_connections": self.config.active_connections,
            "connection_failures": self.config.connection_failures,
            "connection_timeouts": self.config.connection_timeouts,
            "pool_hits": self.config.pool_hits,
            "pool_misses": self.config.pool_misses,
            "last_health_check": self.config.last_health_check.isoformat(),
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on connection pool.
        
        Returns:
            Dict containing health check results
        """
        health_status = {
            "healthy": True,
            "timestamp": datetime.utcnow().isoformat(),
            "pool_status": await self.get_pool_status(),
            "checks": {},
        }
        
        # Check if pool is initialized
        if not self._initialized:
            health_status["healthy"] = False
            health_status["checks"]["initialization"] = {
                "status": "failed",
                "message": "Connection pool not initialized",
            }
            return health_status
        
        # Check connection
        try:
            async with self.get_session() as session:
                from app.core.constants import HEALTH_CHECK_QUERY
                from sqlalchemy import text
                result = await session.execute(text(HEALTH_CHECK_QUERY))
                result.scalar()
                
            health_status["checks"]["connection"] = {
                "status": "healthy",
                "message": "Database connection successful",
            }
            
        except Exception as e:
            health_status["healthy"] = False
            health_status["checks"]["connection"] = {
                "status": "failed",
                "message": str(e),
            }
        
        # Check pool metrics
        pool_status = health_status["pool_status"]
        
        # Check for high failure rate
        if pool_status["connection_failures"] > 10:
            health_status["checks"]["failure_rate"] = {
                "status": "warning",
                "message": f"High connection failure rate: {pool_status['connection_failures']}",
            }
        
        # Check for pool exhaustion
        if pool_status["current_overflow"] >= self.config.max_overflow:
            health_status["checks"]["pool_exhaustion"] = {
                "status": "warning",
                "message": "Connection pool at maximum overflow",
            }
        
        # Check for timeout issues
        if pool_status["connection_timeouts"] > 5:
            health_status["checks"]["timeout_rate"] = {
                "status": "warning",
                "message": f"High connection timeout rate: {pool_status['connection_timeouts']}",
            }
        
        # Update last health check time
        self.config.last_health_check = datetime.utcnow()
        
        return health_status
    
    async def close(self) -> None:
        """Close connection pool."""
        if self.engine:
            await self.engine.dispose()
            self.engine = None
            self.session_maker = None
            self._initialized = False
            
            logger.info("Connection pool closed")


# Global connection pool manager
_connection_pool_manager: Optional[ConnectionPoolManager] = None


def get_connection_pool_manager() -> ConnectionPoolManager:
    """Get the global connection pool manager.
    
    Returns:
        ConnectionPoolManager: Global connection pool manager
        
    Raises:
        RuntimeError: If connection pool not initialized
    """
    global _connection_pool_manager
    
    if _connection_pool_manager is None:
        raise RuntimeError("Connection pool not initialized. Call initialize_connection_pool() first.")
    
    return _connection_pool_manager


async def initialize_connection_pool(
    database_url: str,
    pool_config: Optional[ConnectionPoolConfig] = None,
) -> ConnectionPoolManager:
    """Initialize the global connection pool.
    
    Args:
        database_url: Database connection URL
        pool_config: Optional connection pool configuration
        
    Returns:
        ConnectionPoolManager: Initialized connection pool manager
    """
    global _connection_pool_manager
    
    if _connection_pool_manager is not None:
        logger.warning("Connection pool already initialized")
        return _connection_pool_manager
    
    if pool_config is None:
        pool_config = ConnectionPoolConfig()
    
    _connection_pool_manager = ConnectionPoolManager(pool_config)
    await _connection_pool_manager.initialize(database_url)
    
    return _connection_pool_manager


async def close_connection_pool() -> None:
    """Close the global connection pool."""
    global _connection_pool_manager
    
    if _connection_pool_manager is not None:
        await _connection_pool_manager.close()
        _connection_pool_manager = None