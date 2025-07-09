"""Database connection and session management following pure Python principles.

This module provides comprehensive database connection management, session handling,
and monitoring capabilities following clean architecture principles with pure Python
classes that are completely independent of any framework (FastAPI, Pydantic, etc.).

The database layer handles SQLAlchemy async sessions, connection pooling, health checks,
and performance monitoring while maintaining framework-agnostic design.

Design Principles:
- Pure Python classes with explicit configuration validation
- Framework-agnostic design for maximum portability
- Comprehensive connection management and pooling
- Rich error handling and recovery mechanisms
- Performance monitoring and health checks
- Transaction safety with automatic rollback
- Configurable connection strategies per environment

Architecture:
- ConnectionManager: Connection lifecycle and pool management
- SessionManager: Session creation and transaction handling
- HealthChecker: Database connectivity and performance monitoring
- MetricsCollector: Performance and usage metrics collection
"""

import asyncio
import contextlib
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import event, text
from sqlalchemy.exc import DisconnectionError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import DatabaseConfig
from app.core.constants import HEALTH_CHECK_QUERY
from app.core.enums import HealthStatus
from app.core.errors import InfrastructureError
from app.core.logging import get_logger

logger = get_logger(__name__)


# =====================================================================================
# CONSTANTS
# =====================================================================================

# Performance thresholds
HEALTH_CHECK_EXCELLENT_THRESHOLD = 0.01
HEALTH_CHECK_GOOD_THRESHOLD = 0.1
HEALTH_CHECK_DEGRADED_THRESHOLD = 0.5
RESOURCE_UTILIZATION_MODERATE_THRESHOLD = 0.5
RESOURCE_UTILIZATION_HIGH_THRESHOLD = 0.8
HEALTH_RESPONSE_FAST_THRESHOLD = 0.1
HEALTH_RESPONSE_SLOW_THRESHOLD = 1.0

# Error messages
DB_INIT_ERROR_MSG = "Database initialization failed"
DB_NOT_INITIALIZED_MSG = "Database not initialized"
CONNECTION_MANAGER_NOT_INIT_MSG = "ConnectionManager not initialized"
SESSION_MANAGER_NOT_INIT_MSG = "SessionManager not initialized"
DB_CONNECTION_TIMEOUT_MSG = "Database connection timeout"
DB_DISCONNECTION_ERROR_MSG = "Database disconnection"
DB_CONNECTION_ERROR_MSG = "Database connection error"


# =====================================================================================
# METRICS AND MONITORING
# =====================================================================================


@dataclass
class ConnectionMetrics:
    """Database connection metrics for monitoring."""

    # Connection counts
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    failed_connections: int = 0

    # Performance metrics
    avg_connection_time: float = 0.0
    max_connection_time: float = 0.0
    total_query_time: float = 0.0
    query_count: int = 0

    # Health metrics
    health_check_count: int = 0
    health_check_failures: int = 0
    last_health_check: datetime | None = None
    current_health_status: HealthStatus = HealthStatus.UNKNOWN

    # Error tracking
    connection_errors: int = 0
    timeout_errors: int = 0
    other_errors: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_connections": self.total_connections,
            "active_connections": self.active_connections,
            "idle_connections": self.idle_connections,
            "failed_connections": self.failed_connections,
            "avg_connection_time": self.avg_connection_time,
            "max_connection_time": self.max_connection_time,
            "total_query_time": self.total_query_time,
            "query_count": self.query_count,
            "avg_query_time": self.total_query_time / max(self.query_count, 1),
            "health_check_count": self.health_check_count,
            "health_check_failures": self.health_check_failures,
            "health_check_success_rate": 1.0
            - (self.health_check_failures / max(self.health_check_count, 1)),
            "last_health_check": self.last_health_check.isoformat()
            if self.last_health_check
            else None,
            "current_health_status": self.current_health_status.value,
            "connection_errors": self.connection_errors,
            "timeout_errors": self.timeout_errors,
            "other_errors": self.other_errors,
            "total_errors": self.connection_errors
            + self.timeout_errors
            + self.other_errors,
        }


# =====================================================================================
# CONNECTION MANAGEMENT
# =====================================================================================


class ConnectionManager:
    """
    Database connection manager with comprehensive lifecycle management.

    Manages SQLAlchemy async engines, connection pooling, and provides
    framework-agnostic database connectivity.

    Design Features:
    - Pure Python implementation
    - Comprehensive connection lifecycle management
    - Performance monitoring and metrics collection
    - Automatic retry and recovery mechanisms
    - Health checking and status monitoring
    - Environment-specific optimizations

    Usage Example:
        config = DatabaseConfig(url="postgresql+asyncpg://...")
        manager = ConnectionManager(config)

        await manager.initialize()

        # Use engine for raw connections
        async with manager.get_connection() as conn:
            result = await conn.execute(text(HEALTH_CHECK_QUERY))

        await manager.shutdown()
    """

    def __init__(self, config: DatabaseConfig):
        """
        Initialize connection manager.

        Args:
            config: Database configuration
        """
        self.config = config
        self.engine: AsyncEngine | None = None
        self.metrics = ConnectionMetrics()
        self._initialized = False
        self._shutdown = False
        self._health_check_task: asyncio.Task | None = None

        # Performance tracking
        self._connection_times: list[float] = []
        self._query_times: list[float] = []

        logger.info("ConnectionManager initialized", config=config.to_dict())

    async def initialize(self) -> None:
        """
        Initialize database engine and start monitoring.

        Raises:
            InfrastructureError: If initialization fails
        """
        if self._initialized:
            logger.warning("ConnectionManager already initialized")
            return

        try:
            # Create async engine
            self.engine = create_async_engine(
                self.config.url, **self.config.get_engine_kwargs()
            )

            # Set up event listeners
            self._setup_event_listeners()

            # Test initial connection
            await self._test_connection()

            # Start health check monitoring
            if self.config.health_check_interval > 0:
                self._health_check_task = asyncio.create_task(self._health_check_loop())

            self._initialized = True

            logger.info(
                "ConnectionManager initialized successfully",
                engine_info=str(self.engine.url).replace(
                    str(self.engine.url.password) or "", "***"
                ),
            )

        except Exception as e:
            logger.exception(
                "Failed to initialize ConnectionManager",
                error=str(e),
                error_type=type(e).__name__,
            )
            raise InfrastructureError(DB_INIT_ERROR_MSG) from e

    async def shutdown(self) -> None:
        """Shutdown connection manager and cleanup resources."""
        if self._shutdown:
            return

        self._shutdown = True

        # Cancel health check task
        if self._health_check_task:
            self._health_check_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_check_task

        # Dispose engine
        if self.engine:
            await self.engine.dispose()

        logger.info("ConnectionManager shutdown completed")

    @asynccontextmanager
    async def get_connection(self):
        """
        Get raw database connection with automatic cleanup.

        Yields:
            AsyncConnection: Database connection

        Raises:
            InfrastructureError: If connection fails
        """
        if not self._initialized or not self.engine:
            raise InfrastructureError(CONNECTION_MANAGER_NOT_INIT_MSG)

        start_time = time.time()
        connection = None

        try:
            connection = await self.engine.connect()

            # Track connection time
            connection_time = time.time() - start_time
            self._connection_times.append(connection_time)
            self.metrics.total_connections += 1
            self.metrics.active_connections += 1

            # Update metrics
            self.metrics.max_connection_time = max(
                self.metrics.max_connection_time, connection_time
            )

            self.metrics.avg_connection_time = sum(self._connection_times[-100:]) / len(
                self._connection_times[-100:]
            )

            logger.debug(
                "Database connection acquired",
                connection_time=connection_time,
                active_connections=self.metrics.active_connections,
            )

            yield connection

        except SQLAlchemyTimeoutError as e:
            self.metrics.timeout_errors += 1
            self.metrics.failed_connections += 1
            logger.exception(
                "Database connection timeout",
                error=str(e),
                connection_time=time.time() - start_time,
                active_connections=self.metrics.active_connections
            )
            raise InfrastructureError(
                f"{DB_CONNECTION_TIMEOUT_MSG}: {str(e)[:100]}"
            ) from e

        except DisconnectionError as e:
            self.metrics.connection_errors += 1
            self.metrics.failed_connections += 1
            logger.exception(
                "Database disconnection error",
                error=str(e),
                connection_time=time.time() - start_time,
                active_connections=self.metrics.active_connections
            )
            raise InfrastructureError(
                f"{DB_DISCONNECTION_ERROR_MSG}: {str(e)[:100]}"
            ) from e

        except SQLAlchemyError as e:
            self.metrics.other_errors += 1
            self.metrics.failed_connections += 1
            logger.exception(
                "Database connection error",
                error=str(e),
                error_type=type(e).__name__,
                connection_time=time.time() - start_time,
                active_connections=self.metrics.active_connections
            )
            raise InfrastructureError(
                f"{DB_CONNECTION_ERROR_MSG}: {str(e)[:100]}"
            ) from e

        finally:
            if connection:
                await connection.close()
                self.metrics.active_connections -= 1

                logger.debug(
                    "Database connection released",
                    active_connections=self.metrics.active_connections,
                )

    async def execute_query(
        self, query: str, parameters: dict[str, Any] | None = None
    ) -> Any:
        """
        Execute a query with performance tracking.

        Args:
            query: SQL query to execute
            parameters: Query parameters

        Returns:
            Query result

        Raises:
            InfrastructureError: If query execution fails
        """
        start_time = time.time()

        try:
            async with self.get_connection() as conn:
                if parameters:
                    result = await conn.execute(text(query), parameters)
                else:
                    result = await conn.execute(text(query))

                # Track query time
                query_time = time.time() - start_time
                self._query_times.append(query_time)
                self.metrics.query_count += 1
                self.metrics.total_query_time += query_time

                logger.debug(
                    "Query executed successfully",
                    query_time=query_time,
                    query_count=self.metrics.query_count,
                )

                return result

        except Exception as e:
            query_time = time.time() - start_time
            logger.exception(
                "Query execution failed",
                query=query[:100],  # First 100 chars only
                query_time=query_time,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise

    async def check_health(self) -> HealthStatus:
        """
        Check database health status.

        Returns:
            HealthStatus: Current health status
        """
        try:
            start_time = time.time()

            async with self.get_connection() as conn:
                await conn.execute(text(HEALTH_CHECK_QUERY))

            check_time = time.time() - start_time
            self.metrics.health_check_count += 1
            self.metrics.last_health_check = datetime.utcnow()

            # Determine health status based on performance
            if check_time < HEALTH_RESPONSE_FAST_THRESHOLD:
                status = HealthStatus.HEALTHY
            elif check_time < HEALTH_RESPONSE_SLOW_THRESHOLD:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.UNHEALTHY

            self.metrics.current_health_status = status

            logger.debug(
                "Health check completed", status=status.value, check_time=check_time
            )

        except Exception as e:
            self.metrics.health_check_failures += 1
            self.metrics.current_health_status = HealthStatus.UNHEALTHY

            logger.exception(
                "Health check failed", error=str(e), error_type=type(e).__name__
            )

            return HealthStatus.UNHEALTHY
        else:
            return status

    def get_metrics(self) -> dict[str, Any]:
        """Get current connection metrics."""
        return self.metrics.to_dict()

    def _setup_event_listeners(self) -> None:
        """Setup SQLAlchemy event listeners for monitoring."""
        if not self.engine:
            return

        @event.listens_for(self.engine.sync_engine, "connect")
        def on_connect(dbapi_connection, connection_record):
            """Handle new database connections."""
            logger.debug("New database connection established")

        @event.listens_for(self.engine.sync_engine, "checkout")
        def on_checkout(dbapi_connection, connection_record, connection_proxy):
            """Handle connection checkout from pool."""
            self.metrics.active_connections += 1

        @event.listens_for(self.engine.sync_engine, "checkin")
        def on_checkin(dbapi_connection, connection_record):
            """Handle connection checkin to pool."""
            self.metrics.active_connections = max(
                0, self.metrics.active_connections - 1
            )

    async def _test_connection(self) -> None:
        """Test initial database connection."""
        try:
            async with self.get_connection() as conn:
                await conn.execute(text(HEALTH_CHECK_QUERY))

            logger.info("Initial database connection test successful")

        except Exception as e:
            logger.exception("Initial database connection test failed", error=str(e))
            raise

    async def _health_check_loop(self) -> None:
        """Background health check monitoring loop."""
        consecutive_failures = 0

        while not self._shutdown:
            try:
                await asyncio.sleep(self.config.health_check_interval)

                if self._shutdown:
                    break

                status = await self.check_health()

                if status == HealthStatus.UNHEALTHY:
                    consecutive_failures += 1

                    if consecutive_failures >= self.config.max_health_check_failures:
                        logger.error(
                            "Database health check failed repeatedly",
                            consecutive_failures=consecutive_failures,
                            max_failures=self.config.max_health_check_failures,
                        )
                        # Could trigger alerts or circuit breaker here
                else:
                    consecutive_failures = 0

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(
                    "Health check loop error", error=str(e), error_type=type(e).__name__
                )
                await asyncio.sleep(5)  # Brief pause before retry


# =====================================================================================
# SESSION MANAGEMENT
# =====================================================================================


class SessionManager:
    """
    Database session manager with transaction support and monitoring.

    Provides framework-agnostic database session management with automatic
    transaction handling, rollback on errors, and comprehensive monitoring.

    Design Features:
    - Pure Python implementation
    - Automatic transaction management
    - Session lifecycle tracking
    - Error handling and rollback
    - Performance monitoring
    - Context manager support

    Usage Example:
        manager = SessionManager(connection_manager)

        async with manager.get_session() as session:
            user = await session.get(User, user_id)
            user.name = "Updated Name"
            # Automatic commit on success, rollback on error
    """

    def __init__(self, connection_manager: ConnectionManager):
        """
        Initialize session manager.

        Args:
            connection_manager: Database connection manager
        """
        self.connection_manager = connection_manager
        self.session_factory: async_sessionmaker | None = None

        # Session tracking
        self._active_sessions: dict[UUID, datetime] = {}
        self._session_count = 0
        self._error_count = 0
        self._total_session_time = 0.0

        logger.info("SessionManager initialized")

    def initialize(self) -> None:
        """Initialize session factory."""
        if not self.connection_manager.engine:
            raise InfrastructureError(CONNECTION_MANAGER_NOT_INIT_MSG)

        self.session_factory = async_sessionmaker(
            self.connection_manager.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )

        logger.info("SessionManager session factory initialized")

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get database session with automatic transaction management.

        Yields:
            AsyncSession: Database session

        Raises:
            InfrastructureError: If session creation fails
        """
        if not self.session_factory:
            raise InfrastructureError(SESSION_MANAGER_NOT_INIT_MSG)

        session_id = uuid4()
        start_time = time.time()
        session = None

        try:
            # Create session
            session = self.session_factory()
            self._active_sessions[session_id] = datetime.utcnow()
            self._session_count += 1

            logger.debug(
                "Database session created",
                session_id=session_id,
                active_sessions=len(self._active_sessions),
            )

            yield session

        except Exception as e:
            # Rollback transaction on error
            if session:
                await session.rollback()

            self._error_count += 1
            session_time = time.time() - start_time
            self._total_session_time += session_time

            logger.exception(
                "Database session rollback due to error",
                session_id=session_id,
                session_time=session_time,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise
        else:
            # Commit transaction on success
            await session.commit()

            session_time = time.time() - start_time
            self._total_session_time += session_time

            logger.debug(
                "Database session committed",
                session_id=session_id,
                session_time=session_time,
            )

        finally:
            # Always close session
            if session:
                await session.close()

            # Remove from active sessions
            self._active_sessions.pop(session_id, None)

            logger.debug(
                "Database session closed",
                session_id=session_id,
                active_sessions=len(self._active_sessions),
            )

    def get_session_metrics(self) -> dict[str, Any]:
        """Get session performance metrics."""
        avg_session_time = self._total_session_time / max(self._session_count, 1)
        error_rate = self._error_count / max(self._session_count, 1)

        return {
            "total_sessions": self._session_count,
            "active_sessions": len(self._active_sessions),
            "error_count": self._error_count,
            "total_session_time": self._total_session_time,
            "average_session_time": avg_session_time,
            "error_rate": error_rate,
            "longest_active_session": self._get_longest_active_session_age(),
        }

    def _get_longest_active_session_age(self) -> float | None:
        """Get age of longest active session in seconds."""
        if not self._active_sessions:
            return None

        now = datetime.utcnow()
        oldest_time = min(self._active_sessions.values())
        return (now - oldest_time).total_seconds()


# =====================================================================================
# HEALTH CHECKER
# =====================================================================================


class HealthChecker:
    """
    Comprehensive database health checker with detailed diagnostics.

    Provides detailed health checking capabilities including connectivity,
    performance, and resource utilization monitoring.
    """

    def __init__(self, connection_manager: ConnectionManager):
        """Initialize health checker."""
        self.connection_manager = connection_manager
        self.last_check_time: datetime | None = None
        self.last_check_result: dict[str, Any] | None = None

    async def check_comprehensive_health(self) -> dict[str, Any]:
        """
        Perform comprehensive health check.

        Returns:
            dict[str, Any]: Detailed health status
        """
        start_time = time.time()
        health_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": HealthStatus.UNKNOWN.value,
            "checks": {},
            "metrics": {},
            "check_duration": 0.0,
        }

        try:
            # Basic connectivity check
            health_data["checks"]["connectivity"] = await self._check_connectivity()

            # Performance check
            health_data["checks"]["performance"] = await self._check_performance()

            # Resource utilization check
            health_data["checks"]["resources"] = await self._check_resources()

            # Determine overall status
            health_data["overall_status"] = self._determine_overall_status(
                health_data["checks"]
            )

            # Add metrics
            health_data["metrics"] = self.connection_manager.get_metrics()

            # Update tracking
            self.last_check_time = datetime.utcnow()
            self.last_check_result = health_data

        except Exception as e:
            health_data["overall_status"] = HealthStatus.UNHEALTHY.value
            health_data["error"] = str(e)
            health_data["error_type"] = type(e).__name__

        health_data["check_duration"] = time.time() - start_time
        return health_data

    async def _check_connectivity(self) -> dict[str, Any]:
        """Check basic database connectivity."""
        try:
            start_time = time.time()

            async with self.connection_manager.get_connection() as conn:
                await conn.execute(text(HEALTH_CHECK_QUERY))

            response_time = time.time() - start_time

        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "error_type": type(e).__name__,
                "message": "Database connection failed",
            }
        else:
            return {
                "status": "healthy",
                "response_time": response_time,
                "message": "Database connection successful",
            }

    async def _check_performance(self) -> dict[str, Any]:
        """Check database performance metrics."""
        try:
            queries = ["SELECT 1", "SELECT version()", "SELECT current_timestamp"]

            total_time = 0.0
            query_times = []

            for query in queries:
                start_time = time.time()

                async with self.connection_manager.get_connection() as conn:
                    await conn.execute(text(query))

                query_time = time.time() - start_time
                query_times.append(query_time)
                total_time += query_time

            avg_time = total_time / len(queries)
            max_time = max(query_times)

            # Determine performance status
            if avg_time < HEALTH_CHECK_EXCELLENT_THRESHOLD:
                status = "excellent"
            elif avg_time < HEALTH_CHECK_GOOD_THRESHOLD:
                status = "good"
            elif avg_time < HEALTH_CHECK_DEGRADED_THRESHOLD:
                status = "degraded"
            else:
                status = "poor"

            return {
                "status": status,
                "avg_query_time": avg_time,
                "max_query_time": max_time,
                "total_test_time": total_time,
                "queries_tested": len(queries),
            }

        except Exception as e:
            return {"status": "failed", "error": str(e), "error_type": type(e).__name__}

    async def _check_resources(self) -> dict[str, Any]:
        """Check database resource utilization."""
        try:
            metrics = self.connection_manager.get_metrics()

            # Analyze connection utilization
            total_connections = metrics.get("total_connections", 0)
            active_connections = metrics.get("active_connections", 0)
            max_connections = (
                self.connection_manager.config.pool_size
                + self.connection_manager.config.max_overflow
            )

            utilization = active_connections / max(max_connections, 1)

            if utilization < RESOURCE_UTILIZATION_MODERATE_THRESHOLD:
                status = "good"
            elif utilization < RESOURCE_UTILIZATION_HIGH_THRESHOLD:
                status = "moderate"
            else:
                status = "high"

        except Exception as e:
            return {"status": "failed", "error": str(e), "error_type": type(e).__name__}
        else:
            return {
                "status": status,
                "connection_utilization": utilization,
                "active_connections": active_connections,
                "max_connections": max_connections,
                "total_connections": total_connections,
            }

    def _determine_overall_status(self, checks: dict[str, Any]) -> str:
        """Determine overall health status from individual checks."""
        connectivity_status = checks.get("connectivity", {}).get("status", "unknown")
        performance_status = checks.get("performance", {}).get("status", "unknown")
        resources_status = checks.get("resources", {}).get("status", "unknown")

        # Connectivity is critical
        if connectivity_status == "unhealthy":
            return HealthStatus.UNHEALTHY.value

        # Performance degradation
        if performance_status in ["poor", "failed"]:
            return HealthStatus.DEGRADED.value

        # Resource constraints
        if resources_status == "high":
            return HealthStatus.DEGRADED.value

        # All good
        if all(
            status in ["healthy", "excellent", "good"]
            for status in [connectivity_status, performance_status, resources_status]
        ):
            return HealthStatus.HEALTHY.value

        return HealthStatus.DEGRADED.value


# =====================================================================================
# FACTORY FUNCTIONS AND GLOBALS
# =====================================================================================

# Global instances (initialized by application)
_connection_manager: ConnectionManager | None = None
_session_manager: SessionManager | None = None
_health_checker: HealthChecker | None = None


def initialize_database(config: DatabaseConfig) -> None:
    """
    Initialize global database components.

    Args:
        config: Database configuration
    """
    global _connection_manager, _session_manager, _health_checker  # noqa: PLW0603

    # Create managers
    _connection_manager = ConnectionManager(config)
    _session_manager = SessionManager(_connection_manager)
    _health_checker = HealthChecker(_connection_manager)

    logger.info("Database components initialized")


async def startup_database() -> None:
    """Startup database connections and monitoring."""
    # Global variables are read-only in this function

    if not _connection_manager:
        raise InfrastructureError(DB_NOT_INITIALIZED_MSG)

    await _connection_manager.initialize()
    if _session_manager:
        _session_manager.initialize()

    logger.info("Database startup completed")


async def shutdown_database() -> None:
    """Shutdown database connections and cleanup."""
    if _connection_manager:
        await _connection_manager.shutdown()

    logger.info("Database shutdown completed")


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session (convenience function).

    Yields:
        AsyncSession: Database session
    """
    if not _session_manager:
        raise InfrastructureError(DB_NOT_INITIALIZED_MSG)

    async with _session_manager.get_session() as session:
        yield session


async def check_database_health() -> dict[str, Any]:
    """
    Check database health (convenience function).

    Returns:
        dict[str, Any]: Health status
    """
    if not _health_checker:
        raise InfrastructureError(DB_NOT_INITIALIZED_MSG)

    return await _health_checker.check_comprehensive_health()


def get_database_metrics() -> dict[str, Any]:
    """
    Get database metrics (convenience function).

    Returns:
        dict[str, Any]: Database metrics
    """
    if not _connection_manager or not _session_manager:
        raise InfrastructureError(DB_NOT_INITIALIZED_MSG)

    connection_metrics = _connection_manager.get_metrics()
    session_metrics = _session_manager.get_session_metrics()

    return {
        "connection_metrics": connection_metrics,
        "session_metrics": session_metrics,
        "combined_metrics": {
            "total_operations": connection_metrics.get("total_connections", 0)
            + session_metrics.get("total_sessions", 0),
            "active_operations": connection_metrics.get("active_connections", 0)
            + session_metrics.get("active_sessions", 0),
            "error_rate": (
                connection_metrics.get("total_errors", 0)
                + session_metrics.get("error_count", 0)
            )
            / max(
                connection_metrics.get("total_connections", 0)
                + session_metrics.get("total_sessions", 0),
                1,
            ),
        },
    }


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    "ConnectionManager",
    "ConnectionMetrics",
    "HealthChecker",
    "SessionManager",
    "check_database_health",
    "get_database_metrics",
    "get_session",
    "initialize_database",
    "shutdown_database",
    "startup_database",
]
