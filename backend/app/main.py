"""Application entry point."""

import os
import signal
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from prometheus_client import make_asgi_app
from strawberry.fastapi import GraphQLRouter

from app.core.cache import cache_manager
from app.core.config import settings
from app.core.database import initialize_database, shutdown_database, startup_database
from app.core.dependencies import ContainerMode, DependencyConfig, create_container
from app.core.enums import Environment
from app.core.events.bus import create_event_bus
from app.core.events.types import IEventBus
from app.core.logging import configure_logging, get_logger
from app.core.middleware.auth import AuthMiddleware, CoreAuthenticator
from app.core.middleware.rate_limiter import RateLimitMiddleware
from app.core.monitoring import register_metrics
from app.presentation.graphql.schema import create_schema, get_context

# Configure structured logging
configure_logging()
logger = get_logger(__name__)

# Module dependency configurations (with safe imports)
try:
    from app.modules.identity.infrastructure.dependencies import (
        configure_identity_dependencies,
    )
except ImportError:
    logger.warning("Identity dependency configuration not found")

    def configure_identity_dependencies(x):
        return None


try:
    from app.modules.audit.infrastructure.dependencies import (
        configure_audit_dependencies,
    )
except ImportError:
    logger.warning("Audit dependency configuration not found")

    def configure_audit_dependencies(x):
        return None


try:
    from app.modules.notification.infrastructure.dependencies import (
        configure_notification_dependencies,
    )
except ImportError:
    logger.warning("Notification dependency configuration not found")

    def configure_notification_dependencies(x):
        return None


try:
    from app.modules.integration.infrastructure.dependencies import (
        configure_integration_dependencies,
    )
except ImportError:
    logger.warning("Integration dependency configuration not found")

    def configure_integration_dependencies(x):
        return None


# Module event handlers registration (with safe imports)
try:
    from app.modules.identity.application.event_handlers import (
        register_identity_event_handlers,
    )
except ImportError:
    logger.warning("Identity event handlers registration function not found")

    def register_identity_event_handlers(x):
        return None


try:
    from app.modules.audit.application.event_handlers import (
        register_audit_event_handlers,
    )
except ImportError:
    logger.warning("Audit event handlers registration function not found")

    def register_audit_event_handlers(x):
        return None


try:
    from app.modules.notification.application.event_handlers import (
        register_notification_event_handlers,
    )
except ImportError:
    logger.warning("Notification event handlers registration function not found")

    def register_notification_event_handlers(x):
        return None


try:
    from app.modules.integration.application.events import (
        register_integration_event_handlers,
    )
except ImportError:
    logger.warning("Integration event handlers registration function not found")

    def register_integration_event_handlers(x):
        return None


# Background task imports
try:
    from celery import Celery
    from kombu import Queue

    HAS_CELERY = True
except ImportError:
    HAS_CELERY = False


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan manager with comprehensive module integration."""
    # Log database connection info (without credentials)
    db_info = _get_database_url_info()
    logger.info(
        "Starting EzzDay Backend",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT.value,
        database_driver=db_info.get("scheme"),
        database_host=db_info.get("host"),
        database_port=db_info.get("port"),
        database_name=db_info.get("database"),
        database_user=db_info.get("username"),
        pool_size=settings.database.pool_size,
        max_overflow=settings.database.max_overflow,
    )

    # Initialize dependency container with environment-aware configuration
    container_config = DependencyConfig(
        environment=settings.ENVIRONMENT,
        mode=ContainerMode.PRODUCTION
        if settings.ENVIRONMENT == Environment.PRODUCTION
        else ContainerMode.STANDARD,
        enable_monitoring=True,
        enable_circular_detection=settings.ENVIRONMENT != Environment.PRODUCTION,
        enable_caching=True,
        enable_service_isolation=settings.ENVIRONMENT == Environment.PRODUCTION,
    )

    container = create_container(container_config)
    app.state.container = container

    # Configure all module dependencies
    logger.info("Configuring module dependencies")
    
    async def configure_module_dependencies():
        """Configure all module dependencies with proper error handling and PostgreSQL context."""
        modules = [
            ("Identity", configure_identity_dependencies),
            ("Audit", configure_audit_dependencies),
            ("Notification", configure_notification_dependencies),
            ("Integration", configure_integration_dependencies),
        ]
        
        configured_modules = []
        failed_modules = []
        
        # Register database session factory for modules
        from app.core.database import get_session
        await container.register(RegistrationRequest(
            interface=type('ISessionFactory', (), {}),
            implementation=get_session,
            lifetime=ServiceLifetime.SINGLETON,
            name="database_session_factory",
            description="PostgreSQL async session factory"
        ))
        
        for module_name, configure_func in modules:
            try:
                await configure_func(container)
                configured_modules.append(module_name)
                logger.info(f"{module_name} module dependencies configured with PostgreSQL support")
            except Exception as e:
                failed_modules.append((module_name, str(e)))
                logger.exception(f"Failed to configure {module_name} dependencies: {e}")
                # In production, continue with placeholders for resilience
                if settings.ENVIRONMENT == Environment.PRODUCTION:
                    logger.warning(f"Continuing with placeholder dependencies for {module_name}")
                else:
                    logger.warning(f"Module {module_name} has configuration issues but continuing")
        
        # Log final configuration status
        logger.info(
            "Module dependency configuration completed",
            configured_modules=configured_modules,
            failed_modules=[name for name, _ in failed_modules],
            total_modules=len(modules),
            success_rate=f"{len(configured_modules)}/{len(modules)}",
            database_type="PostgreSQL"
        )
        
        return configured_modules, failed_modules

    configured_modules, failed_modules = await configure_module_dependencies()

    # Initialize and configure event bus
    logger.info("Initializing event bus", backend="hybrid")
    redis_url = getattr(settings, "REDIS_URL", None) or getattr(
        settings.cache, "redis_url", None
    )
    event_bus = create_event_bus(
        mode="hybrid" if redis_url else "in_memory",
        redis_url=redis_url,
        fallback_to_memory=True,
        health_check_interval=30,
    )

    await event_bus.start()
    app.state.event_bus = event_bus
    # Register the event bus with container using RegistrationRequest
    from app.core.dependencies import RegistrationRequest
    from app.core.enums import ServiceLifetime
    await container.register(RegistrationRequest(
        interface=IEventBus,
        implementation=event_bus,
        lifetime=ServiceLifetime.SINGLETON,
        name="event_bus",
        description="Application event bus for cross-module communication"
    ))

    # Register cross-module event subscriptions
    logger.info("Registering cross-module event handlers")
    try:
        register_identity_event_handlers(event_bus)
        logger.info("Identity event handlers registered")
    except Exception as e:
        logger.exception(f"Failed to register Identity event handlers: {e}")

    try:
        register_audit_event_handlers(event_bus)
        logger.info("Audit event handlers registered")
    except Exception as e:
        logger.exception(f"Failed to register Audit event handlers: {e}")

    try:
        register_notification_event_handlers(event_bus)
        logger.info("Notification event handlers registered")
    except Exception as e:
        logger.exception(f"Failed to register Notification event handlers: {e}")

    try:
        register_integration_event_handlers(event_bus)
        logger.info("Integration event handlers registered")
    except Exception as e:
        logger.exception(f"Failed to register Integration event handlers: {e}")

    # Initialize cache manager
    logger.info("Initializing cache manager", backend=settings.cache.backend_type.value)
    await cache_manager.start()
    app.state.cache_manager = cache_manager

    # Register Prometheus metrics
    register_metrics()

    # Initialize database with health check and PostgreSQL optimizations
    logger.info("Initializing PostgreSQL database connection")
    try:
        # Initialize database components with PostgreSQL-specific settings
        initialize_database(settings.database)

        # Startup database connections with connection testing
        await startup_database()

        # Test PostgreSQL connection and extensions
        await _test_postgresql_setup()

        logger.info("PostgreSQL database connection established successfully")
    except Exception as e:
        logger.exception("PostgreSQL database connection failed", error=str(e))
        if settings.ENVIRONMENT == Environment.PRODUCTION:
            # In production, fail fast on database issues
            raise
        else:
            # In development, log but continue (for development without DB)
            logger.warning("Continuing without database connection for development")

    # Initialize Celery workers if available
    if HAS_CELERY:
        logger.info("Initializing background task workers")
        celery_app = configure_celery()
        app.state.celery_app = celery_app

    # Setup graceful shutdown handlers
    setup_shutdown_handlers(app)

    logger.info("EzzDay Backend startup completed successfully")

    yield

    # Cleanup during shutdown
    logger.info("Starting graceful shutdown")

    # Stop event bus
    try:
        await event_bus.stop()
        logger.info("Event bus stopped")
    except Exception as e:
        logger.exception("Error stopping event bus", error=str(e))

    # Stop cache manager
    try:
        await cache_manager.stop()
        logger.info("Cache manager stopped")
    except Exception as e:
        logger.exception("Error stopping cache manager", error=str(e))

    # Shutdown database connections
    try:
        await shutdown_database()
        logger.info("Database connections disposed")
    except Exception as e:
        logger.exception("Error disposing database", error=str(e))

    # Clear dependency container
    try:
        container.clear()
        logger.info("Dependency container cleared")
    except Exception as e:
        logger.exception("Error clearing container", error=str(e))

    logger.info("EzzDay Backend shutdown completed")


async def _test_postgresql_setup() -> None:
    """Test PostgreSQL database setup and extensions."""
    try:
        from sqlalchemy import text

        from app.core.constants import (
            JSON_SUPPORT_QUERY,
            POSTGIS_VERSION_QUERY,
            POSTGRESQL_VERSION_QUERY,
        )
        
        async with get_session() as session:
            # Test PostgreSQL version
            result = await session.execute(text(POSTGRESQL_VERSION_QUERY))
            version = result.scalar()
            logger.info("PostgreSQL version confirmed", version=version)
            
            # Test PostGIS extension if available
            try:
                result = await session.execute(text(POSTGIS_VERSION_QUERY))
                postgis_version = result.scalar()
                logger.info("PostGIS extension available", version=postgis_version)
            except Exception:
                logger.info("PostGIS extension not available (optional)")
                
            # Test JSON capabilities
            result = await session.execute(text(JSON_SUPPORT_QUERY))
            logger.info("PostgreSQL JSON support confirmed")
            
    except Exception as e:
        logger.exception("PostgreSQL setup test failed", error=str(e))
        raise


def configure_celery() -> "Celery":
    """Configure Celery for background tasks."""
    if not HAS_CELERY:
        raise RuntimeError("Celery is not available")

    celery_config = settings.get_celery_config()

    celery_app = Celery("ezzday_backend")
    celery_app.config_from_object(celery_config)

    # Configure task routing for different modules
    celery_app.conf.task_routes = {
        "app.modules.notification.*": {"queue": "notifications"},
        "app.modules.audit.*": {"queue": "audit"},
        "app.modules.integration.*": {"queue": "integrations"},
        "app.modules.identity.*": {"queue": "identity"},
    }

    # Configure queues with priority support
    celery_app.conf.task_default_queue = "default"
    celery_app.conf.task_queues = (
        Queue("default", routing_key="default"),
        Queue("notifications", routing_key="notifications"),
        Queue("audit", routing_key="audit"),
        Queue("integrations", routing_key="integrations"),
        Queue("identity", routing_key="identity"),
        Queue("high_priority", routing_key="high_priority"),
    )

    logger.info(
        "Celery configured successfully",
        broker=celery_config["broker_url"],
        queues=len(celery_app.conf.task_queues),
    )

    return celery_app


def setup_shutdown_handlers(app: FastAPI) -> None:
    """Setup graceful shutdown signal handlers."""

    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, initiating graceful shutdown")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def _get_database_url_info() -> dict[str, str]:
    """Extract database connection information for logging (without credentials)."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(settings.database.url)
        return {
            "scheme": parsed.scheme,
            "host": parsed.hostname or "unknown",
            "port": str(parsed.port) if parsed.port else "default",
            "database": parsed.path.lstrip('/') if parsed.path else "unknown",
            "username": parsed.username or "unknown"
        }
    except Exception:
        return {"info": "unavailable"}


def create_app() -> FastAPI:
    """Create and configure FastAPI application with comprehensive middleware stack."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        debug=settings.DEBUG,
        lifespan=lifespan,
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
    )

    # Security headers middleware (add first for security)
    if settings.security.enable_security_headers:
        add_security_headers_middleware(app)

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Auth-Processing-Time"],
    )

    # Trusted host middleware for production
    if not settings.DEBUG:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.ALLOWED_HOSTS,
        )

    # Request ID middleware for tracing
    add_request_id_middleware(app)

    # Authentication middleware with module-aware configuration
    authenticator = CoreAuthenticator()
    app.add_middleware(
        AuthMiddleware,
        authenticator=authenticator,
        skip_paths=[
            "/health",
            "/health/db",
            "/health/cache",
            "/health/events",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/favicon.ico",
        ],
        require_auth_by_default=False,  # Let endpoints decide
    )

    # Rate limiting middleware
    app.add_middleware(RateLimitMiddleware)

    # Error handling middleware
    add_error_handling_middleware(app)

    # Logging middleware for audit
    add_logging_middleware(app)

    # Mount GraphQL with enhanced context
    try:
        schema = create_schema()

        async def context_getter(request, response=None):
            """Enhanced context getter that includes all necessary dependencies."""
            context = await get_context(request, response)

            # Add additional app-specific context
            context["event_bus"] = getattr(request.app.state, "event_bus", None)
            context["cache_manager"] = getattr(request.app.state, "cache_manager", None)

            return context

        graphql_app = GraphQLRouter(
            schema,
            graphiql=settings.DEBUG,
            context_getter=context_getter,
        )
        app.include_router(graphql_app, prefix="/graphql")

        logger.info(
            "GraphQL endpoint mounted successfully",
            path="/graphql",
            graphiql_enabled=settings.DEBUG,
        )

    except Exception as e:
        logger.exception("Failed to mount GraphQL endpoint", error=str(e))
        if settings.DEBUG:
            raise

    # Module API routers
    register_module_routes(app)

    # Mount Prometheus metrics
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

    # Comprehensive health check endpoints
    register_health_endpoints(app)

    # Admin and monitoring endpoints
    if settings.DEBUG or settings.ENVIRONMENT != Environment.PRODUCTION:
        register_admin_endpoints(app)

    # Instrument with OpenTelemetry
    if getattr(settings, "JAEGER_ENABLED", False):
        FastAPIInstrumentor.instrument_app(app)

    logger.info(
        "FastAPI application configured successfully",
        middleware_count=len(app.middleware_stack),
        environment=settings.ENVIRONMENT.value,
    )

    return app


def add_security_headers_middleware(app: FastAPI) -> None:
    """Add security headers middleware."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response

    class SecurityHeadersMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            response: Response = await call_next(request)

            # Security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

            # HSTS for HTTPS
            if request.url.scheme == "https":
                response.headers[
                    "Strict-Transport-Security"
                ] = f"max-age={settings.security.hsts_max_age_seconds}; includeSubDomains"

            # CSP if configured
            if settings.security.content_security_policy:
                response.headers[
                    "Content-Security-Policy"
                ] = settings.security.content_security_policy

            return response

    app.add_middleware(SecurityHeadersMiddleware)


def add_request_id_middleware(app: FastAPI) -> None:
    """Add request ID middleware for tracing."""
    import uuid

    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response

    class RequestIDMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
            request.state.request_id = request_id

            response: Response = await call_next(request)
            response.headers["X-Request-ID"] = request_id

            return response

    app.add_middleware(RequestIDMiddleware)


def add_error_handling_middleware(app: FastAPI) -> None:
    """Add comprehensive error handling middleware."""
    import traceback

    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    class ErrorHandlingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            try:
                return await call_next(request)
            except Exception as e:
                logger.exception(
                    "Unhandled error in request",
                    error=str(e),
                    path=request.url.path,
                    method=request.method,
                    request_id=getattr(request.state, "request_id", None),
                    traceback=traceback.format_exc(),
                )

                return JSONResponse(
                    status_code=500,
                    content={
                        "error": "Internal server error",
                        "message": str(e) if settings.DEBUG else "An error occurred",
                        "request_id": getattr(request.state, "request_id", None),
                    },
                )

    app.add_middleware(ErrorHandlingMiddleware)


def add_logging_middleware(app: FastAPI) -> None:
    """Add request/response logging middleware for audit."""
    import time

    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    class LoggingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            start_time = time.time()

            # Log request
            logger.info(
                "Request started",
                method=request.method,
                path=request.url.path,
                query_params=str(request.query_params),
                client_ip=request.client.host if request.client else None,
                user_agent=request.headers.get("User-Agent"),
                request_id=getattr(request.state, "request_id", None),
            )

            response = await call_next(request)

            process_time = time.time() - start_time

            # Log response
            logger.info(
                "Request completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                process_time_ms=round(process_time * 1000, 2),
                request_id=getattr(request.state, "request_id", None),
            )

            response.headers["X-Process-Time"] = str(process_time)
            return response

    app.add_middleware(LoggingMiddleware)


def register_module_routes(app: FastAPI) -> None:
    """Register API routes for all modules."""
    from fastapi import APIRouter

    # Create main API router
    api_router = APIRouter(prefix="/api/v1")

    # Import module routers (these would need to be implemented)
    try:
        from app.modules.identity.presentation.api import router as identity_router

        api_router.include_router(
            identity_router, prefix="/identity", tags=["identity"]
        )
    except ImportError:
        logger.warning("Identity API router not found")

    try:
        from app.modules.audit.presentation.api import router as audit_router

        api_router.include_router(audit_router, prefix="/audit", tags=["audit"])
    except ImportError:
        logger.warning("Audit API router not found")

    try:
        from app.modules.notification.presentation.api import (
            router as notification_router,
        )

        api_router.include_router(
            notification_router, prefix="/notifications", tags=["notifications"]
        )
    except ImportError:
        logger.warning("Notification API router not found")

    try:
        from app.modules.integration.presentation.api import (
            router as integration_router,
        )

        api_router.include_router(
            integration_router, prefix="/integrations", tags=["integrations"]
        )
    except ImportError:
        logger.warning("Integration API router not found")

    app.include_router(api_router)


def register_health_endpoints(app: FastAPI) -> None:
    """Register comprehensive health check endpoints."""

    @app.get("/health")
    async def health_check():
        """Basic health check."""
        return {
            "status": "healthy",
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT.value,
            "timestamp": "now",
        }

    @app.get("/health/db")
    async def database_health():
        """Database health check."""
        from app.core.database import check_database_health

        try:
            health_status = await check_database_health()
            return {
                "status": health_status["overall_status"],
                "component": "database",
                "details": health_status,
            }
        except Exception as e:
            logger.exception("Database health check failed", error=str(e))
            raise HTTPException(status_code=503, detail="Database unhealthy")

    @app.get("/health/cache")
    async def cache_health():
        """Cache health check."""
        try:
            # This would need cache_manager implementation
            if hasattr(app.state, "cache_manager"):
                await app.state.cache_manager.ping()
            return {"status": "healthy", "component": "cache"}
        except Exception as e:
            logger.exception("Cache health check failed", error=str(e))
            raise HTTPException(status_code=503, detail="Cache unhealthy")

    @app.get("/health/events")
    async def event_bus_health():
        """Event bus health check."""
        try:
            if hasattr(app.state, "event_bus"):
                is_healthy = (
                    app.state.event_bus.is_healthy()
                    if hasattr(app.state.event_bus, "is_healthy")
                    else True
                )
                if not is_healthy:
                    raise HTTPException(status_code=503, detail="Event bus unhealthy")
            return {"status": "healthy", "component": "event_bus"}
        except Exception as e:
            logger.exception("Event bus health check failed", error=str(e))
            raise HTTPException(status_code=503, detail="Event bus unhealthy")


def register_admin_endpoints(app: FastAPI) -> None:
    """Register admin and monitoring endpoints for non-production environments."""

    @app.get("/admin/stats")
    async def application_stats():
        """Get application statistics."""
        stats = {
            "app_name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT.value,
            "debug": settings.DEBUG,
        }

        # Add container stats if available
        if hasattr(app.state, "container"):
            stats["container"] = app.state.container.get_container_stats()

        # Add event bus stats if available
        if hasattr(app.state, "event_bus") and hasattr(
            app.state.event_bus, "get_statistics"
        ):
            stats["event_bus"] = app.state.event_bus.get_statistics()

        return stats

    @app.get("/admin/config")
    async def application_config():
        """Get application configuration (sanitized)."""
        return settings.to_dict(include_secrets=False)


app = create_app()

if __name__ == "__main__":
    import uvicorn

    # Get host from environment variable, default to localhost for security
    # Docker deployments will override these through environment variables
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    
    logger.info(
        "Starting EzzDay Backend server",
        host=host,
        port=port,
        environment=settings.ENVIRONMENT.value,
        database_url=str(settings.database.url).replace(
            str(settings.database.url).split('@')[0].split('//')[-1], '***'
        ) if '@' in str(settings.database.url) else "***",
        debug=settings.DEBUG
    )

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=settings.DEBUG,
        log_config=None,  # Use structlog
    )
