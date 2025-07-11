"""Get system health query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import SystemHealthResponse
from app.modules.identity.domain.interfaces.repositories.audit_repository import (
    IAuditRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)


@dataclass
class GetSystemHealthQuery(Query[SystemHealthResponse]):
    """Query to get system health status."""
    
    include_detailed_checks: bool = True
    requester_permissions: list[str] = field(default_factory=list)


class GetSystemHealthQueryHandler(QueryHandler[GetSystemHealthQuery, SystemHealthResponse]):
    """Handler for system health queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        audit_repository: IAuditRepository,
        config_service: IConfigurationPort,
        cache_service: ICachePort
    ):
        self.uow = uow
        self.user_repository = user_repository
        self.session_repository = session_repository
        self.audit_repository = audit_repository
        self.config_service = config_service
        self.cache_service = cache_service
    
    @rate_limit(max_calls=200, window_seconds=60)
    @require_permission("admin.health.read")
    @validate_request
    async def handle(self, query: GetSystemHealthQuery) -> SystemHealthResponse:
        """Handle system health query."""
        
        async with self.uow:
            health_checks = {}
            overall_status = "healthy"
            
            # Database health check
            try:
                db_start = datetime.now(UTC)
                await self.user_repository.count_users({})
                db_latency = (datetime.now(UTC) - db_start).total_seconds() * 1000
                health_checks["database"] = {
                    "status": "healthy" if db_latency < 100 else "degraded",
                    "latency_ms": db_latency,
                    "message": "Database connection is operational"
                }
            except Exception as e:
                health_checks["database"] = {
                    "status": "unhealthy",
                    "error": str(e),
                    "message": "Database connection failed"
                }
                overall_status = "unhealthy"
            
            # Cache health check
            try:
                cache_key = f"health_check_{datetime.now(UTC).timestamp()}"
                await self.cache_service.set_user_cache(None, cache_key, "test", 10)
                cache_value = await self.cache_service.get_user_cache(None, cache_key)
                health_checks["cache"] = {
                    "status": "healthy" if cache_value == "test" else "degraded",
                    "message": "Cache service is operational"
                }
            except Exception as e:
                health_checks["cache"] = {
                    "status": "unhealthy",
                    "error": str(e),
                    "message": "Cache service unavailable"
                }
                if overall_status != "unhealthy":
                    overall_status = "degraded"
            
            if query.include_detailed_checks:
                # Session statistics
                try:
                    active_sessions = await self.session_repository.count_user_sessions(
                        user_id=None,
                        active_only=True
                    )
                    health_checks["sessions"] = {
                        "status": "healthy",
                        "active_count": active_sessions,
                        "message": "Session management operational"
                    }
                except Exception as e:
                    health_checks["sessions"] = {
                        "status": "degraded",
                        "error": str(e)
                    }
                
                # Audit system check
                try:
                    recent_events = await self.audit_repository.count_events(
                        datetime.now(UTC).replace(hour=0, minute=0, second=0),
                        datetime.now(UTC)
                    )
                    health_checks["audit"] = {
                        "status": "healthy",
                        "events_today": recent_events,
                        "message": "Audit system operational"
                    }
                except Exception as e:
                    health_checks["audit"] = {
                        "status": "degraded",
                        "error": str(e)
                    }
                
                # Configuration check
                try:
                    await self.config_service.get_password_policy()
                    health_checks["configuration"] = {
                        "status": "healthy",
                        "message": "Configuration service operational"
                    }
                except Exception as e:
                    health_checks["configuration"] = {
                        "status": "unhealthy",
                        "error": str(e)
                    }
                    if overall_status != "unhealthy":
                        overall_status = "degraded"
            
            # Calculate uptime
            system_start_time = await self._get_system_start_time()
            uptime_seconds = (datetime.now(UTC) - system_start_time).total_seconds()
            
            return SystemHealthResponse(
                status=overall_status,
                components=health_checks,
                uptime_seconds=int(uptime_seconds),
                version="1.0.0",  # This should come from config
                checked_at=datetime.now(UTC)
            )
    
    async def _get_system_start_time(self) -> datetime:
        """Get system start time from cache or default."""
        start_time = await self.cache_service.get_user_cache(None, "system_start_time")
        if not start_time:
            start_time = datetime.now(UTC)
            await self.cache_service.set_user_cache(None, "system_start_time", start_time)
        return start_time