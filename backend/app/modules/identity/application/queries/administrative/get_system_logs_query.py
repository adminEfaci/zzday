"""Get system logs query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.repositories.audit_repository import IAuditRepository
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import SystemLogsResponse


class LogLevel(Enum):
    """Log level enumeration."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class GetSystemLogsQuery(Query[SystemLogsResponse]):
    """Query to get system logs."""
    
    log_types: list[str] | None = None
    log_levels: list[LogLevel] | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    search_term: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    page: int = 1
    page_size: int = 50
    requester_permissions: list[str] = field(default_factory=list)


class GetSystemLogsQueryHandler(QueryHandler[GetSystemLogsQuery, SystemLogsResponse]):
    """Handler for system logs queries."""
    
    def __init__(self, uow: UnitOfWork, audit_repository: IAuditRepository):
        self.uow = uow
        self.audit_repository = audit_repository
    
    @rate_limit(max_calls=30, window_seconds=60)
    @require_permission("admin.logs.read")
    @validate_request
    async def handle(self, query: GetSystemLogsQuery) -> SystemLogsResponse:
        """Handle system logs query."""
        
        async with self.uow:
            # Build filters
            filters = self._build_filters(query)
            
            # Search logs
            log_results = await self.audit_repository.search_logs(
                filters,
                page=query.page,
                page_size=query.page_size
            )
            
            # Format logs for response
            formatted_logs = []
            for log in log_results.items:
                formatted_logs.append({
                    "id": str(log.id),
                    "timestamp": log.created_at.isoformat(),
                    "level": self._determine_log_level(log),
                    "type": log.resource_type,
                    "action": log.action,
                    "user_id": str(log.user_id) if log.user_id else None,
                    "actor_id": str(log.actor_id) if log.actor_id else None,
                    "session_id": str(log.session_id) if log.session_id else None,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent,
                    "resource": f"{log.resource_type}:{log.resource_id}" if log.resource_id else log.resource_type,
                    "details": log.details,
                    "correlation_id": log.details.get("correlation_id"),
                    "duration_ms": log.details.get("duration_ms"),
                    "error": log.details.get("error")
                })
            
            # Get log statistics
            statistics = await self._get_log_statistics(filters)
            
            return SystemLogsResponse(
                logs=formatted_logs,
                total_count=log_results.total_count,
                page=query.page,
                page_size=query.page_size,
                has_next=log_results.has_next,
                statistics=statistics,
                filters_applied=self._get_applied_filters(query),
                retrieved_at=datetime.now(UTC)
            )
    
    def _build_filters(self, query: GetSystemLogsQuery) -> dict[str, Any]:
        """Build filters for log search."""
        filters = {}
        
        if query.start_date:
            filters["start_date"] = query.start_date
        if query.end_date:
            filters["end_date"] = query.end_date
        
        if query.log_types:
            filters["resource_type__in"] = query.log_types
        
        if query.user_id:
            filters["user_id"] = query.user_id
        
        if query.session_id:
            filters["session_id"] = query.session_id
        
        if query.search_term:
            filters["search"] = query.search_term
        
        # Filter by log level if specified
        if query.log_levels:
            # Map log levels to action patterns
            level_patterns = []
            for level in query.log_levels:
                if level == LogLevel.ERROR:
                    level_patterns.extend(["failed", "error", "exception"])
                elif level == LogLevel.WARNING:
                    level_patterns.extend(["warning", "deprecated", "slow"])
                elif level == LogLevel.CRITICAL:
                    level_patterns.extend(["critical", "fatal", "emergency"])
            
            if level_patterns:
                filters["action__in"] = level_patterns
        
        return filters
    
    def _determine_log_level(self, log) -> str:
        """Determine log level from audit log."""
        action_lower = log.action.lower()
        
        # Check for error indicators
        if any(word in action_lower for word in ["fail", "error", "exception"]) or log.details.get("error"):
            return LogLevel.ERROR.value
        
        # Check for warning indicators
        if any(word in action_lower for word in ["warning", "deprecated", "slow"]) or log.details.get("risk_level") == "high":
            return LogLevel.WARNING.value
        
        # Check for critical indicators
        if any(word in action_lower for word in ["critical", "fatal", "breach"]):
            return LogLevel.CRITICAL.value
        
        # Check for debug indicators
        if any(word in action_lower for word in ["debug", "trace"]):
            return LogLevel.DEBUG.value
        
        # Default to info
        return LogLevel.INFO.value
    
    async def _get_log_statistics(self, filters: dict[str, Any]) -> dict[str, Any]:
        """Get log statistics."""
        # Get time range from filters or default
        start_date = filters.get("start_date", datetime.now(UTC).replace(hour=0, minute=0, second=0))
        end_date = filters.get("end_date", datetime.now(UTC))
        
        # Get audit statistics
        stats = await self.audit_repository.get_audit_statistics(filters)
        
        # Get breakdown by type
        breakdown = await self.audit_repository.get_activity_breakdown_by_type(
            start_date,
            end_date
        )
        
        return {
            "total_logs": stats.get("total", 0),
            "by_level": {
                "debug": stats.get("debug_count", 0),
                "info": stats.get("info_count", 0),
                "warning": stats.get("warning_count", 0),
                "error": stats.get("error_count", 0),
                "critical": stats.get("critical_count", 0)
            },
            "by_type": breakdown,
            "unique_users": stats.get("unique_users", 0),
            "unique_sessions": stats.get("unique_sessions", 0),
            "error_rate": stats.get("error_rate", 0),
            "peak_hour": stats.get("peak_hour"),
            "top_actions": stats.get("top_actions", [])[:10]
        }
    
    def _get_applied_filters(self, query: GetSystemLogsQuery) -> dict[str, Any]:
        """Get summary of applied filters."""
        applied = {}
        
        if query.log_types:
            applied["types"] = query.log_types
        if query.log_levels:
            applied["levels"] = [level.value for level in query.log_levels]
        if query.start_date:
            applied["start_date"] = query.start_date.isoformat()
        if query.end_date:
            applied["end_date"] = query.end_date.isoformat()
        if query.search_term:
            applied["search"] = query.search_term
        if query.user_id:
            applied["user_id"] = query.user_id
        if query.session_id:
            applied["session_id"] = query.session_id
        
        return applied