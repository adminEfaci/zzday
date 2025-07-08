"""
Security Query Resolvers

GraphQL query resolvers for security-related operations including:
- Security events and audit logs
- Login attempts and authentication events
- Security statistics and analytics
- Threat intelligence and risk assessment
"""

import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import strawberry
from strawberry.types import Info

from .base_query_resolver import (
    BaseQueryResolver,
    Connection,
    Edge,
    FilterInput,
    NotFoundError,
    PageInfo,
    PaginationInput,
    SortInput,
    ValidationError,
)
from .dataloaders import IdentityDataLoaders


@strawberry.input
class SecurityEventFilterInput(FilterInput):
    """Advanced filtering options for security event queries."""
    user_id: UUID | None = None
    event_type: str | None = None
    severity: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    resource: str | None = None
    action: str | None = None
    status: str | None = None
    risk_score_min: float | None = None
    risk_score_max: float | None = None


@strawberry.input
class AuditLogFilterInput(FilterInput):
    """Advanced filtering options for audit log queries."""
    user_id: UUID | None = None
    entity_type: str | None = None
    entity_id: UUID | None = None
    action: str | None = None
    source_ip: str | None = None
    session_id: str | None = None
    success: bool | None = None


@strawberry.input
class LoginAttemptFilterInput(FilterInput):
    """Advanced filtering options for login attempt queries."""
    user_id: UUID | None = None
    email: str | None = None
    username: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    success: bool | None = None
    failure_reason: str | None = None
    is_suspicious: bool | None = None


@strawberry.input
class SecurityEventSortInput(SortInput):
    """Sorting options for security event queries."""
    # Uses base sort fields (field, direction)


@strawberry.input
class AuditLogSortInput(SortInput):
    """Sorting options for audit log queries."""
    # Uses base sort fields (field, direction)


@strawberry.input
class LoginAttemptSortInput(SortInput):
    """Sorting options for login attempt queries."""
    # Uses base sort fields (field, direction)


@dataclass
class SecurityStatistics:
    """Security statistics data."""
    total_security_events: int
    high_severity_events: int
    medium_severity_events: int
    low_severity_events: int
    successful_logins_today: int
    failed_logins_today: int
    blocked_ips_count: int
    suspicious_activities_count: int
    average_risk_score: float
    top_threat_types: list[dict[str, Any]]
    geographic_distribution: list[dict[str, Any]]


@strawberry.type
class ThreatType:
    """GraphQL type for threat type statistics."""
    type: str
    count: int
    percentage: float


@strawberry.type
class GeographicLocation:
    """GraphQL type for geographic distribution."""
    country: str
    region: str
    count: int
    percentage: float


@strawberry.type
class SecurityStatisticsType:
    """GraphQL type for security statistics."""
    total_security_events: int
    high_severity_events: int
    medium_severity_events: int
    low_severity_events: int
    successful_logins_today: int
    failed_logins_today: int
    blocked_ips_count: int
    suspicious_activities_count: int
    average_risk_score: float
    top_threat_types: list[ThreatType]
    geographic_distribution: list[GeographicLocation]


class SecurityQueries(BaseQueryResolver):
    """GraphQL query resolvers for security operations."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dataloaders: IdentityDataLoaders | None = None
    
    def set_dataloaders(self, dataloaders: IdentityDataLoaders):
        """Set DataLoaders for this resolver."""
        self.dataloaders = dataloaders
    
    async def security_event(self, info: Info, id: UUID) -> dict | None:
        """
        Get a single security event by ID.
        
        Requires 'security:events:read' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "security:events:read")
            
            # Get security event
            result = await self.security_event_repository.find_by_id(id)
            event = await self.handle_repository_result(result)
            
            if not event:
                raise NotFoundError("Security event not found", "SecurityEvent")
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "securityEvent", {"id": str(id)}, execution_time
            )
            
            return event
            
        except Exception as e:
            self.logger.exception(f"Error in securityEvent query: {e}")
            raise
    
    async def security_events(
        self,
        info: Info,
        filter: SecurityEventFilterInput | None = None,
        sort: SecurityEventSortInput | None = None,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get a list of security events with filtering, sorting, and pagination.
        
        Requires 'security:events:read' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "security:events:read")
            
            # Validate input
            pagination = self.validate_pagination(pagination)
            sort = self.validate_sort(sort, [
                "created_at", "updated_at", "event_type", "severity", "risk_score"
            ])
            
            # Build query parameters
            query_params = {}
            if filter:
                if filter.user_id:
                    query_params["user_id"] = filter.user_id
                if filter.event_type:
                    query_params["event_type"] = filter.event_type
                if filter.severity:
                    query_params["severity"] = filter.severity
                if filter.source_ip:
                    query_params["source_ip"] = filter.source_ip
                if filter.user_agent:
                    query_params["user_agent"] = filter.user_agent
                if filter.resource:
                    query_params["resource"] = filter.resource
                if filter.action:
                    query_params["action"] = filter.action
                if filter.status:
                    query_params["status"] = filter.status
                if filter.risk_score_min is not None:
                    query_params["risk_score_min"] = filter.risk_score_min
                if filter.risk_score_max is not None:
                    query_params["risk_score_max"] = filter.risk_score_max
            
            # Execute query
            result = await self.security_event_repository.find_with_filters(
                filters=query_params,
                sort_field=sort.field if sort else "created_at",
                sort_direction=sort.direction if sort else "DESC",
                limit=pagination.limit,
                offset=pagination.offset
            )
            
            events = await self.handle_repository_result(result)
            
            # Get total count for pagination
            count_result = await self.security_event_repository.count_with_filters(query_params)
            total_count = await self.handle_repository_result(count_result)
            
            # Build connection
            edges = [
                Edge(node=event, cursor=str(event.id))
                for event in events
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(events) < total_count,
                has_previous_page=pagination.offset > 0,
                start_cursor=edges[0].cursor if edges else None,
                end_cursor=edges[-1].cursor if edges else None,
                total_count=total_count
            )
            
            connection = Connection(
                edges=edges,
                page_info=page_info,
                total_count=total_count
            )
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "securityEvents", {
                    "filter": filter.__dict__ if filter else None,
                    "sort": sort.__dict__ if sort else None,
                    "pagination": pagination.__dict__,
                    "result_count": len(events)
                }, execution_time
            )
            
            return connection
            
        except Exception as e:
            self.logger.exception(f"Error in securityEvents query: {e}")
            raise
    
    async def audit_log(
        self,
        info: Info,
        filter: AuditLogFilterInput | None = None,
        sort: AuditLogSortInput | None = None,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get audit log entries with filtering, sorting, and pagination.
        
        Requires 'audit:read' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "audit:read")
            
            # Validate input
            pagination = self.validate_pagination(pagination)
            sort = self.validate_sort(sort, [
                "created_at", "updated_at", "action", "entity_type", "user_id"
            ])
            
            # Build query parameters
            query_params = {}
            if filter:
                if filter.user_id:
                    query_params["user_id"] = filter.user_id
                if filter.entity_type:
                    query_params["entity_type"] = filter.entity_type
                if filter.entity_id:
                    query_params["entity_id"] = filter.entity_id
                if filter.action:
                    query_params["action"] = filter.action
                if filter.source_ip:
                    query_params["source_ip"] = filter.source_ip
                if filter.session_id:
                    query_params["session_id"] = filter.session_id
                if filter.success is not None:
                    query_params["success"] = filter.success
            
            # Use security event repository for audit logs
            # (assuming audit logs are a type of security event)
            result = await self.security_event_repository.find_audit_logs(
                filters=query_params,
                sort_field=sort.field if sort else "created_at",
                sort_direction=sort.direction if sort else "DESC",
                limit=pagination.limit,
                offset=pagination.offset
            )
            
            logs = await self.handle_repository_result(result)
            
            # Get total count for pagination
            count_result = await self.security_event_repository.count_audit_logs(query_params)
            total_count = await self.handle_repository_result(count_result)
            
            # Build connection
            edges = [
                Edge(node=log, cursor=str(log.id))
                for log in logs
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(logs) < total_count,
                has_previous_page=pagination.offset > 0,
                start_cursor=edges[0].cursor if edges else None,
                end_cursor=edges[-1].cursor if edges else None,
                total_count=total_count
            )
            
            connection = Connection(
                edges=edges,
                page_info=page_info,
                total_count=total_count
            )
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "auditLog", {
                    "filter": filter.__dict__ if filter else None,
                    "sort": sort.__dict__ if sort else None,
                    "pagination": pagination.__dict__,
                    "result_count": len(logs)
                }, execution_time
            )
            
            return connection
            
        except Exception as e:
            self.logger.exception(f"Error in auditLog query: {e}")
            raise
    
    async def login_attempts(
        self,
        info: Info,
        filter: LoginAttemptFilterInput | None = None,
        sort: LoginAttemptSortInput | None = None,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get login attempts with filtering, sorting, and pagination.
        
        Requires 'security:login_attempts:read' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "security:login_attempts:read")
            
            # Validate input
            pagination = self.validate_pagination(pagination)
            sort = self.validate_sort(sort, [
                "created_at", "updated_at", "email", "username", "source_ip", "success"
            ])
            
            # Build query parameters
            query_params = {}
            if filter:
                if filter.user_id:
                    query_params["user_id"] = filter.user_id
                if filter.email:
                    query_params["email"] = filter.email
                if filter.username:
                    query_params["username"] = filter.username
                if filter.source_ip:
                    query_params["source_ip"] = filter.source_ip
                if filter.user_agent:
                    query_params["user_agent"] = filter.user_agent
                if filter.success is not None:
                    query_params["success"] = filter.success
                if filter.failure_reason:
                    query_params["failure_reason"] = filter.failure_reason
                if filter.is_suspicious is not None:
                    query_params["is_suspicious"] = filter.is_suspicious
            
            # Get login attempts from login attempt repository
            
            # This would need to be injected properly
            # For now, we'll use security event repository as a fallback
            result = await self.security_event_repository.find_login_attempts(
                filters=query_params,
                sort_field=sort.field if sort else "created_at",
                sort_direction=sort.direction if sort else "DESC",
                limit=pagination.limit,
                offset=pagination.offset
            )
            
            attempts = await self.handle_repository_result(result)
            
            # Get total count for pagination
            count_result = await self.security_event_repository.count_login_attempts(query_params)
            total_count = await self.handle_repository_result(count_result)
            
            # Build connection
            edges = [
                Edge(node=attempt, cursor=str(attempt.id))
                for attempt in attempts
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(attempts) < total_count,
                has_previous_page=pagination.offset > 0,
                start_cursor=edges[0].cursor if edges else None,
                end_cursor=edges[-1].cursor if edges else None,
                total_count=total_count
            )
            
            connection = Connection(
                edges=edges,
                page_info=page_info,
                total_count=total_count
            )
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "loginAttempts", {
                    "filter": filter.__dict__ if filter else None,
                    "sort": sort.__dict__ if sort else None,
                    "pagination": pagination.__dict__,
                    "result_count": len(attempts)
                }, execution_time
            )
            
            return connection
            
        except Exception as e:
            self.logger.exception(f"Error in loginAttempts query: {e}")
            raise
    
    async def security_statistics(
        self,
        info: Info,
        days: int = 30
    ) -> SecurityStatisticsType:
        """
        Get security statistics for a specified time period.
        
        Requires 'security:statistics:read' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "security:statistics:read")
            
            # Validate input
            if days <= 0 or days > 365:
                raise ValidationError("Days must be between 1 and 365")
            
            # Get security statistics
            stats_result = await self.security_event_repository.get_security_statistics(days)
            stats = await self.handle_repository_result(stats_result)
            
            # Convert threat types to GraphQL types
            threat_types = [
                ThreatType(
                    type=threat["type"],
                    count=threat["count"],
                    percentage=threat["percentage"]
                )
                for threat in stats.top_threat_types
            ]
            
            # Convert geographic distribution to GraphQL types
            geographic_dist = [
                GeographicLocation(
                    country=location["country"],
                    region=location["region"],
                    count=location["count"],
                    percentage=location["percentage"]
                )
                for location in stats.geographic_distribution
            ]
            
            # Create result
            security_stats = SecurityStatisticsType(
                total_security_events=stats.total_security_events,
                high_severity_events=stats.high_severity_events,
                medium_severity_events=stats.medium_severity_events,
                low_severity_events=stats.low_severity_events,
                successful_logins_today=stats.successful_logins_today,
                failed_logins_today=stats.failed_logins_today,
                blocked_ips_count=stats.blocked_ips_count,
                suspicious_activities_count=stats.suspicious_activities_count,
                average_risk_score=stats.average_risk_score,
                top_threat_types=threat_types,
                geographic_distribution=geographic_dist
            )
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "securityStatistics", {"days": days}, execution_time
            )
            
            return security_stats
            
        except Exception as e:
            self.logger.exception(f"Error in securityStatistics query: {e}")
            raise