"""
Session Query Resolvers

GraphQL query resolvers for session-related operations including:
- Single session and session listing with filtering/pagination
- Active sessions and session history
- Suspicious session detection and analysis
"""

import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
class SessionFilterInput(FilterInput):
    """Advanced filtering options for session queries."""
    user_id: UUID | None = None
    is_active: bool | None = None
    device_type: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    location: str | None = None
    is_suspicious: bool | None = None
    last_activity_after: datetime | None = None
    last_activity_before: datetime | None = None
    duration_minutes_min: int | None = None
    duration_minutes_max: int | None = None


@strawberry.input
class SessionSortInput(SortInput):
    """Sorting options for session queries."""
    # Uses base sort fields (field, direction)


@dataclass
class SessionSummary:
    """Session summary information."""
    total_sessions: int
    active_sessions: int
    expired_sessions: int
    suspicious_sessions: int
    average_duration_minutes: float
    unique_users: int
    unique_ip_addresses: int
    most_common_device_type: str


@strawberry.type
class SessionSummaryType:
    """GraphQL type for session summary."""
    total_sessions: int
    active_sessions: int
    expired_sessions: int
    suspicious_sessions: int
    average_duration_minutes: float
    unique_users: int
    unique_ip_addresses: int
    most_common_device_type: str


class SessionQueries(BaseQueryResolver):
    """GraphQL query resolvers for session operations."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dataloaders: IdentityDataLoaders | None = None
    
    def set_dataloaders(self, dataloaders: IdentityDataLoaders):
        """Set DataLoaders for this resolver."""
        self.dataloaders = dataloaders
    
    async def session(self, info: Info, id: UUID) -> dict | None:
        """
        Get a single session by ID.
        
        Requires either:
        - User accessing their own session
        - 'session:read' permission
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Use DataLoader if available
            if self.dataloaders:
                session = await self.dataloaders.session_loader.load(id)
            else:
                result = await self.session_repository.find_by_id(id)
                session = await self.handle_repository_result(result)
            
            if not session:
                raise NotFoundError("Session not found", "Session")
            
            # Check authorization
            self.require_self_or_permission(context, session.user_id, "session:read")
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "session", {"id": str(id)}, execution_time
            )
            
            return session
            
        except Exception as e:
            self.logger.exception(f"Error in session query: {e}")
            raise
    
    async def sessions(
        self,
        info: Info,
        filter: SessionFilterInput | None = None,
        sort: SessionSortInput | None = None,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get a list of sessions with filtering, sorting, and pagination.
        
        Requires 'session:list' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "session:list")
            
            # Validate input
            pagination = self.validate_pagination(pagination)
            sort = self.validate_sort(sort, [
                "created_at", "updated_at", "last_activity", "expires_at", "duration"
            ])
            
            # Build query parameters
            query_params = {}
            if filter:
                if filter.user_id:
                    query_params["user_id"] = filter.user_id
                if filter.is_active is not None:
                    query_params["is_active"] = filter.is_active
                if filter.device_type:
                    query_params["device_type"] = filter.device_type
                if filter.ip_address:
                    query_params["ip_address"] = filter.ip_address
                if filter.user_agent:
                    query_params["user_agent"] = filter.user_agent
                if filter.location:
                    query_params["location"] = filter.location
                if filter.is_suspicious is not None:
                    query_params["is_suspicious"] = filter.is_suspicious
                if filter.last_activity_after:
                    query_params["last_activity_after"] = filter.last_activity_after
                if filter.last_activity_before:
                    query_params["last_activity_before"] = filter.last_activity_before
                if filter.duration_minutes_min:
                    query_params["duration_minutes_min"] = filter.duration_minutes_min
                if filter.duration_minutes_max:
                    query_params["duration_minutes_max"] = filter.duration_minutes_max
            
            # Execute query
            result = await self.session_repository.find_with_filters(
                filters=query_params,
                sort_field=sort.field if sort else "created_at",
                sort_direction=sort.direction if sort else "DESC",
                limit=pagination.limit,
                offset=pagination.offset
            )
            
            sessions = await self.handle_repository_result(result)
            
            # Get total count for pagination
            count_result = await self.session_repository.count_with_filters(query_params)
            total_count = await self.handle_repository_result(count_result)
            
            # Build connection
            edges = [
                Edge(node=session, cursor=str(session.id))
                for session in sessions
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(sessions) < total_count,
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
                context, "sessions", {
                    "filter": filter.__dict__ if filter else None,
                    "sort": sort.__dict__ if sort else None,
                    "pagination": pagination.__dict__,
                    "result_count": len(sessions)
                }, execution_time
            )
            
            return connection
            
        except Exception as e:
            self.logger.exception(f"Error in sessions query: {e}")
            raise
    
    async def active_sessions(
        self,
        info: Info,
        user_id: UUID | None = None,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get active sessions, optionally filtered by user.
        
        Requires either:
        - User accessing their own sessions
        - 'session:list' permission for all sessions
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Determine authorization requirements
            if user_id:
                # Accessing specific user's sessions
                self.require_self_or_permission(context, user_id, "session:list")
            else:
                # Accessing all active sessions
                self.require_permission(context, "session:list")
            
            # Validate pagination
            pagination = self.validate_pagination(pagination)
            
            # Build filter for active sessions
            now = datetime.now(UTC)
            query_params = {
                "is_active": True,
                "expires_at_after": now
            }
            
            if user_id:
                query_params["user_id"] = user_id
            
            # Execute query
            result = await self.session_repository.find_with_filters(
                filters=query_params,
                sort_field="last_activity",
                sort_direction="DESC",
                limit=pagination.limit,
                offset=pagination.offset
            )
            
            sessions = await self.handle_repository_result(result)
            
            # Get total count
            count_result = await self.session_repository.count_with_filters(query_params)
            total_count = await self.handle_repository_result(count_result)
            
            # Build connection
            edges = [
                Edge(node=session, cursor=str(session.id))
                for session in sessions
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(sessions) < total_count,
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
                context, "activeSessions", {
                    "user_id": str(user_id) if user_id else None,
                    "pagination": pagination.__dict__,
                    "result_count": len(sessions)
                }, execution_time
            )
            
            return connection
            
        except Exception as e:
            self.logger.exception(f"Error in activeSessions query: {e}")
            raise
    
    async def session_history(
        self,
        info: Info,
        user_id: UUID,
        days: int = 30,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get session history for a user.
        
        Requires either:
        - User accessing their own session history
        - 'session:history:read' permission
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_self_or_permission(context, user_id, "session:history:read")
            
            # Validate input
            if days <= 0 or days > 365:
                raise ValidationError("Days must be between 1 and 365")
            
            pagination = self.validate_pagination(pagination)
            
            # Build filter for session history
            cutoff_date = datetime.now(UTC) - timedelta(days=days)
            query_params = {
                "user_id": user_id,
                "created_at_after": cutoff_date
            }
            
            # Execute query
            result = await self.session_repository.find_with_filters(
                filters=query_params,
                sort_field="created_at",
                sort_direction="DESC",
                limit=pagination.limit,
                offset=pagination.offset
            )
            
            sessions = await self.handle_repository_result(result)
            
            # Get total count
            count_result = await self.session_repository.count_with_filters(query_params)
            total_count = await self.handle_repository_result(count_result)
            
            # Build connection
            edges = [
                Edge(node=session, cursor=str(session.id))
                for session in sessions
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(sessions) < total_count,
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
                context, "sessionHistory", {
                    "user_id": str(user_id),
                    "days": days,
                    "pagination": pagination.__dict__,
                    "result_count": len(sessions)
                }, execution_time
            )
            
            return connection
            
        except Exception as e:
            self.logger.exception(f"Error in sessionHistory query: {e}")
            raise
    
    async def suspicious_sessions(
        self,
        info: Info,
        severity_threshold: float = 0.7,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get sessions flagged as suspicious.
        
        Requires 'security:sessions:read' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "security:sessions:read")
            
            # Validate input
            if severity_threshold < 0.0 or severity_threshold > 1.0:
                raise ValidationError("Severity threshold must be between 0.0 and 1.0")
            
            pagination = self.validate_pagination(pagination)
            
            # Build filter for suspicious sessions
            query_params = {
                "is_suspicious": True,
                "risk_score_min": severity_threshold
            }
            
            # Execute query
            result = await self.session_repository.find_with_filters(
                filters=query_params,
                sort_field="risk_score",
                sort_direction="DESC",
                limit=pagination.limit,
                offset=pagination.offset
            )
            
            sessions = await self.handle_repository_result(result)
            
            # Get total count
            count_result = await self.session_repository.count_with_filters(query_params)
            total_count = await self.handle_repository_result(count_result)
            
            # Build connection
            edges = [
                Edge(node=session, cursor=str(session.id))
                for session in sessions
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(sessions) < total_count,
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
                context, "suspiciousSessions", {
                    "severity_threshold": severity_threshold,
                    "pagination": pagination.__dict__,
                    "result_count": len(sessions)
                }, execution_time
            )
            
            return connection
            
        except Exception as e:
            self.logger.exception(f"Error in suspiciousSessions query: {e}")
            raise