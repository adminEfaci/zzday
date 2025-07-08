"""
User Query Resolvers

Comprehensive GraphQL query resolvers for user-related operations including:
- Single user and user listing with filtering/pagination
- User profile and preferences
- User sessions, roles, and permissions
- User audit logs and statistics
"""

import time
from dataclasses import dataclass
from datetime import datetime
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
)
from .dataloaders import IdentityDataLoaders


@strawberry.input
class UserFilterInput(FilterInput):
    """Advanced filtering options for user queries."""
    email: str | None = None
    username: str | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    role_ids: list[UUID] | None = None
    has_mfa: bool | None = None
    last_login_after: datetime | None = None
    last_login_before: datetime | None = None
    registration_source: str | None = None
    account_status: str | None = None


@strawberry.input
class UserSortInput(SortInput):
    """Sorting options for user queries."""
    # Uses base sort fields (field, direction)


@dataclass
class UserStatistics:
    """User statistics data."""
    total_users: int
    active_users: int
    verified_users: int
    users_with_mfa: int
    new_users_today: int
    new_users_this_week: int
    new_users_this_month: int
    login_count_today: int
    average_session_duration: float


@strawberry.type
class UserStatisticsType:
    """GraphQL type for user statistics."""
    total_users: int
    active_users: int
    verified_users: int
    users_with_mfa: int
    new_users_today: int
    new_users_this_week: int
    new_users_this_month: int
    login_count_today: int
    average_session_duration: float


class UserQueries(BaseQueryResolver):
    """GraphQL query resolvers for user operations."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dataloaders: IdentityDataLoaders | None = None
    
    def set_dataloaders(self, dataloaders: IdentityDataLoaders):
        """Set DataLoaders for this resolver."""
        self.dataloaders = dataloaders
    
    def _raise_user_not_found(self) -> None:
        """Raise NotFoundError for user not found."""
        raise NotFoundError("User not found", "User")
    
    def _raise_current_user_not_found(self) -> None:
        """Raise NotFoundError for current user not found."""
        raise NotFoundError("Current user not found", "User")
    
    def _raise_profile_not_found(self) -> None:
        """Raise NotFoundError for user profile not found."""
        raise NotFoundError("User profile not found", "UserProfile")
    
    def _raise_preferences_not_found(self) -> None:
        """Raise NotFoundError for user preferences not found."""
        raise NotFoundError("User preferences not found", "UserPreferences")
    
    async def user(self, info: Info, user_id: UUID) -> dict | None:
        """
        Get a single user by ID.
        
        Requires either:
        - User accessing their own data
        - 'user:read' permission for other users
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_self_or_permission(context, user_id, "user:read")
            
            # Use DataLoader if available
            if self.dataloaders:
                user = await self.dataloaders.user_loader.load(user_id)
            else:
                result = await self.user_repository.find_by_id(user_id)
                user = await self.handle_repository_result(result)
            
            if not user:
                self._raise_user_not_found()
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "user", {"id": str(user_id)}, execution_time
            )
            
        except Exception:
            self.logger.exception("Error in user query")
            raise
        else:
            return user
    
    async def users(
        self,
        info: Info,
        user_filter: UserFilterInput | None = None,
        sort: UserSortInput | None = None,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get a list of users with filtering, sorting, and pagination.
        
        Requires 'user:list' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "user:list")
            
            # Validate input
            pagination = self.validate_pagination(pagination)
            sort = self.validate_sort(sort, [
                "created_at", "updated_at", "email", "username", 
                "last_login", "display_name"
            ])
            
            # Build query parameters
            query_params = {}
            if filter:
                if filter.email:
                    query_params["email"] = filter.email
                if filter.username:
                    query_params["username"] = filter.username
                if filter.is_active is not None:
                    query_params["is_active"] = filter.is_active
                if filter.is_verified is not None:
                    query_params["is_verified"] = filter.is_verified
                if filter.role_ids:
                    query_params["role_ids"] = filter.role_ids
                if filter.has_mfa is not None:
                    query_params["has_mfa"] = filter.has_mfa
                if filter.last_login_after:
                    query_params["last_login_after"] = filter.last_login_after
                if filter.last_login_before:
                    query_params["last_login_before"] = filter.last_login_before
                if filter.registration_source:
                    query_params["registration_source"] = filter.registration_source
                if filter.account_status:
                    query_params["account_status"] = filter.account_status
            
            # Execute query
            result = await self.user_repository.find_with_filters(
                filters=query_params,
                sort_field=sort.field if sort else "created_at",
                sort_direction=sort.direction if sort else "DESC",
                limit=pagination.limit,
                offset=pagination.offset
            )
            
            users = await self.handle_repository_result(result)
            
            # Get total count for pagination
            count_result = await self.user_repository.count_with_filters(query_params)
            total_count = await self.handle_repository_result(count_result)
            
            # Build connection
            edges = [
                Edge(node=user, cursor=str(user.id))
                for user in users
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(users) < total_count,
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
                context, "users", {
                    "filter": filter.__dict__ if filter else None,
                    "sort": sort.__dict__ if sort else None,
                    "pagination": pagination.__dict__,
                    "result_count": len(users)
                }, execution_time
            )
            
        except Exception:
            self.logger.exception("Error in users query")
            raise
        else:
            return connection
    
    async def me(self, info: Info) -> dict | None:
        """
        Get the current authenticated user.
        
        Requires authentication.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authentication
            self.require_authentication(context)
            
            # Get current user
            if self.dataloaders:
                user = await self.dataloaders.user_loader.load(context.user_id)
            else:
                result = await self.user_repository.find_by_id(context.user_id)
                user = await self.handle_repository_result(result)
            
            if not user:
                self._raise_current_user_not_found()
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "me", {}, execution_time
            )
            
        except Exception:
            self.logger.exception("Error in me query")
            raise
        else:
            return user
    
    async def user_profile(self, info: Info, user_id: UUID) -> dict | None:
        """
        Get user profile data.
        
        Requires either:
        - User accessing their own profile
        - 'user:profile:read' permission
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_self_or_permission(context, user_id, "user:profile:read")
            
            # Get user profile
            if self.dataloaders:
                profile = await self.dataloaders.user_profile_loader.load(user_id)
            else:
                result = await self.user_profile_repository.find_by_user_id(user_id)
                profile = await self.handle_repository_result(result)
            
            if not profile:
                self._raise_profile_not_found()
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "userProfile", {"user_id": str(user_id)}, execution_time
            )
            
        except Exception:
            self.logger.exception("Error in userProfile query")
            raise
        else:
            return profile
    
    async def user_preferences(self, info: Info, user_id: UUID) -> dict | None:
        """
        Get user preferences.
        
        Requires either:
        - User accessing their own preferences
        - 'user:preferences:read' permission
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_self_or_permission(context, user_id, "user:preferences:read")
            
            # Get user preferences
            if self.dataloaders:
                preferences = await self.dataloaders.user_preference_loader.load(user_id)
            else:
                result = await self.user_preference_repository.find_by_user_id(user_id)
                preferences = await self.handle_repository_result(result)
            
            if not preferences:
                self._raise_preferences_not_found()
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "userPreferences", {"user_id": str(user_id)}, execution_time
            )
            
        except Exception:
            self.logger.exception("Error in userPreferences query")
            raise
        else:
            return preferences
    
    async def user_sessions(self, info: Info, user_id: UUID) -> list[dict]:
        """
        Get user sessions.
        
        Requires either:
        - User accessing their own sessions
        - 'user:sessions:read' permission
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_self_or_permission(context, user_id, "user:sessions:read")
            
            # Get user sessions
            if self.dataloaders:
                sessions = await self.dataloaders.user_sessions_loader.load(user_id)
            else:
                result = await self.session_repository.find_by_user_id(user_id)
                sessions = await self.handle_repository_result(result)
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "userSessions", {"user_id": str(user_id)}, execution_time
            )
            
        except Exception:
            self.logger.exception("Error in userSessions query")
            raise
        else:
            return sessions or []
    
    async def user_roles(self, info: Info, user_id: UUID) -> list[dict]:
        """
        Get user roles.
        
        Requires either:
        - User accessing their own roles
        - 'user:roles:read' permission
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_self_or_permission(context, user_id, "user:roles:read")
            
            # Get user roles
            if self.dataloaders:
                roles = await self.dataloaders.user_roles_loader.load(user_id)
            else:
                result = await self.role_repository.find_by_user_id(user_id)
                roles = await self.handle_repository_result(result)
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "userRoles", {"user_id": str(user_id)}, execution_time
            )
            
        except Exception:
            self.logger.exception("Error in userRoles query")
            raise
        else:
            return roles or []
    
    async def user_permissions(self, info: Info, user_id: UUID) -> list[dict]:
        """
        Get user permissions (aggregated from roles).
        
        Requires either:
        - User accessing their own permissions
        - 'user:permissions:read' permission
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_self_or_permission(context, user_id, "user:permissions:read")
            
            # Get user permissions
            if self.dataloaders:
                permissions = await self.dataloaders.user_permissions_loader.load(user_id)
            else:
                # Get user roles first, then their permissions
                roles_result = await self.role_repository.find_by_user_id(user_id)
                roles = await self.handle_repository_result(roles_result)
                
                permissions = []
                if roles:
                    role_ids = [role.id for role in roles]
                    perms_result = await self.permission_repository.find_by_role_ids(role_ids)
                    permissions = await self.handle_repository_result(perms_result)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_permissions = []
            for perm in permissions or []:
                if perm.id not in seen:
                    seen.add(perm.id)
                    unique_permissions.append(perm)
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "userPermissions", {"user_id": str(user_id)}, execution_time
            )
            
        except Exception:
            self.logger.exception("Error in userPermissions query")
            raise
        else:
            return unique_permissions
    
    async def user_audit_log(
        self,
        info: Info,
        user_id: UUID,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get user audit log.
        
        Requires either:
        - User accessing their own audit log
        - 'user:audit:read' permission
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_self_or_permission(context, user_id, "user:audit:read")
            
            # Validate pagination
            pagination = self.validate_pagination(pagination)
            
            # Get user security events (audit log)
            if self.dataloaders:
                all_events = await self.dataloaders.user_security_events_loader.load(user_id)
                # Apply pagination to the cached results
                total_count = len(all_events)
                events = all_events[pagination.offset:pagination.offset + pagination.limit]
            else:
                result = await self.security_event_repository.find_by_user_id(
                    user_id,
                    limit=pagination.limit,
                    offset=pagination.offset
                )
                events = await self.handle_repository_result(result)
                
                # Get total count
                count_result = await self.security_event_repository.count_by_user_id(user_id)
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
                context, "userAuditLog", {
                    "user_id": str(user_id),
                    "pagination": pagination.__dict__,
                    "result_count": len(events)
                }, execution_time
            )
            
        except Exception:
            self.logger.exception("Error in userAuditLog query")
            raise
        else:
            return connection
    
    async def user_statistics(self, info: Info) -> UserStatisticsType:
        """
        Get user statistics.
        
        Requires 'admin:statistics' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "admin:statistics")
            
            # Get various user statistics
            stats_result = await self.user_repository.get_user_statistics()
            stats = await self.handle_repository_result(stats_result)
            
            # Convert to GraphQL type
            user_stats = UserStatisticsType(
                total_users=stats.total_users,
                active_users=stats.active_users,
                verified_users=stats.verified_users,
                users_with_mfa=stats.users_with_mfa,
                new_users_today=stats.new_users_today,
                new_users_this_week=stats.new_users_this_week,
                new_users_this_month=stats.new_users_this_month,
                login_count_today=stats.login_count_today,
                average_session_duration=stats.average_session_duration
            )
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "userStatistics", {}, execution_time
            )
            
        except Exception:
            self.logger.exception("Error in userStatistics query")
            raise
        else:
            return user_stats