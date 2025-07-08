"""
Base Query Resolver

Provides common functionality for all GraphQL query resolvers including:
- Authentication and authorization
- Error handling
- Performance monitoring
- Input validation
- Pagination helpers
"""

import logging
from abc import ABC
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from strawberry.types import Info

from app.core.domain.exceptions import DomainError
from app.core.domain.result import Result
from app.modules.identity.domain.interfaces.repositories import (
    IPermissionRepository,
    IRoleRepository,
    ISecurityEventRepository,
    ISessionRepository,
    IUserRepository,
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class PaginationInput:
    """Standard pagination input."""
    limit: int = 50
    offset: int = 0
    cursor: str | None = None

    def __post_init__(self):
        """Validate pagination parameters."""
        if self.limit <= 0:
            raise ValueError("Limit must be positive")
        if self.limit > 1000:
            raise ValueError("Limit cannot exceed 1000")
        if self.offset < 0:
            raise ValueError("Offset cannot be negative")


@dataclass
class SortInput:
    """Standard sort input."""
    field: str
    direction: str = "ASC"

    def __post_init__(self):
        """Validate sort parameters."""
        if not self.field:
            raise ValueError("Sort field is required")
        if self.direction not in ["ASC", "DESC"]:
            raise ValueError("Sort direction must be ASC or DESC")


@dataclass
class FilterInput:
    """Base filter input."""
    created_after: datetime | None = None
    created_before: datetime | None = None
    updated_after: datetime | None = None
    updated_before: datetime | None = None


@dataclass
class QueryContext:
    """Context information for query execution."""
    user_id: UUID | None
    permissions: list[str]
    session_id: str | None
    request_ip: str | None
    request_timestamp: datetime
    is_admin: bool = False


class GraphQLError(Exception):
    """Custom GraphQL error with structured error information."""
    
    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_ERROR",
        extensions: dict[str, Any] | None = None
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.extensions = extensions or {}


class UnauthorizedError(GraphQLError):
    """Error raised when user lacks required permissions."""
    
    def __init__(self, message: str = "Unauthorized access", required_permission: str | None = None):
        extensions = {}
        if required_permission:
            extensions["required_permission"] = required_permission
        super().__init__(message, "UNAUTHORIZED", extensions)


class ValidationError(GraphQLError):
    """Error raised for input validation failures."""
    
    def __init__(self, message: str, field: str | None = None):
        extensions = {}
        if field:
            extensions["field"] = field
        super().__init__(message, "VALIDATION_ERROR", extensions)


class NotFoundError(GraphQLError):
    """Error raised when requested resource is not found."""
    
    def __init__(self, message: str = "Resource not found", resource_type: str | None = None):
        extensions = {}
        if resource_type:
            extensions["resource_type"] = resource_type
        super().__init__(message, "NOT_FOUND", extensions)


class BaseQueryResolver(ABC):
    """Base class for all query resolvers."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        role_repository: IRoleRepository,
        permission_repository: IPermissionRepository,
        session_repository: ISessionRepository,
        security_event_repository: ISecurityEventRepository,
    ):
        self.user_repository = user_repository
        self.role_repository = role_repository
        self.permission_repository = permission_repository
        self.session_repository = session_repository
        self.security_event_repository = security_event_repository
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def extract_context(self, info: Info) -> QueryContext:
        """Extract query context from GraphQL info."""
        try:
            # Extract user information from context
            context = info.context
            user_id = getattr(context, 'user_id', None)
            session_id = getattr(context, 'session_id', None)
            request_ip = getattr(context, 'request_ip', None)
            
            # Get user permissions
            permissions = []
            is_admin = False
            
            if user_id:
                # Load user permissions (would typically come from JWT or session)
                user_result = await self.user_repository.find_by_id(user_id)
                if user_result.is_success and user_result.value:
                    # Extract permissions from user roles
                    permissions = await self._get_user_permissions(user_id)
                    is_admin = await self._is_user_admin(user_id)
            
            return QueryContext(
                user_id=user_id,
                permissions=permissions,
                session_id=session_id,
                request_ip=request_ip,
                request_timestamp=datetime.now(UTC),
                is_admin=is_admin
            )
        except Exception as e:
            self.logger.exception(f"Failed to extract query context: {e}")
            raise GraphQLError("Failed to process authentication context")
    
    async def _get_user_permissions(self, user_id: UUID) -> list[str]:
        """Get user permissions from roles."""
        try:
            # Get user roles
            roles_result = await self.role_repository.find_by_user_id(user_id)
            if not roles_result.is_success:
                return []
            
            permissions = set()
            for role in roles_result.value:
                # Get role permissions
                role_perms_result = await self.permission_repository.find_by_role_id(role.id)
                if role_perms_result.is_success:
                    permissions.update(perm.name for perm in role_perms_result.value)
            
            return list(permissions)
        except Exception as e:
            self.logger.exception(f"Failed to get user permissions for {user_id}: {e}")
            return []
    
    async def _is_user_admin(self, user_id: UUID) -> bool:
        """Check if user has admin privileges."""
        permissions = await self._get_user_permissions(user_id)
        return "admin:*" in permissions or "system:admin" in permissions
    
    def require_authentication(self, context: QueryContext) -> None:
        """Require user to be authenticated."""
        if not context.user_id:
            raise UnauthorizedError("Authentication required")
    
    def require_permission(self, context: QueryContext, permission: str) -> None:
        """Require specific permission."""
        self.require_authentication(context)
        
        if not context.is_admin and permission not in context.permissions:
            raise UnauthorizedError(
                f"Permission '{permission}' required",
                required_permission=permission
            )
    
    def require_admin(self, context: QueryContext) -> None:
        """Require admin privileges."""
        self.require_authentication(context)
        
        if not context.is_admin:
            raise UnauthorizedError("Admin privileges required")
    
    def require_self_or_permission(
        self, 
        context: QueryContext, 
        target_user_id: UUID, 
        permission: str
    ) -> None:
        """Require user to be accessing their own data or have specific permission."""
        self.require_authentication(context)
        
        if context.user_id == target_user_id:
            return  # User can access their own data
        
        if not context.is_admin and permission not in context.permissions:
            raise UnauthorizedError(
                f"Permission '{permission}' required to access other user's data",
                required_permission=permission
            )
    
    def validate_pagination(self, pagination: PaginationInput | None) -> PaginationInput:
        """Validate and normalize pagination input."""
        if pagination is None:
            return PaginationInput()
        
        try:
            # Validate through dataclass post_init
            return PaginationInput(
                limit=pagination.limit,
                offset=pagination.offset,
                cursor=pagination.cursor
            )
        except ValueError as e:
            raise ValidationError(str(e), "pagination")
    
    def validate_sort(self, sort: SortInput | None, allowed_fields: list[str]) -> SortInput | None:
        """Validate sort input against allowed fields."""
        if sort is None:
            return None
        
        try:
            validated_sort = SortInput(field=sort.field, direction=sort.direction)
            
            if validated_sort.field not in allowed_fields:
                raise ValidationError(
                    f"Sort field '{validated_sort.field}' not allowed. "
                    f"Allowed fields: {', '.join(allowed_fields)}",
                    "sort.field"
                )
            
            return validated_sort
        except ValueError as e:
            raise ValidationError(str(e), "sort")
    
    async def handle_repository_result(self, result: Result[T]) -> T:
        """Handle repository result and convert errors to GraphQL errors."""
        if result.is_success:
            return result.value
        
        error = result.error
        if isinstance(error, DomainError):
            if "not found" in str(error).lower():
                raise NotFoundError(str(error))
            if "unauthorized" in str(error).lower():
                raise UnauthorizedError(str(error))
            if "validation" in str(error).lower():
                raise ValidationError(str(error))
        
        self.logger.error(f"Repository operation failed: {error}")
        raise GraphQLError("Internal server error")
    
    async def log_query_execution(
        self,
        context: QueryContext,
        query_name: str,
        parameters: dict[str, Any],
        execution_time_ms: float
    ) -> None:
        """Log query execution for monitoring."""
        self.logger.info(
            f"GraphQL Query: {query_name}",
            extra={
                "user_id": str(context.user_id) if context.user_id else None,
                "session_id": context.session_id,
                "request_ip": context.request_ip,
                "execution_time_ms": execution_time_ms,
                "parameters": parameters,
                "timestamp": context.request_timestamp.isoformat()
            }
        )
    
    def apply_filters(self, query_builder, filters: FilterInput) -> Any:
        """Apply common filters to query builder."""
        if filters.created_after:
            query_builder = query_builder.where("created_at >= ?", filters.created_after)
        if filters.created_before:
            query_builder = query_builder.where("created_at <= ?", filters.created_before)
        if filters.updated_after:
            query_builder = query_builder.where("updated_at >= ?", filters.updated_after)
        if filters.updated_before:
            query_builder = query_builder.where("updated_at <= ?", filters.updated_before)
        
        return query_builder
    
    def apply_pagination(self, query_builder, pagination: PaginationInput) -> Any:
        """Apply pagination to query builder."""
        return query_builder.limit(pagination.limit).offset(pagination.offset)
    
    def apply_sort(self, query_builder, sort: SortInput | None) -> Any:
        """Apply sorting to query builder."""
        if sort:
            direction = "ASC" if sort.direction == "ASC" else "DESC"
            return query_builder.order_by(f"{sort.field} {direction}")
        return query_builder.order_by("created_at DESC")


@dataclass
class PageInfo:
    """Page information for cursor-based pagination."""
    has_next_page: bool
    has_previous_page: bool
    start_cursor: str | None
    end_cursor: str | None
    total_count: int | None = None


@dataclass
class Edge(Generic[T]):
    """Edge in a connection."""
    node: T
    cursor: str


@dataclass
class Connection(Generic[T]):
    """Connection for cursor-based pagination."""
    edges: list[Edge[T]]
    page_info: PageInfo
    total_count: int | None = None