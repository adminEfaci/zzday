"""
Search users query implementation.

Handles searching and filtering users with advanced search capabilities,
sorting, pagination, and export functionality.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.repositories.audit_repository import IAuditRepository
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import SearchUsersResponse
from app.modules.identity.domain.enums import AccountType, UserStatus
from app.modules.identity.domain.exceptions import (
    InvalidSearchParametersError,
    UnauthorizedAccessError,
    UserSearchError,
)


class SearchField(Enum):
    """Fields available for user search."""
    USERNAME = "username"
    EMAIL = "email"
    FIRST_NAME = "first_name"
    LAST_NAME = "last_name"
    FULL_NAME = "full_name"
    DEPARTMENT = "department"
    TITLE = "title"
    ROLES = "roles"
    ALL_FIELDS = "all_fields"

@dataclass
class SearchUsersQuery(Query[SearchUsersResponse]):
    """Query to search users."""

    # Required fields (no defaults) - MUST come first
    requester_id: UUID

    # Optional fields (with defaults) - come after required fields
    # Search parameters
    search_term: str | None = None
    search_fields: list[SearchField] | None = None

    # Filters
    status: UserStatus | None = None
    account_type: AccountType | None = None
    roles: list[str] | None = None
    departments: list[str] | None = None
    created_after: datetime | None = None
    created_before: datetime | None = None
    last_login_after: datetime | None = None
    last_login_before: datetime | None = None
    is_active: bool | None = None
    is_verified: bool | None = None

    # Advanced filters
    has_mfa_enabled: bool | None = None
    has_recent_activity: bool | None = None
    risk_level: str | None = None

    # Sorting and pagination
    sort_by: str = "created_at"
    sort_order: str = "desc"
    page: int = 1
    page_size: int = 20

    # Output options
    include_inactive: bool = False
    include_locked: bool = False
    include_unverified: bool = True
    export_format: str | None = None

    # Access control
    requester_permissions: list[str] = field(default_factory=list)

class SearchUsersQueryHandler(QueryHandler[SearchUsersQuery, SearchUsersResponse]):
    """Handler for user search queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        user_repository: IUserRepository,
        audit_repository: IAuditRepository
    ):
        self.uow = uow
        self.user_repository = user_repository
        self.audit_repository = audit_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("user.search")
    @validate_request
    async def handle(self, query: SearchUsersQuery) -> SearchUsersResponse:
        """Handle user search query."""
        
        try:
            async with self.uow:
                # Validate search parameters
                await self._validate_search_parameters(query)
                
                # Build search criteria
                search_criteria = await self._build_search_criteria(query)
                
                # Perform search
                users = await self.user_repository.search_users(
                    criteria=search_criteria,
                    sort_by=query.sort_by,
                    sort_order=query.sort_order,
                    page=query.page,
                    page_size=query.page_size
                )
                
                # Get total count
                total_count = await self.user_repository.count_users(search_criteria)
                
                # Filter results based on permissions
                filtered_users = await self._filter_results_by_permissions(users, query)
                
                # Prepare export data if requested
                export_data = None
                if query.export_format:
                    export_data = await self._prepare_export_data(
                        filtered_users, query.export_format
                    )
                
                return SearchUsersResponse(
                    users=filtered_users,
                    total_count=total_count,
                    page=query.page,
                    page_size=query.page_size,
                    total_pages=(total_count + query.page_size - 1) // query.page_size,
                    search_criteria=search_criteria,
                    export_data=export_data,
                    searched_at=datetime.now(UTC)
                )
                
        except Exception as e:
            raise UserSearchError(f"Failed to search users: {e!s}") from e
    
    async def _validate_search_parameters(self, query: SearchUsersQuery) -> None:
        """Validate search parameters."""
        
        # Check search permissions
        if "user.search" not in query.requester_permissions:
            raise UnauthorizedAccessError("Insufficient permissions for user search")
        
        # Validate search term length
        if query.search_term and len(query.search_term) < 2:
            raise InvalidSearchParametersError("Search term must be at least 2 characters")
        
        # Validate page size
        if query.page_size > 100:
            raise InvalidSearchParametersError("Page size cannot exceed 100")
        
        # Check advanced filter permissions
        if query.has_mfa_enabled is not None or query.risk_level:
            if "user.advanced_search" not in query.requester_permissions:
                raise UnauthorizedAccessError("No permission for advanced search filters")
    
    async def _build_search_criteria(self, query: SearchUsersQuery) -> dict[str, Any]:
        """Build search criteria from query parameters."""
        
        criteria = {}
        
        # Search term and fields
        if query.search_term:
            criteria["search_term"] = query.search_term
            criteria["search_fields"] = [field.value for field in (query.search_fields or [SearchField.ALL_FIELDS])]
        
        # Status filters
        if query.status:
            criteria["status"] = query.status.value
        
        if query.account_type:
            criteria["account_type"] = query.account_type.value
        
        # List filters
        if query.roles:
            criteria["roles"] = query.roles
        
        if query.departments:
            criteria["departments"] = query.departments
        
        # Date filters
        if query.created_after:
            criteria["created_after"] = query.created_after
        
        if query.created_before:
            criteria["created_before"] = query.created_before
        
        if query.last_login_after:
            criteria["last_login_after"] = query.last_login_after
        
        if query.last_login_before:
            criteria["last_login_before"] = query.last_login_before
        
        # Boolean filters
        if query.is_active is not None:
            criteria["is_active"] = query.is_active
        
        if query.is_verified is not None:
            criteria["is_verified"] = query.is_verified
        
        if query.has_mfa_enabled is not None:
            criteria["has_mfa_enabled"] = query.has_mfa_enabled
        
        # Advanced filters
        if query.has_recent_activity is not None:
            criteria["has_recent_activity"] = query.has_recent_activity
        
        if query.risk_level:
            criteria["risk_level"] = query.risk_level
        
        # Include options
        criteria["include_inactive"] = query.include_inactive
        criteria["include_locked"] = query.include_locked
        criteria["include_unverified"] = query.include_unverified
        
        return criteria
    
    async def _filter_results_by_permissions(self, users: list[dict[str, Any]], query: SearchUsersQuery) -> list[dict[str, Any]]:
        """Filter search results based on user permissions."""
        
        filtered_users = []
        
        for user in users:
            # Basic user info that everyone can see
            filtered_user = {
                "id": user["id"],
                "username": user["username"],
                "first_name": user["first_name"],
                "last_name": user["last_name"],
                "status": user["status"],
                "created_at": user["created_at"],
                "is_active": user["is_active"]
            }
            
            # Add email if permitted
            if "user.email.read" in query.requester_permissions:
                filtered_user["email"] = user.get("email")
            
            # Add contact info if permitted
            if "user.contact.read" in query.requester_permissions:
                filtered_user.update({
                    "phone_number": user.get("phone_number"),
                    "department": user.get("department"),
                    "title": user.get("title")
                })
            
            # Add roles if permitted
            if "user.roles.read" in query.requester_permissions:
                filtered_user["roles"] = user.get("roles", [])
            
            # Add last login if permitted
            if "user.activity.read" in query.requester_permissions:
                filtered_user["last_login_at"] = user.get("last_login_at")
            
            filtered_users.append(filtered_user)
        
        return filtered_users
    
    async def _prepare_export_data(self, users: list[dict[str, Any]], export_format: str) -> dict[str, Any]:
        """Prepare users for export."""
        
        return {
            "format": export_format,
            "content": f"Users search results in {export_format} format",
            "filename": f"users_search_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{export_format}",
            "record_count": len(users)
        }