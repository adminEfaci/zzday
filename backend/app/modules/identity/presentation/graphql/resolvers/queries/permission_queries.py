"""
Permission Query Resolvers

GraphQL query resolvers for permission-related operations including:
- Single permission and permission listing with filtering/pagination
- Permission checks and validation
- Permission hierarchy and grouping
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
    ValidationError,
)
from .dataloaders import IdentityDataLoaders


@strawberry.input
class PermissionFilterInput(FilterInput):
    """Advanced filtering options for permission queries."""
    name: str | None = None
    resource: str | None = None
    action: str | None = None
    is_active: bool | None = None
    is_system: bool | None = None
    category: str | None = None
    role_ids: list[UUID] | None = None


@strawberry.input
class PermissionSortInput(SortInput):
    """Sorting options for permission queries."""
    # Uses base sort fields (field, direction)


@dataclass
class PermissionCheckResult:
    """Result of a permission check."""
    user_id: UUID
    resource: str
    action: str
    granted: bool
    reason: str
    checked_at: datetime


@strawberry.type
class PermissionCheckResultType:
    """GraphQL type for permission check results."""
    user_id: UUID
    resource: str
    action: str
    granted: bool
    reason: str
    checked_at: datetime


class PermissionQueries(BaseQueryResolver):
    """GraphQL query resolvers for permission operations."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dataloaders: IdentityDataLoaders | None = None
    
    def set_dataloaders(self, dataloaders: IdentityDataLoaders):
        """Set DataLoaders for this resolver."""
        self.dataloaders = dataloaders
    
    async def permission(self, info: Info, id: UUID) -> dict | None:
        """
        Get a single permission by ID.
        
        Requires 'permission:read' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "permission:read")
            
            # Use DataLoader if available
            if self.dataloaders:
                permission = await self.dataloaders.permission_loader.load(id)
            else:
                result = await self.permission_repository.find_by_id(id)
                permission = await self.handle_repository_result(result)
            
            if not permission:
                raise NotFoundError("Permission not found", "Permission")
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "permission", {"id": str(id)}, execution_time
            )
            
            return permission
            
        except Exception as e:
            self.logger.exception(f"Error in permission query: {e}")
            raise
    
    async def permissions(
        self,
        info: Info,
        filter: PermissionFilterInput | None = None,
        sort: PermissionSortInput | None = None,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get a list of permissions with filtering, sorting, and pagination.
        
        Requires 'permission:list' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "permission:list")
            
            # Validate input
            pagination = self.validate_pagination(pagination)
            sort = self.validate_sort(sort, [
                "created_at", "updated_at", "name", "resource", "action", "category"
            ])
            
            # Build query parameters
            query_params = {}
            if filter:
                if filter.name:
                    query_params["name"] = filter.name
                if filter.resource:
                    query_params["resource"] = filter.resource
                if filter.action:
                    query_params["action"] = filter.action
                if filter.is_active is not None:
                    query_params["is_active"] = filter.is_active
                if filter.is_system is not None:
                    query_params["is_system"] = filter.is_system
                if filter.category:
                    query_params["category"] = filter.category
                if filter.role_ids:
                    query_params["role_ids"] = filter.role_ids
            
            # Execute query
            result = await self.permission_repository.find_with_filters(
                filters=query_params,
                sort_field=sort.field if sort else "created_at",
                sort_direction=sort.direction if sort else "DESC",
                limit=pagination.limit,
                offset=pagination.offset
            )
            
            permissions = await self.handle_repository_result(result)
            
            # Get total count for pagination
            count_result = await self.permission_repository.count_with_filters(query_params)
            total_count = await self.handle_repository_result(count_result)
            
            # Build connection
            edges = [
                Edge(node=permission, cursor=str(permission.id))
                for permission in permissions
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(permissions) < total_count,
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
                context, "permissions", {
                    "filter": filter.__dict__ if filter else None,
                    "sort": sort.__dict__ if sort else None,
                    "pagination": pagination.__dict__,
                    "result_count": len(permissions)
                }, execution_time
            )
            
            return connection
            
        except Exception as e:
            self.logger.exception(f"Error in permissions query: {e}")
            raise
    
    async def permission_check(
        self,
        info: Info,
        user_id: UUID,
        resource: str,
        action: str
    ) -> PermissionCheckResultType:
        """
        Check if a user has a specific permission.
        
        Requires either:
        - User checking their own permissions
        - 'permission:check' permission
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_self_or_permission(context, user_id, "permission:check")
            
            # Validate input
            if not resource or not action:
                raise ValidationError("Resource and action are required")
            
            # Perform permission check
            from datetime import UTC, datetime
            
            # Get user permissions
            if self.dataloaders:
                user_permissions = await self.dataloaders.user_permissions_loader.load(user_id)
            else:
                # Get user roles first, then their permissions
                roles_result = await self.role_repository.find_by_user_id(user_id)
                roles = await self.handle_repository_result(roles_result)
                
                user_permissions = []
                if roles:
                    role_ids = [role.id for role in roles]
                    perms_result = await self.permission_repository.find_by_role_ids(role_ids)
                    user_permissions = await self.handle_repository_result(perms_result)
            
            # Check for exact permission match
            granted = False
            reason = "Permission denied"
            
            # Check for admin permissions first
            admin_permissions = [
                "admin:*",
                "system:admin",
                f"{resource}:*",
                "*:*"
            ]
            
            for perm in user_permissions or []:
                if perm.name in admin_permissions:
                    granted = True
                    reason = f"Admin permission '{perm.name}' grants access"
                    break
                if perm.resource == resource and perm.action == action:
                    granted = True
                    reason = f"Direct permission '{perm.name}' grants access"
                    break
                if perm.resource == resource and perm.action == "*":
                    granted = True
                    reason = f"Wildcard permission '{perm.name}' grants access"
                    break
            
            if not granted:
                if not user_permissions:
                    reason = "User has no permissions"
                else:
                    reason = f"No permission found for {resource}:{action}"
            
            # Create result
            result = PermissionCheckResultType(
                user_id=user_id,
                resource=resource,
                action=action,
                granted=granted,
                reason=reason,
                checked_at=datetime.now(UTC)
            )
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "permissionCheck", {
                    "user_id": str(user_id),
                    "resource": resource,
                    "action": action,
                    "granted": granted
                }, execution_time
            )
            
            return result
            
        except Exception as e:
            self.logger.exception(f"Error in permissionCheck query: {e}")
            raise