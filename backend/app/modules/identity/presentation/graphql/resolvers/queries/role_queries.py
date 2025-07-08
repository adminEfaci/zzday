"""
Role Query Resolvers

GraphQL query resolvers for role-related operations including:
- Single role and role listing with filtering/pagination
- Role permissions and user assignments
- Role hierarchy and inheritance
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
class RoleFilterInput(FilterInput):
    """Advanced filtering options for role queries."""
    name: str | None = None
    description: str | None = None
    is_active: bool | None = None
    is_system: bool | None = None
    is_assignable: bool | None = None
    parent_role_id: UUID | None = None
    permission_ids: list[UUID] | None = None


@strawberry.input
class RoleSortInput(SortInput):
    """Sorting options for role queries."""
    # Uses base sort fields (field, direction)


@dataclass
class RoleAssignment:
    """Role assignment information."""
    user_id: UUID
    role_id: UUID
    assigned_by: UUID
    assigned_at: datetime
    expires_at: datetime | None
    is_active: bool


@strawberry.type
class RoleAssignmentType:
    """GraphQL type for role assignments."""
    user_id: UUID
    role_id: UUID
    assigned_by: UUID
    assigned_at: datetime
    expires_at: datetime | None
    is_active: bool


class RoleQueries(BaseQueryResolver):
    """GraphQL query resolvers for role operations."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dataloaders: IdentityDataLoaders | None = None
    
    def set_dataloaders(self, dataloaders: IdentityDataLoaders):
        """Set DataLoaders for this resolver."""
        self.dataloaders = dataloaders
    
    async def role(self, info: Info, id: UUID) -> dict | None:
        """
        Get a single role by ID.
        
        Requires 'role:read' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "role:read")
            
            # Use DataLoader if available
            if self.dataloaders:
                role = await self.dataloaders.role_loader.load(id)
            else:
                result = await self.role_repository.find_by_id(id)
                role = await self.handle_repository_result(result)
            
            if not role:
                raise NotFoundError("Role not found", "Role")
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "role", {"id": str(id)}, execution_time
            )
            
            return role
            
        except Exception as e:
            self.logger.exception(f"Error in role query: {e}")
            raise
    
    async def roles(
        self,
        info: Info,
        filter: RoleFilterInput | None = None,
        sort: RoleSortInput | None = None,
        pagination: PaginationInput | None = None
    ) -> Connection:
        """
        Get a list of roles with filtering, sorting, and pagination.
        
        Requires 'role:list' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "role:list")
            
            # Validate input
            pagination = self.validate_pagination(pagination)
            sort = self.validate_sort(sort, [
                "created_at", "updated_at", "name", "description", "priority"
            ])
            
            # Build query parameters
            query_params = {}
            if filter:
                if filter.name:
                    query_params["name"] = filter.name
                if filter.description:
                    query_params["description"] = filter.description
                if filter.is_active is not None:
                    query_params["is_active"] = filter.is_active
                if filter.is_system is not None:
                    query_params["is_system"] = filter.is_system
                if filter.is_assignable is not None:
                    query_params["is_assignable"] = filter.is_assignable
                if filter.parent_role_id:
                    query_params["parent_role_id"] = filter.parent_role_id
                if filter.permission_ids:
                    query_params["permission_ids"] = filter.permission_ids
            
            # Execute query
            result = await self.role_repository.find_with_filters(
                filters=query_params,
                sort_field=sort.field if sort else "created_at",
                sort_direction=sort.direction if sort else "DESC",
                limit=pagination.limit,
                offset=pagination.offset
            )
            
            roles = await self.handle_repository_result(result)
            
            # Get total count for pagination
            count_result = await self.role_repository.count_with_filters(query_params)
            total_count = await self.handle_repository_result(count_result)
            
            # Build connection
            edges = [
                Edge(node=role, cursor=str(role.id))
                for role in roles
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(roles) < total_count,
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
                context, "roles", {
                    "filter": filter.__dict__ if filter else None,
                    "sort": sort.__dict__ if sort else None,
                    "pagination": pagination.__dict__,
                    "result_count": len(roles)
                }, execution_time
            )
            
            return connection
            
        except Exception as e:
            self.logger.exception(f"Error in roles query: {e}")
            raise
    
    async def role_permissions(self, info: Info, role_id: UUID) -> list[dict]:
        """
        Get permissions for a specific role.
        
        Requires 'role:permissions:read' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_permission(context, "role:permissions:read")
            
            # Verify role exists
            if self.dataloaders:
                role = await self.dataloaders.role_loader.load(role_id)
            else:
                role_result = await self.role_repository.find_by_id(role_id)
                role = await self.handle_repository_result(role_result)
            
            if not role:
                raise NotFoundError("Role not found", "Role")
            
            # Get role permissions
            if self.dataloaders:
                permissions = await self.dataloaders.role_permissions_loader.load(role_id)
            else:
                result = await self.permission_repository.find_by_role_id(role_id)
                permissions = await self.handle_repository_result(result)
            
            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "rolePermissions", {"role_id": str(role_id)}, execution_time
            )
            
            return permissions or []
            
        except Exception as e:
            self.logger.exception(f"Error in rolePermissions query: {e}")
            raise
    
    async def user_role_assignments(
        self,
        info: Info,
        user_id: UUID,
        pagination: PaginationInput | None = None
    ) -> Connection[RoleAssignmentType]:
        """
        Get role assignments for a specific user.
        
        Requires either:
        - User accessing their own role assignments
        - 'user:roles:read' permission
        """
        start_time = time.time()
        context = await self.extract_context(info)
        
        try:
            # Check authorization
            self.require_self_or_permission(context, user_id, "user:roles:read")
            
            # Validate pagination
            pagination = self.validate_pagination(pagination)
            
            # Get user role assignments
            result = await self.role_repository.find_user_role_assignments(
                user_id,
                limit=pagination.limit,
                offset=pagination.offset
            )
            assignments = await self.handle_repository_result(result)
            
            # Get total count
            count_result = await self.role_repository.count_user_role_assignments(user_id)
            total_count = await self.handle_repository_result(count_result)
            
            # Convert to GraphQL types
            assignment_types = [
                RoleAssignmentType(
                    user_id=assignment.user_id,
                    role_id=assignment.role_id,
                    assigned_by=assignment.assigned_by,
                    assigned_at=assignment.assigned_at,
                    expires_at=assignment.expires_at,
                    is_active=assignment.is_active
                )
                for assignment in assignments
            ]
            
            # Build connection
            edges = [
                Edge(node=assignment, cursor=f"{assignment.user_id}:{assignment.role_id}")
                for assignment in assignment_types
            ]
            
            page_info = PageInfo(
                has_next_page=pagination.offset + len(assignments) < total_count,
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
                context, "userRoleAssignments", {
                    "user_id": str(user_id),
                    "pagination": pagination.__dict__,
                    "result_count": len(assignments)
                }, execution_time
            )
            
            return connection
            
        except Exception as e:
            self.logger.exception(f"Error in userRoleAssignments query: {e}")
            raise