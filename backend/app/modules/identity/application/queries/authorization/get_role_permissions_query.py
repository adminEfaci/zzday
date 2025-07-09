"""Get role permissions query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import RolePermissionsResponse
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)


@dataclass
class GetRolePermissionsQuery(Query[RolePermissionsResponse]):
    """Query to get role permissions."""
    
    role_name: str
    include_hierarchy: bool = False
    requester_permissions: list[str] = field(default_factory=list)


class GetRolePermissionsQueryHandler(QueryHandler[GetRolePermissionsQuery, RolePermissionsResponse]):
    """Handler for role permissions queries."""
    
    def __init__(self, uow: UnitOfWork, user_repository: IUserRepository):
        self.uow = uow
        self.user_repository = user_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("authorization.roles.read")
    @validate_request
    async def handle(self, query: GetRolePermissionsQuery) -> RolePermissionsResponse:
        """Handle role permissions query."""
        
        async with self.uow:
            permissions = await self.user_repository.find_by_role(query.role_name)
            
            hierarchy = None
            if query.include_hierarchy:
                hierarchy = await self.user_repository.get_role_hierarchy(query.role_name)
            
            return RolePermissionsResponse(
                role_name=query.role_name,
                permissions=permissions,
                hierarchy=hierarchy,
                retrieved_at=datetime.now(UTC)
            )