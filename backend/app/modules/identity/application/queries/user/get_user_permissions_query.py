"""
Get user permissions query implementation.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import UserPermissionsResponse
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)


@dataclass
class GetUserPermissionsQuery(Query[UserPermissionsResponse]):
    """Query to retrieve user permissions."""
    
    user_id: UUID
    requester_id: UUID
    include_role_hierarchy: bool = True
    requester_permissions: list[str] = field(default_factory=list)


class GetUserPermissionsQueryHandler(
    QueryHandler[GetUserPermissionsQuery, UserPermissionsResponse]
):
    """Handler for user permissions queries."""
    
    def __init__(self, uow: UnitOfWork, user_repository: IUserRepository):
        self.uow = uow
        self.user_repository = user_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("user.permissions.read")
    @validate_request
    async def handle(self, query: GetUserPermissionsQuery) -> UserPermissionsResponse:
        """Handle user permissions query."""
        
        async with self.uow:
            user = await self.user_repository.find_by_id(query.user_id)
            permissions = await self.user_repository.get_user_effective_permissions(
                query.user_id
            )
            role_permissions = await self.user_repository.get_user_role_permissions(
                query.user_id
            )
            
            return UserPermissionsResponse(
                user_id=query.user_id,
                roles=user.roles,
                permissions=permissions,
                role_permissions=role_permissions,
                retrieved_at=datetime.now(UTC)
            )