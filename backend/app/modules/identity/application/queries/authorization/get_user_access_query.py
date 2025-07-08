"""
Get user access query implementation.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import UserAccessResponse


@dataclass
class GetUserAccessQuery(Query[UserAccessResponse]):
    """Query to get user access information."""
    
    user_id: UUID
    requester_id: UUID
    resource_type: str | None = None
    include_inherited: bool = True
    requester_permissions: list[str] = field(default_factory=list)


class GetUserAccessQueryHandler(QueryHandler[GetUserAccessQuery, UserAccessResponse]):
    """Handler for user access queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        user_repository: IUserRepository,
        authorization_repository: IAuthorizationRepository
    ):
        self.uow = uow
        self.user_repository = user_repository
        self.authorization_repository = authorization_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("authorization.read")
    @validate_request
    async def handle(self, query: GetUserAccessQuery) -> UserAccessResponse:
        """Handle user access query."""
        
        async with self.uow:
            user = await self.user_repository.find_by_id(query.user_id)
            
            # Get direct permissions
            direct_permissions = getattr(user, 'permissions', [])
            
            # Get role-based permissions
            role_permissions = []
            for role in user.roles:
                perms = await self.user_repository.find_by_role(role)
                role_permissions.extend(perms)
            
            # Get effective permissions
            effective_permissions = list(set(direct_permissions + role_permissions))
            
            # Get resource access if specified
            resource_access = None
            if query.resource_type:
                resource_access = await (
                    self.authorization_repository.get_user_resource_access(
                        query.user_id, query.resource_type
                    )
                )
            
            return UserAccessResponse(
                user_id=query.user_id,
                direct_permissions=direct_permissions,
                role_permissions=role_permissions,
                effective_permissions=effective_permissions,
                roles=user.roles,
                resource_access=resource_access,
                retrieved_at=datetime.now(UTC)
            )