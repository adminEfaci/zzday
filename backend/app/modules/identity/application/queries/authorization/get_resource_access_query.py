"""Get resource access query implementation."""

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
from app.modules.identity.application.dtos.response import ResourceAccessResponse


@dataclass
class GetResourceAccessQuery(Query[ResourceAccessResponse]):
    """Query to get resource access information."""
    
    resource_id: str
    resource_type: str
    user_id: UUID | None = None
    requester_permissions: list[str] = field(default_factory=list)


class GetResourceAccessQueryHandler(QueryHandler[GetResourceAccessQuery, ResourceAccessResponse]):
    """Handler for resource access queries."""
    
    def __init__(self, uow: UnitOfWork, authorization_repository: IAuthorizationRepository):
        self.uow = uow
        self.authorization_repository = authorization_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("authorization.resources.read")
    @validate_request
    async def handle(self, query: GetResourceAccessQuery) -> ResourceAccessResponse:
        """Handle resource access query."""
        
        async with self.uow:
            access_list = await self.authorization_repository.get_resource_access(
                query.resource_id, query.resource_type, query.user_id
            )
            
            return ResourceAccessResponse(
                resource_id=query.resource_id,
                resource_type=query.resource_type,
                access_list=access_list,
                retrieved_at=datetime.now(UTC)
            )