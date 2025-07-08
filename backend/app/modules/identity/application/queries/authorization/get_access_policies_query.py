"""Get access policies query implementation."""

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
from app.modules.identity.application.dtos.response import AccessPoliciesResponse


@dataclass
class GetAccessPoliciesQuery(Query[AccessPoliciesResponse]):
    """Query to get access policies."""
    
    user_id: UUID | None = None
    resource_type: str | None = None
    policy_type: str | None = None
    is_active: bool = True
    requester_permissions: list[str] = field(default_factory=list)


class GetAccessPoliciesQueryHandler(
    QueryHandler[GetAccessPoliciesQuery, AccessPoliciesResponse]
):
    """Handler for access policies queries."""
    
    def __init__(self, uow: UnitOfWork, policy_repository: IPolicyRepository):
        self.uow = uow
        self.policy_repository = policy_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("authorization.policies.read")
    @validate_request
    async def handle(self, query: GetAccessPoliciesQuery) -> AccessPoliciesResponse:
        """Handle access policies query."""
        
        async with self.uow:
            policies = await self.policy_repository.get_policies(
                user_id=query.user_id,
                resource_type=query.resource_type,
                policy_type=query.policy_type,
                is_active=query.is_active
            )
            
            return AccessPoliciesResponse(
                policies=policies,
                total_count=len(policies),
                retrieved_at=datetime.now(UTC)
            )