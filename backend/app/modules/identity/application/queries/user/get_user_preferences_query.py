"""
Get user preferences query implementation.
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
from app.modules.identity.application.dtos.response import UserPreferencesResponse
from app.modules.identity.domain.interfaces.services import (
    IPreferencesRepository,
)


@dataclass
class GetUserPreferencesQuery(Query[UserPreferencesResponse]):
    """Query to retrieve user preferences."""
    
    user_id: UUID
    requester_id: UUID
    category: str = None  # Optional filter by category
    requester_permissions: list[str] = field(default_factory=list)


class GetUserPreferencesQueryHandler(
    QueryHandler[GetUserPreferencesQuery, UserPreferencesResponse]
):
    """Handler for user preferences queries."""
    
    def __init__(self, uow: UnitOfWork, preferences_repository: IPreferencesRepository):
        self.uow = uow
        self.preferences_repository = preferences_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("user.preferences.read")
    @validate_request
    async def handle(self, query: GetUserPreferencesQuery) -> UserPreferencesResponse:
        """Handle user preferences query."""
        
        async with self.uow:
            preferences = await self.preferences_repository.get_user_preferences(
                query.user_id, query.category
            )
            
            return UserPreferencesResponse(
                user_id=query.user_id,
                preferences=preferences,
                category=query.category,
                retrieved_at=datetime.now(UTC)
            )