"""
Get user sessions query implementation.

Handles retrieval of user session information with filtering and analysis.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import UserSessionsResponse
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)


@dataclass
class GetUserSessionsQuery(Query[UserSessionsResponse]):
    """Query to retrieve user sessions."""
    
    user_id: UUID
    requester_id: UUID
    include_active_only: bool = False
    days_back: int = 30
    page: int = 1
    page_size: int = 20
    requester_permissions: list[str] = field(default_factory=list)


class GetUserSessionsQueryHandler(
    QueryHandler[GetUserSessionsQuery, UserSessionsResponse]
):
    """Handler for user sessions queries."""
    
    def __init__(self, uow: UnitOfWork, session_repository: ISessionRepository):
        self.uow = uow
        self.session_repository = session_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("user.sessions.read")
    @validate_request
    async def handle(self, query: GetUserSessionsQuery) -> UserSessionsResponse:
        """Handle user sessions query."""
        
        async with self.uow:
            end_date = datetime.now(UTC)
            start_date = end_date - timedelta(days=query.days_back)
            
            sessions = await self.session_repository.get_user_sessions(
                query.user_id, 
                start_date=start_date,
                end_date=end_date,
                active_only=query.include_active_only,
                page=query.page,
                page_size=query.page_size
            )
            
            total_count = await self.session_repository.count_user_sessions(
                query.user_id, start_date, end_date, query.include_active_only
            )
            
            return UserSessionsResponse(
                user_id=query.user_id,
                sessions=sessions,
                total_count=total_count,
                page=query.page,
                page_size=query.page_size,
                retrieved_at=datetime.now(UTC)
            )