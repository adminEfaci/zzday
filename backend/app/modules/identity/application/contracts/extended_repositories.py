"""
Extended Repository Interfaces

Application-specific repository interfaces that extend domain repositories
with additional query and analytics capabilities.
"""

from abc import abstractmethod
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from app.core.infrastructure.pagination import PagedResult
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.entities.session.session import Session
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository as IDomainSessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository as IDomainUserRepository,
)
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.username import Username


class IExtendedUserRepository(IDomainUserRepository, Protocol):
    """Extended user repository with application-specific queries."""
    
    @abstractmethod
    async def get_by_id(self, user_id: UUID) -> 'User' | None:
        """Get user by ID (alias for find_by_id)."""
        ...
    
    @abstractmethod
    async def get_by_email(self, email: Email) -> 'User' | None:
        """Get user by email value object."""
        ...
    
    @abstractmethod
    async def get_by_username(self, username: Username) -> 'User' | None:
        """Get user by username value object."""
        ...
    
    @abstractmethod
    async def exists_by_username(self, username: Username) -> bool:
        """Check if user exists by username."""
        ...
    
    @abstractmethod
    async def search(
        self,
        criteria: dict[str, Any],
        page: int = 1,
        page_size: int = 20,
        sort_by: str = "created_at",
        sort_order: str = "desc"
    ) -> PagedResult['User']:
        """Search users with pagination."""
        ...
    
    @abstractmethod
    async def search_users(
        self,
        criteria: dict[str, Any],
        sort_by: str = "created_at",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 20
    ) -> list[dict[str, Any]]:
        """Search users returning dict format."""
        ...
    
    @abstractmethod
    async def count_users(self, criteria: dict[str, Any]) -> int:
        """Count users matching criteria."""
        ...
    
    @abstractmethod
    async def get_role_permissions(self, role: str) -> list[str]:
        """Get permissions for a role."""
        ...
    
    @abstractmethod
    async def get_user_effective_permissions(self, user_id: UUID) -> list[str]:
        """Get effective permissions for user."""
        ...
    
    @abstractmethod
    async def get_user_role_permissions(self, user_id: UUID) -> dict[str, list[str]]:
        """Get role-based permissions for user."""
        ...
    
    @abstractmethod
    async def get_role_hierarchy(self, role_name: str) -> dict[str, Any] | None:
        """Get role hierarchy."""
        ...
    
    @abstractmethod
    async def get_user_compliance_status(self, user_id: UUID) -> dict[str, Any]:
        """Get user compliance status."""
        ...
    
    @abstractmethod
    async def get_user_engagement_trends(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: str
    ) -> dict[str, Any]:
        """Get user engagement trends."""
        ...


class IExtendedSessionRepository(IDomainSessionRepository, Protocol):
    """Extended session repository with analytics capabilities."""
    
    @abstractmethod
    async def create(self, session: Session) -> Session:
        """Create new session."""
        ...
    
    @abstractmethod
    async def get_by_id(self, session_id: UUID) -> Session | None:
        """Get session by ID."""
        ...
    
    @abstractmethod
    async def get_by_token(self, access_token: str) -> Session | None:
        """Get session by access token."""
        ...
    
    @abstractmethod
    async def get_by_refresh_token(self, refresh_token: str) -> Session | None:
        """Get session by refresh token."""
        ...
    
    @abstractmethod
    async def get_active_sessions(self, user_id: UUID) -> list[Session]:
        """Get all active sessions for user."""
        ...
    
    @abstractmethod
    async def update(self, session: Session) -> None:
        """Update session."""
        ...
    
    @abstractmethod
    async def revoke(self, session_id: UUID) -> None:
        """Revoke session."""
        ...
    
    @abstractmethod
    async def revoke_all_for_user(self, user_id: UUID, except_session_id: UUID | None = None) -> None:
        """Revoke all sessions for user."""
        ...
    
    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Clean up expired sessions."""
        ...
    
    @abstractmethod
    async def count_user_sessions(
        self,
        user_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        active_only: bool = False
    ) -> int:
        """Count user sessions."""
        ...
    
    @abstractmethod
    async def get_user_session_summary(
        self,
        user_id: UUID,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get user session summary."""
        ...
    
    @abstractmethod
    async def get_session_statistics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get session statistics."""
        ...
