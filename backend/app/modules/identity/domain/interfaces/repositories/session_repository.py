"""Session Repository Interface

Domain contract for session data access that must be implemented by the infrastructure layer.
"""

from abc import abstractmethod
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.entities.session.session import Session


class ISessionRepository(Protocol):
    """Repository interface for Session entity."""
    
    @abstractmethod
    async def find_by_id(self, session_id: UUID) -> 'Session' | None:
        """Find session by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session entity if found, None otherwise
        """
        ...
    
    @abstractmethod
    async def save(self, session: 'Session') -> None:
        """Save session entity (create or update).
        
        Args:
            session: Session entity to save
        """
        ...
    
    @abstractmethod
    async def invalidate_session(self, session_id: UUID) -> bool:
        """Invalidate a specific session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if invalidated, False if not found
        """
        ...
    
    @abstractmethod
    async def invalidate_all_user_sessions(
        self, 
        user_id: UUID, 
        exclude_session_id: UUID | None = None
    ) -> int:
        """Invalidate all sessions for a user.
        
        Args:
            user_id: User identifier
            exclude_session_id: Optional session to exclude from invalidation
            
        Returns:
            Number of sessions invalidated
        """
        ...
    
    @abstractmethod
    async def find_active_sessions_by_user(self, user_id: UUID) -> list['Session']:
        """Find all active sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of active session entities
        """
        ...
    
    @abstractmethod
    async def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions.
        
        Returns:
            Number of sessions removed
        """
        ...
    
    @abstractmethod
    async def count_active_sessions_by_user(self, user_id: UUID) -> int:
        """Count active sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of active sessions
        """
        ...
    
    @abstractmethod
    async def find_by_token(self, token: str) -> 'Session' | None:
        """Find session by access token.
        
        Args:
            token: Access token
            
        Returns:
            Session entity if found, None otherwise
        """
        ...
    
    @abstractmethod
    async def exists(self, session_id: UUID) -> bool:
        """Check if session exists.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if session exists
        """
        ...
    
    @abstractmethod
    async def delete(self, session_id: UUID) -> bool:
        """Delete session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if deleted, False if not found
        """
        ...