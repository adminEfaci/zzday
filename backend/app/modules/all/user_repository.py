"""User Repository Interface

Domain contract for user data access that must be implemented by the infrastructure layer.
"""

from abc import abstractmethod
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User


class IUserRepository(Protocol):
    """Repository interface for User aggregate."""
    
    @abstractmethod
    async def find_by_id(self, user_id: UUID) -> 'User' | None:
        """Find user by ID.
        
        Args:
            user_id: User identifier
            
        Returns:
            User aggregate if found, None otherwise
        """
        ...
    
    @abstractmethod
    async def find_by_email(self, email: str) -> 'User' | None:
        """Find user by email address.
        
        Args:
            email: Email address
            
        Returns:
            User aggregate if found, None otherwise
        """
        ...
    
    @abstractmethod
    async def save(self, user: 'User') -> None:
        """Save user aggregate (create or update).
        
        Args:
            user: User aggregate to save
        """
        ...
    
    @abstractmethod
    async def delete(self, user_id: UUID) -> bool:
        """Delete user by ID.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if deleted, False if not found
        """
        ...
    
    @abstractmethod
    async def find_by_username(self, username: str) -> 'User' | None:
        """Find user by username.
        
        Args:
            username: Username
            
        Returns:
            User aggregate if found, None otherwise
        """
        ...
    
    @abstractmethod
    async def exists_by_email(self, email: str) -> bool:
        """Check if user exists by email.
        
        Args:
            email: Email address
            
        Returns:
            True if user exists
        """
        ...
    
    @abstractmethod
    async def find_all(
        self, 
        include_inactive: bool = False,
        limit: int = 100,
        offset: int = 0
    ) -> list['User']:
        """Find all users with pagination.
        
        Args:
            include_inactive: Whether to include inactive users
            limit: Maximum number of results
            offset: Number of results to skip
            
        Returns:
            List of user aggregates
        """
        ...
    
    @abstractmethod
    async def count_active_users(self) -> int:
        """Count active users.
        
        Returns:
            Number of active users
        """
        ...
    
    @abstractmethod
    async def exists(self, user_id: UUID) -> bool:
        """Check if user exists.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if user exists
        """
        ...
    
    @abstractmethod
    async def search(
        self,
        query: str,
        filters: dict | None = None,
        limit: int = 20,
        offset: int = 0
    ) -> tuple[list['User'], int]:
        """Search users with filters.
        
        Args:
            query: Search query for name/email/username
            filters: Additional filters (status, role, etc.)
            limit: Maximum number of results
            offset: Number of results to skip
            
        Returns:
            Tuple of (users, total_count)
        """
        ...