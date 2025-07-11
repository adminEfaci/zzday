"""Password History Repository Interface

Domain contract for password history tracking that must be implemented by the infrastructure layer.
"""

from abc import abstractmethod
from typing import Protocol
from uuid import UUID


class IPasswordHistoryRepository(Protocol):
    """Repository interface for password history management."""
    
    @abstractmethod
    async def create(
        self, 
        user_id: UUID,
        password_hash: str,
        changed_by: UUID | None = None
    ) -> UUID:
        """Record password change.
        
        Args:
            user_id: User identifier
            password_hash: Hashed password value
            changed_by: ID of user who changed password (for admin changes)
            
        Returns:
            Created history entry ID
        """
        ...
    
    @abstractmethod
    async def find_recent_passwords(
        self, 
        user_id: UUID,
        limit: int = 12
    ) -> list[str]:
        """Get recent password hashes for user.
        
        Args:
            user_id: User identifier
            limit: Number of recent passwords to return
            
        Returns:
            List of password hashes
        """
        ...
    
    @abstractmethod
    async def is_password_reused(
        self, 
        user_id: UUID,
        password_hash: str,
        check_last: int = 12
    ) -> bool:
        """Check if password was recently used.
        
        Args:
            user_id: User identifier
            password_hash: Password hash to check
            check_last: Number of recent passwords to check
            
        Returns:
            True if password was recently used
        """
        ...
    
    @abstractmethod
    async def count_password_changes(
        self, 
        user_id: UUID
    ) -> int:
        """Count total password changes for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of password changes
        """
        ...
    
    @abstractmethod
    async def cleanup_old_history(
        self, 
        user_id: UUID,
        keep_last: int = 12
    ) -> int:
        """Remove old password history entries.
        
        Args:
            user_id: User identifier
            keep_last: Number of recent entries to keep
            
        Returns:
            Number of entries removed
        """
        ...