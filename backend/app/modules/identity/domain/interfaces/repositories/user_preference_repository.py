"""User Preference Repository Interface

Domain contract for user preference data access that must be implemented by the infrastructure layer.
"""

from typing import Any, Protocol
from uuid import UUID


class IUserPreferenceRepository(Protocol):
    """Repository interface for user preference management."""
    
    async def create(
        self, 
        user_id: UUID,
        key: str,
        value: Any,
        category: str | None = None
    ) -> UUID:
        """Create user preference.
        
        Args:
            user_id: User identifier
            key: Preference key
            value: Preference value
            category: Optional preference category
            
        Returns:
            Created preference ID
        """
        ...
    
    async def find_by_user(self, user_id: UUID) -> dict[str, Any]:
        """Find all preferences for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dictionary of preferences (key -> value)
        """
        ...
    
    async def find_by_key(self, user_id: UUID, key: str) -> Any | None:
        """Find specific preference for user.
        
        Args:
            user_id: User identifier
            key: Preference key
            
        Returns:
            Preference value if found, None otherwise
        """
        ...
    
    async def find_by_category(
        self, 
        user_id: UUID, 
        category: str
    ) -> dict[str, Any]:
        """Find preferences by category for user.
        
        Args:
            user_id: User identifier
            category: Preference category
            
        Returns:
            Dictionary of preferences in category
        """
        ...
    
    async def set_preference(
        self, 
        user_id: UUID,
        key: str,
        value: Any,
        category: str | None = None
    ) -> bool:
        """Set user preference (create or update).
        
        Args:
            user_id: User identifier
            key: Preference key
            value: Preference value
            category: Optional preference category
            
        Returns:
            True if set successfully
        """
        ...
    
    async def update_preferences(
        self, 
        user_id: UUID,
        preferences: dict[str, Any]
    ) -> bool:
        """Update multiple preferences at once.
        
        Args:
            user_id: User identifier
            preferences: Dictionary of preferences to update
            
        Returns:
            True if updated successfully
        """
        ...
    
    async def delete_preference(self, user_id: UUID, key: str) -> bool:
        """Delete specific preference.
        
        Args:
            user_id: User identifier
            key: Preference key
            
        Returns:
            True if deleted, False if not found
        """
        ...
    
    async def delete_all_preferences(self, user_id: UUID) -> int:
        """Delete all preferences for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of preferences deleted
        """
        ...