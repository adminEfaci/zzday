"""User Profile Repository Interface

Domain contract for user profile data access that must be implemented by the infrastructure layer.
"""

from datetime import date
from typing import Protocol
from uuid import UUID


class IUserProfileRepository(Protocol):
    """Repository interface for user profile management."""
    
    async def create(
        self, 
        user_id: UUID,
        display_name: str | None = None,
        bio: str | None = None,
        avatar_url: str | None = None,
        date_of_birth: date | None = None,
        timezone: str | None = None,
        locale: str | None = None,
        metadata: dict | None = None
    ) -> UUID:
        """Create user profile.
        
        Args:
            user_id: User identifier
            display_name: User's display name
            bio: User biography
            avatar_url: URL to user's avatar image
            date_of_birth: User's date of birth
            timezone: User's timezone
            locale: User's locale
            metadata: Additional profile metadata
            
        Returns:
            Created profile ID
        """
        ...
    
    async def find_by_user(self, user_id: UUID) -> dict | None:
        """Find profile by user ID.
        
        Args:
            user_id: User identifier
            
        Returns:
            Profile data if found, None otherwise
        """
        ...
    
    async def update(
        self, 
        user_id: UUID,
        display_name: str | None = None,
        bio: str | None = None,
        avatar_url: str | None = None,
        date_of_birth: date | None = None,
        timezone: str | None = None,
        locale: str | None = None,
        metadata: dict | None = None
    ) -> bool:
        """Update user profile.
        
        Args:
            user_id: User identifier
            display_name: New display name
            bio: New biography
            avatar_url: New avatar URL
            date_of_birth: New date of birth
            timezone: New timezone
            locale: New locale
            metadata: New metadata
            
        Returns:
            True if updated, False if not found
        """
        ...
    
    async def update_avatar(self, user_id: UUID, avatar_url: str) -> bool:
        """Update user avatar.
        
        Args:
            user_id: User identifier
            avatar_url: New avatar URL
            
        Returns:
            True if updated, False if not found
        """
        ...
    
    async def delete_avatar(self, user_id: UUID) -> bool:
        """Delete user avatar.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if deleted, False if not found
        """
        ...
    
    async def search_profiles(
        self, 
        query: str,
        limit: int = 20
    ) -> list[dict]:
        """Search user profiles by display name or bio.
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of matching profiles
        """
        ...
    
    async def delete_profile(self, user_id: UUID) -> bool:
        """Delete user profile.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if deleted, False if not found
        """
        ...