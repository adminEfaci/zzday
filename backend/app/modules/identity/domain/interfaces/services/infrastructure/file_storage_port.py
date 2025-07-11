"""
File Storage Port Interface

Port for file storage operations, particularly user avatars.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

if TYPE_CHECKING:
    from ...value_objects.avatar_storage import AvatarStorage
    from ...value_objects.thumbnail_set import ThumbnailSet


class IFileStoragePort(ABC):
    """Port for file storage operations."""
    
    @abstractmethod
    async def store_avatar(
        self,
        user_id: UUID,
        file_data: BinaryIO,
        content_type: str
    ) -> "AvatarStorage":
        """
        Store user avatar.
        
        Args:
            user_id: User identifier
            file_data: Avatar file data
            content_type: MIME type
            
        Returns:
            AvatarStorage value object containing storage metadata
        """
    
    @abstractmethod
    async def delete_avatar(self, user_id: UUID) -> bool:
        """
        Delete user avatar.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if deleted successfully
        """
    
    @abstractmethod
    async def generate_avatar_url(
        self,
        user_id: UUID,
        size: int | None = None
    ) -> str:
        """
        Generate avatar URL.
        
        Args:
            user_id: User identifier
            size: Optional size parameter
            
        Returns:
            Avatar URL
        """
    
    @abstractmethod
    async def process_avatar_thumbnails(
        self,
        user_id: UUID,
        avatar_storage: "AvatarStorage"
    ) -> "ThumbnailSet":
        """
        Process avatar thumbnails.
        
        Args:
            user_id: User identifier
            avatar_storage: Original avatar storage reference
            
        Returns:
            ThumbnailSet value object containing thumbnail references
        """
