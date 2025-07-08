"""
Thumbnail Set Value Object

Represents a set of avatar thumbnails with different sizes.
"""

from dataclasses import dataclass
from typing import Any

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class ThumbnailInfo:
    """Information about a single thumbnail."""
    size: int
    url: str
    file_path: str
    size_bytes: int


@dataclass(frozen=True)
class ThumbnailSet(ValueObject):
    """
    Value object representing a set of avatar thumbnails.
    
    Encapsulates multiple thumbnail sizes and their access information
    for responsive avatar display.
    """
    
    original_storage_id: str
    thumbnails: dict[int, ThumbnailInfo]  # size -> thumbnail info
    created_at: str | None = None
    metadata: dict[str, Any] | None = None
    
    def __post_init__(self) -> None:
        """Validate thumbnail set data."""
        if not self.thumbnails:
            raise ValueError("Thumbnail set cannot be empty")
        
        for size, thumbnail in self.thumbnails.items():
            if size <= 0:
                raise ValueError("Thumbnail size must be positive")
            if thumbnail.size != size:
                raise ValueError("Thumbnail size mismatch")
    
    def get_available_sizes(self) -> list[int]:
        """Get list of available thumbnail sizes."""
        return sorted(self.thumbnails.keys())
    
    def get_thumbnail(self, size: int) -> ThumbnailInfo | None:
        """Get thumbnail for specific size."""
        return self.thumbnails.get(size)
    
    def get_closest_thumbnail(self, target_size: int) -> ThumbnailInfo | None:
        """Get thumbnail closest to target size."""
        if not self.thumbnails:
            return None
        
        available_sizes = self.get_available_sizes()
        closest_size = min(available_sizes, key=lambda x: abs(x - target_size))
        return self.thumbnails[closest_size]
    
    def get_largest_thumbnail(self) -> ThumbnailInfo | None:
        """Get largest available thumbnail."""
        if not self.thumbnails:
            return None
        
        largest_size = max(self.thumbnails.keys())
        return self.thumbnails[largest_size]
    
    def get_smallest_thumbnail(self) -> ThumbnailInfo | None:
        """Get smallest available thumbnail."""
        if not self.thumbnails:
            return None
        
        smallest_size = min(self.thumbnails.keys())
        return self.thumbnails[smallest_size]
