"""
Avatar Storage Value Object

Represents avatar storage metadata and access information.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class AvatarStorage(ValueObject):
    """
    Value object representing avatar storage metadata.
    
    Encapsulates storage location, access URLs, and metadata
    for avatar file management.
    """
    
    storage_id: str
    file_path: str
    content_type: str
    size_bytes: int
    width: int | None = None
    height: int | None = None
    upload_url: str | None = None
    public_url: str | None = None
    created_at: datetime | None = None
    metadata: dict[str, Any] | None = None
    
    def __post_init__(self) -> None:
        """Validate avatar storage data."""
        if self.size_bytes < 0:
            raise ValueError("File size cannot be negative")
        
        if self.width is not None and self.width <= 0:
            raise ValueError("Width must be positive")
        
        if self.height is not None and self.height <= 0:
            raise ValueError("Height must be positive")
    
    def get_size_mb(self) -> float:
        """Get file size in megabytes."""
        return self.size_bytes / (1024 * 1024)
    
    def has_dimensions(self) -> bool:
        """Check if avatar has dimension information."""
        return self.width is not None and self.height is not None
    
    def is_square(self) -> bool:
        """Check if avatar is square."""
        return (
            self.has_dimensions() and 
            self.width == self.height
        )
    
    def get_aspect_ratio(self) -> float | None:
        """Get aspect ratio (width/height)."""
        if not self.has_dimensions() or self.height == 0:
            return None
        return self.width / self.height
