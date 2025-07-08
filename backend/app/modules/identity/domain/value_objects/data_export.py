"""
Data Export Value Object

Represents the result of a data export operation.
"""

from dataclasses import dataclass
from datetime import datetime

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class DataExport(ValueObject):
    """
    Value object representing a data export result.
    
    Encapsulates export metadata and access information
    for compliance and data portability operations.
    """
    
    export_id: str
    format: str
    size_bytes: int
    created_at: datetime
    expires_at: datetime | None = None
    download_url: str | None = None
    checksum: str | None = None
    
    def __post_init__(self) -> None:
        """Validate export data."""
        if self.size_bytes < 0:
            raise ValueError("Export size cannot be negative")
        
        if self.expires_at and self.expires_at <= self.created_at:
            raise ValueError("Export expiry must be after creation time")
    
    def is_expired(self) -> bool:
        """Check if export has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    def get_size_mb(self) -> float:
        """Get export size in megabytes."""
        return self.size_bytes / (1024 * 1024)
