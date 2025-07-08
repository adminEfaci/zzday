"""
Audit Export Value Object

Represents audit log export metadata and access information.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class AuditExport(ValueObject):
    """
    Value object representing audit log export metadata.
    
    Encapsulates export details, access information, and metadata
    for audit log export operations.
    """
    
    export_id: str
    format: str
    record_count: int
    size_bytes: int
    created_at: datetime
    expires_at: datetime | None = None
    download_url: str | None = None
    filters_applied: dict[str, Any] | None = None
    checksum: str | None = None
    
    def __post_init__(self) -> None:
        """Validate audit export data."""
        if self.record_count < 0:
            raise ValueError("Record count cannot be negative")
        
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
    
    def has_filters(self) -> bool:
        """Check if export was created with filters."""
        return bool(self.filters_applied)
    
    def is_empty(self) -> bool:
        """Check if export contains no records."""
        return self.record_count == 0
