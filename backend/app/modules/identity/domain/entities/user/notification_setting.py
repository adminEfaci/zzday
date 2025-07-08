"""
Notification Setting Entity

Manages user notification preferences and channels.
"""

from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Any
from uuid import UUID, uuid4

from app.core.domain.base import Entity


@dataclass
class NotificationSetting(Entity):
    """Entity representing user notification preferences."""
    
    id: UUID
    user_id: UUID
    channel: str  # email, sms, push, in_app
    enabled: bool = True
    category: str | None = None  # security, marketing, updates, etc.
    frequency: str = "immediate"  # immediate, daily, weekly
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    
    def __post_init__(self) -> None:
        """Initialize entity and validate."""
        super().__post_init__()
        self._validate_entity()
    
    def _validate_entity(self) -> None:
        """Validate entity state."""
        if not self.channel:
            raise ValueError("Notification channel is required")
        
        valid_channels = {"email", "sms", "push", "in_app"}
        if self.channel not in valid_channels:
            raise ValueError(f"Invalid channel: {self.channel}. Must be one of: {', '.join(valid_channels)}")
        
        valid_frequencies = {"immediate", "hourly", "daily", "weekly", "monthly"}
        if self.frequency not in valid_frequencies:
            raise ValueError(f"Invalid frequency: {self.frequency}. Must be one of: {', '.join(valid_frequencies)}")
        
        # Validate category if provided
        if self.category:
            valid_categories = {
                "security", "marketing", "updates", "system", "task_reminders", 
                "account_updates", "promotions", "newsletters", "alerts"
            }
            if self.category not in valid_categories:
                raise ValueError(f"Invalid category: {self.category}. Must be one of: {', '.join(valid_categories)}")
    
    @classmethod
    def create(
        cls,
        user_id: UUID,
        channel: str,
        category: str | None = None,
        enabled: bool = True,
        frequency: str = "immediate",
        metadata: dict[str, Any] | None = None
    ) -> "NotificationSetting":
        """Create a new notification setting."""
        return cls(
            id=uuid4(),
            user_id=user_id,
            channel=channel,
            category=category,
            enabled=enabled,
            frequency=frequency,
            metadata=metadata or {}
        )
    
    def enable(self) -> None:
        """Enable notifications for this setting."""
        self.enabled = True
        self.updated_at = datetime.now(UTC)
    
    def disable(self) -> None:
        """Disable notifications for this setting."""
        self.enabled = False
        self.updated_at = datetime.now(UTC)
    
    def update_frequency(self, frequency: str) -> None:
        """Update notification frequency."""
        valid_frequencies = {"immediate", "hourly", "daily", "weekly", "monthly"}
        if frequency not in valid_frequencies:
            raise ValueError(f"Invalid frequency: {frequency}. Must be one of: {', '.join(valid_frequencies)}")
        
        self.frequency = frequency
        self.updated_at = datetime.now(UTC)
    
    def update_metadata(self, key: str, value: Any) -> None:
        """Update metadata for this setting."""
        if not key or not key.strip():
            raise ValueError("Metadata key cannot be empty")
        
        self.metadata[key] = value
        self.updated_at = datetime.now(UTC)
    
    def remove_metadata(self, key: str) -> None:
        """Remove metadata key."""
        if key in self.metadata:
            del self.metadata[key]
            self.updated_at = datetime.now(UTC)
    
    def is_active_for_frequency(self, current_frequency: str) -> bool:
        """Check if this setting should be active for the given frequency."""
        if not self.enabled:
            return False
        
        frequency_hierarchy = {
            "immediate": 0,
            "hourly": 1,
            "daily": 2,
            "weekly": 3,
            "monthly": 4
        }
        
        setting_level = frequency_hierarchy.get(self.frequency, 0)
        current_level = frequency_hierarchy.get(current_frequency, 0)
        
        return current_level >= setting_level
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "channel": self.channel,
            "category": self.category,
            "enabled": self.enabled,
            "frequency": self.frequency,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }