"""
User Preference Entity

Represents user preferences and settings.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.domain.base import Entity

from .user_enums import DateFormat, Language, TimeFormat


@dataclass
class UserPreference(Entity):
    """User preference entity for personalization settings."""
    
    user_id: UUID
    language: Language = Language.EN
    timezone: str = "UTC"
    date_format: DateFormat = DateFormat.ISO
    time_format: TimeFormat = TimeFormat.TWENTY_FOUR_HOUR
    notification_settings: dict[str, dict[str, Any]] = field(default_factory=dict)
    privacy_settings: dict[str, Any] = field(default_factory=dict)
    accessibility_settings: dict[str, Any] = field(default_factory=dict)
    theme: str = "light"
    email_digest_frequency: str = "weekly"
    show_profile_publicly: bool = False
    allow_messages_from: str = "contacts"  # all, contacts, none
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    
    def __post_init__(self):
        """Initialize user preference entity."""
        super().__post_init__()
        
        # Set default notification settings if not provided
        if not self.notification_settings:
            self.notification_settings = self._get_default_notification_settings()
        
        # Set default privacy settings if not provided
        if not self.privacy_settings:
            self.privacy_settings = self._get_default_privacy_settings()
        
        # Set default accessibility settings if not provided
        if not self.accessibility_settings:
            self.accessibility_settings = self._get_default_accessibility_settings()
        
        # Validate all settings
        self._validate_preferences()
    
    def _validate_preferences(self) -> None:
        """Validate all preference settings."""
        # Validate timezone
        self._validate_timezone()
        
        # Validate theme
        valid_themes = {"light", "dark", "system", "high_contrast"}
        if self.theme not in valid_themes:
            raise ValueError(f"Invalid theme: {self.theme}. Must be one of: {', '.join(valid_themes)}")
        
        # Validate email digest frequency
        valid_frequencies = {"immediate", "daily", "weekly", "monthly", "never"}
        if self.email_digest_frequency not in valid_frequencies:
            raise ValueError(f"Invalid email digest frequency: {self.email_digest_frequency}. Must be one of: {', '.join(valid_frequencies)}")
        
        # Validate allow_messages_from
        valid_message_settings = {"all", "contacts", "none"}
        if self.allow_messages_from not in valid_message_settings:
            raise ValueError(f"Invalid allow_messages_from: {self.allow_messages_from}. Must be one of: {', '.join(valid_message_settings)}")
    
    def _validate_timezone(self) -> None:
        """Validate timezone format and value."""
        # Common timezone patterns
        utc_pattern = r'^UTC([+-]\d{1,2}(:30)?)?$'
        region_pattern = r'^[A-Z][a-z_]+/[A-Z][a-z_]+$'
        
        # List of common valid timezones
        common_timezones = {
            "UTC", "GMT",
            "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
            "America/Toronto", "America/Mexico_City", "America/Sao_Paulo", "America/Argentina/Buenos_Aires",
            "Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Rome", "Europe/Madrid",
            "Europe/Amsterdam", "Europe/Stockholm", "Europe/Moscow",
            "Asia/Tokyo", "Asia/Shanghai", "Asia/Hong_Kong", "Asia/Singapore", "Asia/Kolkata",
            "Asia/Dubai", "Asia/Tehran", "Asia/Jakarta", "Asia/Manila",
            "Australia/Sydney", "Australia/Melbourne", "Australia/Perth",
            "Pacific/Auckland", "Pacific/Honolulu",
            "Africa/Cairo", "Africa/Johannesburg", "Africa/Lagos"
        }
        
        # Validate timezone
        if (self.timezone not in common_timezones and 
            not re.match(utc_pattern, self.timezone) and 
            not re.match(region_pattern, self.timezone)):
            raise ValueError(f"Invalid timezone format: {self.timezone}")
    
    @classmethod
    def create(cls, user_id: UUID) -> 'UserPreference':
        """Create default user preferences."""
        return cls(
            user_id=user_id,
            notification_settings=cls._get_default_notification_settings(),
            privacy_settings=cls._get_default_privacy_settings(),
            accessibility_settings=cls._get_default_accessibility_settings()
        )
    
    @staticmethod
    def _get_default_notification_settings() -> dict[str, dict[str, Any]]:
        """Get default notification settings."""
        return {
            "security_alerts": {
                "enabled": True,
                "channels": ["email", "push"],
                "immediate": True
            },
            "account_updates": {
                "enabled": True,
                "channels": ["email"],
                "immediate": False
            },
            "marketing": {
                "enabled": False,
                "channels": ["email"],
                "immediate": False
            },
            "task_reminders": {
                "enabled": True,
                "channels": ["email", "push"],
                "immediate": True
            },
            "system_updates": {
                "enabled": True,
                "channels": ["email"],
                "immediate": False
            }
        }
    
    @staticmethod
    def _get_default_privacy_settings() -> dict[str, Any]:
        """Get default privacy settings."""
        return {
            "profile_visibility": "private",  # public, contacts, private
            "email_visible": False,
            "phone_visible": False,
            "location_visible": False,
            "activity_status_visible": True,
            "search_indexing": False,
            "data_collection": {
                "analytics": True,
                "personalization": True,
                "third_party_sharing": False
            }
        }
    
    @staticmethod
    def _get_default_accessibility_settings() -> dict[str, Any]:
        """Get default accessibility settings."""
        return {
            "high_contrast": False,
            "font_size": "medium",  # small, medium, large, extra-large
            "reduce_motion": False,
            "screen_reader_optimized": False,
            "keyboard_navigation": True,
            "focus_indicators": True,
            "alt_text_images": True,
            "captions": True
        }
    
    def update_timezone(self, timezone: str) -> None:
        """Update timezone with validation."""
        old_timezone = self.timezone
        self.timezone = timezone
        
        try:
            self._validate_timezone()
            self.updated_at = datetime.now(UTC)
        except ValueError:
            # Revert if validation fails
            self.timezone = old_timezone
            raise
    
    def update_language(self, language: Language) -> None:
        """Update language preference."""
        self.language = language
        self.updated_at = datetime.now(UTC)
    
    def update_theme(self, theme: str) -> None:
        """Update theme preference."""
        valid_themes = {"light", "dark", "system", "high_contrast"}
        if theme not in valid_themes:
            raise ValueError(f"Invalid theme: {theme}. Must be one of: {', '.join(valid_themes)}")
        
        self.theme = theme
        self.updated_at = datetime.now(UTC)
    
    def update_notification_setting(self, notification_type: str, setting_key: str, value: Any) -> None:
        """Update a specific notification setting."""
        if notification_type not in self.notification_settings:
            self.notification_settings[notification_type] = {}
        
        self.notification_settings[notification_type][setting_key] = value
        self.updated_at = datetime.now(UTC)
    
    def update_privacy_setting(self, setting_key: str, value: Any) -> None:
        """Update a privacy setting."""
        # Handle nested settings
        if "." in setting_key:
            parent_key, child_key = setting_key.split(".", 1)
            if parent_key not in self.privacy_settings:
                self.privacy_settings[parent_key] = {}
            self.privacy_settings[parent_key][child_key] = value
        else:
            self.privacy_settings[setting_key] = value
        
        self.updated_at = datetime.now(UTC)
    
    def update_accessibility_setting(self, setting_key: str, value: Any) -> None:
        """Update an accessibility setting."""
        valid_font_sizes = {"small", "medium", "large", "extra-large"}
        if setting_key == "font_size" and value not in valid_font_sizes:
            raise ValueError(f"Invalid font size: {value}. Must be one of: {', '.join(valid_font_sizes)}")
        
        self.accessibility_settings[setting_key] = value
        self.updated_at = datetime.now(UTC)
    
    def reset_to_defaults(self, category: str | None = None) -> None:
        """Reset preferences to defaults."""
        if category == "notification" or category is None:
            self.notification_settings = self._get_default_notification_settings()
        
        if category == "privacy" or category is None:
            self.privacy_settings = self._get_default_privacy_settings()
        
        if category == "accessibility" or category is None:
            self.accessibility_settings = self._get_default_accessibility_settings()
        
        if category is None:
            # Reset all other preferences
            self.language = Language.EN
            self.timezone = "UTC"
            self.date_format = DateFormat.ISO
            self.time_format = TimeFormat.TWENTY_FOUR_HOUR
            self.theme = "light"
            self.email_digest_frequency = "weekly"
            self.show_profile_publicly = False
            self.allow_messages_from = "contacts"
        
        self.updated_at = datetime.now(UTC)
    
    # Simple getters only
    def get_notification_channels(self, notification_type: str) -> list[str]:
        """Get enabled notification channels for a type."""
        settings = self.notification_settings.get(notification_type, {})
        
        if not settings.get("enabled", False):
            return []
        
        return settings.get("channels", [])
    
    def is_notification_enabled(self, notification_type: str) -> bool:
        """Check if notification type is enabled."""
        settings = self.notification_settings.get(notification_type, {})
        return settings.get("enabled", False)
    
    def get_privacy_level(self) -> str:
        """Get overall privacy level."""
        visibility = self.privacy_settings.get("profile_visibility", "private")
        
        if visibility == "public" and self.show_profile_publicly:
            return "low"
        if visibility == "contacts":
            return "medium"
        return "high"
    
    def format_date(self, date: datetime) -> str:
        """Format date according to user preference."""
        if self.date_format == DateFormat.US:
            return date.strftime("%m/%d/%Y")
        if self.date_format == DateFormat.EUROPEAN:
            return date.strftime("%d/%m/%Y")
        if self.date_format == DateFormat.ISO:
            return date.strftime("%Y-%m-%d")
        return date.strftime("%b %d, %Y")  # Friendly format
    
    def format_time(self, time: datetime) -> str:
        """Format time according to user preference."""
        if self.time_format == TimeFormat.TWELVE_HOUR:
            return time.strftime("%I:%M %p")
        return time.strftime("%H:%M")
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "user_id": str(self.user_id),
            "language": self.language.value,
            "timezone": self.timezone,
            "date_format": self.date_format.value,
            "time_format": self.time_format.value,
            "notification_settings": self.notification_settings,
            "privacy_settings": self.privacy_settings,
            "accessibility_settings": self.accessibility_settings,
            "theme": self.theme,
            "email_digest_frequency": self.email_digest_frequency,
            "show_profile_publicly": self.show_profile_publicly,
            "allow_messages_from": self.allow_messages_from,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }