"""
User Preference Model

SQLModel definition for user preference persistence.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlmodel import JSON, Column, Field, SQLModel

from app.modules.identity.domain.entities.user.preference import UserPreference
from app.modules.identity.domain.entities.user.user_enums import (
    DateFormat,
    Language,
    TimeFormat,
)


class UserPreferenceModel(SQLModel, table=True):
    """User preference persistence model."""
    
    __tablename__ = "user_preferences"
    
    # Identity
    id: UUID = Field(primary_key=True)
    user_id: UUID = Field(unique=True, index=True)
    
    # Basic preferences
    language: str = Field(default=Language.EN.value)
    timezone: str = Field(default="UTC")
    date_format: str = Field(default=DateFormat.ISO.value)
    time_format: str = Field(default=TimeFormat.TWENTY_FOUR_HOUR.value)
    theme: str = Field(default="light")
    
    # Communication preferences
    email_digest_frequency: str = Field(default="weekly")
    show_profile_publicly: bool = Field(default=False)
    allow_messages_from: str = Field(default="contacts")
    
    # Settings stored as JSON
    notification_settings: dict[str, dict[str, Any]] = Field(
        default_factory=dict, 
        sa_column=Column(JSON)
    )
    privacy_settings: dict[str, Any] = Field(
        default_factory=dict, 
        sa_column=Column(JSON)
    )
    accessibility_settings: dict[str, Any] = Field(
        default_factory=dict, 
        sa_column=Column(JSON)
    )
    
    # Metadata
    custom_preferences: dict[str, Any] = Field(
        default_factory=dict, 
        sa_column=Column(JSON)
    )
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    
    @classmethod
    def from_domain(cls, preference: UserPreference) -> "UserPreferenceModel":
        """Create model from domain entity."""
        return cls(
            id=preference.id,
            user_id=preference.user_id,
            language=preference.language.value if isinstance(preference.language, Language) else preference.language,
            timezone=preference.timezone,
            date_format=preference.date_format.value if isinstance(preference.date_format, DateFormat) else preference.date_format,
            time_format=preference.time_format.value if isinstance(preference.time_format, TimeFormat) else preference.time_format,
            theme=preference.theme,
            email_digest_frequency=preference.email_digest_frequency,
            show_profile_publicly=preference.show_profile_publicly,
            allow_messages_from=preference.allow_messages_from,
            notification_settings=preference.notification_settings.copy(),
            privacy_settings=preference.privacy_settings.copy(),
            accessibility_settings=preference.accessibility_settings.copy(),
            created_at=preference.created_at,
            updated_at=preference.updated_at
        )
    
    def to_domain(self) -> UserPreference:
        """Convert to domain entity."""
        # Reconstruct enums
        language = Language(self.language) if self.language else Language.EN
        date_format = DateFormat(self.date_format) if self.date_format else DateFormat.ISO
        time_format = TimeFormat(self.time_format) if self.time_format else TimeFormat.TWENTY_FOUR_HOUR
        
        # Create preference instance
        preference = UserPreference(
            id=self.id,
            user_id=self.user_id,
            language=language,
            timezone=self.timezone,
            date_format=date_format,
            time_format=time_format,
            notification_settings=self.notification_settings.copy() if self.notification_settings else {},
            privacy_settings=self.privacy_settings.copy() if self.privacy_settings else {},
            accessibility_settings=self.accessibility_settings.copy() if self.accessibility_settings else {},
            theme=self.theme,
            email_digest_frequency=self.email_digest_frequency,
            show_profile_publicly=self.show_profile_publicly,
            allow_messages_from=self.allow_messages_from,
            created_at=self.created_at,
            updated_at=self.updated_at
        )
        
        return preference
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "user_id": str(self.user_id),
            "language": self.language,
            "timezone": self.timezone,
            "date_format": self.date_format,
            "time_format": self.time_format,
            "theme": self.theme,
            "email_digest_frequency": self.email_digest_frequency,
            "show_profile_publicly": self.show_profile_publicly,
            "allow_messages_from": self.allow_messages_from,
            "notification_settings": self.notification_settings,
            "privacy_settings": self.privacy_settings,
            "accessibility_settings": self.accessibility_settings,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }