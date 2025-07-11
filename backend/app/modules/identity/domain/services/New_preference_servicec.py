"""
User Preference Domain Service

Handles preference updates and validation logic.
"""

from typing import Any

from app.modules.identity.domain.entities.user.preference import UserPreference
from app.modules.identity.domain.entities.user.user_enums import Language


class UserPreferenceService:
    """Domain service for user preference operations."""
    
    def update_user_preference(
        self,
        preference: UserPreference,
        category: str,
        key: str,
        value: Any
    ) -> None:
        """Update a user preference with validation and events."""
        # Validate inputs
        if not category or not key:
            raise ValueError("Category and key cannot be empty")
        
        # Store old value for event
        old_value = self._get_current_value(preference, category, key)
        
        # Update based on category
        if category == "notification":
            self._update_notification_setting(preference, key, value)
        elif category == "privacy":
            self._update_privacy_setting(preference, key, value)
        elif category == "accessibility":
            self._update_accessibility_setting(preference, key, value)
        elif hasattr(preference, key):
            self._update_direct_setting(preference, key, value)
        else:
            raise ValueError(f"Unknown preference: {category}.{key}")
        
        # Emit preference change event
        from ..user_events import ProfileUpdated
        preference.add_domain_event(ProfileUpdated(
            user_id=preference.user_id,
            updated_fields=[f"{category}.{key}"],
            previous_values={f"{category}.{key}": old_value},
            new_values={f"{category}.{key}": value}
        ))
    
    def validate_preference_settings(self, preference: UserPreference) -> list[str]:
        """Validate all preference settings and return issues."""
        issues = []
        
        # Validate language
        if not isinstance(preference.language, Language):
            issues.append("Invalid language setting")
        
        # Validate theme
        if preference.theme not in ["light", "dark", "auto"]:
            issues.append("Invalid theme")
        
        # Validate email digest frequency
        if preference.email_digest_frequency not in ["daily", "weekly", "monthly", "never"]:
            issues.append("Invalid email digest frequency")
        
        # Validate message settings
        if preference.allow_messages_from not in ["all", "contacts", "none"]:
            issues.append("Invalid message permission setting")
        
        # Validate notification channels
        valid_channels = ["email", "sms", "push", "in_app"]
        for notif_type, settings in preference.notification_settings.items():
            if "channels" in settings:
                invalid_channels = [c for c in settings["channels"] if c not in valid_channels]
                if invalid_channels:
                    issues.append(f"Invalid notification channels for {notif_type}: {invalid_channels}")
        
        return issues
    
    def _get_current_value(self, preference: UserPreference, category: str, key: str) -> Any:
        """Get current value for a preference."""
        if category == "notification":
            return preference.notification_settings.get(key)
        if category == "privacy":
            return preference.privacy_settings.get(key)
        if category == "accessibility":
            return preference.accessibility_settings.get(key)
        if hasattr(preference, key):
            return getattr(preference, key)
        return None
    
    def _update_notification_setting(self, preference: UserPreference, key: str, value: Any) -> None:
        """Update notification setting with validation."""
        if not isinstance(value, dict):
            raise ValueError("Notification settings must be dictionaries")
        
        # Validate notification setting structure
        if "enabled" in value and not isinstance(value["enabled"], bool):
            raise ValueError("Notification 'enabled' must be boolean")
        
        if "channels" in value:
            valid_channels = ["email", "sms", "push", "in_app"]
            if not isinstance(value["channels"], list):
                raise ValueError("Notification channels must be a list")
            
            invalid_channels = [c for c in value["channels"] if c not in valid_channels]
            if invalid_channels:
                raise ValueError(f"Invalid notification channels: {invalid_channels}")
        
        if key in preference.notification_settings:
            preference.notification_settings[key].update(value)
        else:
            preference.notification_settings[key] = value
    
    def _update_privacy_setting(self, preference: UserPreference, key: str, value: Any) -> None:
        """Update privacy setting with validation."""
        # Validate specific privacy settings
        if key == "profile_visibility" and value not in ["public", "contacts", "private"]:
            raise ValueError("Profile visibility must be 'public', 'contacts', or 'private'")
        
        if key in ["email_visible", "phone_visible", "location_visible"] and not isinstance(value, bool):
            raise ValueError(f"{key} must be boolean")
        
        preference.privacy_settings[key] = value
    
    def _update_accessibility_setting(self, preference: UserPreference, key: str, value: Any) -> None:
        """Update accessibility setting with validation."""
        # Validate specific accessibility settings
        if key == "font_size" and value not in ["small", "medium", "large", "extra-large"]:
            raise ValueError("Font size must be 'small', 'medium', 'large', or 'extra-large'")
        
        if key in ["high_contrast", "reduce_motion", "screen_reader_optimized"] and not isinstance(value, bool):
            raise ValueError(f"{key} must be boolean")
        
        preference.accessibility_settings[key] = value
    
    def _update_direct_setting(self, preference: UserPreference, key: str, value: Any) -> None:
        """Update direct setting with validation."""
        # Validate specific direct settings
        if key == "language" and not isinstance(value, Language):
            if isinstance(value, str):
                try:
                    value = Language(value)
                except ValueError as e:
                    raise ValueError(f"Invalid language: {value}") from e
            else:
                raise ValueError("Language must be a Language enum or string")
        
        if key == "theme" and value not in ["light", "dark", "auto"]:
            raise ValueError("Theme must be 'light', 'dark', or 'auto'")
        
        if key == "email_digest_frequency" and value not in ["daily", "weekly", "monthly", "never"]:
            raise ValueError("Email digest frequency must be 'daily', 'weekly', 'monthly', or 'never'")
        
        setattr(preference, key, value)