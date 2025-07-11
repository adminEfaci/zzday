"""
Preference Domain Service

Handles user preference management with comprehensive validation and business logic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User

from ...entities.user.preference import Preference, UserPreference
from ...entities.user.user_events import UserPreferencesUpdated, ProfileUpdated
from ...enums import PreferenceCategory, PreferenceType, Language


class PreferenceService:
    """Domain service for user preference operations."""
    
    # Default preference values
    DEFAULT_PREFERENCES = {
        PreferenceCategory.NOTIFICATION: {
            "email_notifications": True,
            "push_notifications": True,
            "sms_notifications": False,
            "marketing_emails": False,
            "security_alerts": True,
            "account_updates": True,
            "newsletter": False,
        },
        PreferenceCategory.PRIVACY: {
            "profile_visibility": "public",
            "show_email": False,
            "show_phone": False,
            "show_last_seen": True,
            "allow_indexing": True,
            "data_collection": True,
        },
        PreferenceCategory.DISPLAY: {
            "theme": "system",
            "language": "en",
            "timezone": "UTC",
            "date_format": "MM/DD/YYYY",
            "time_format": "12h",
            "first_day_of_week": "sunday",
        },
        PreferenceCategory.ACCESSIBILITY: {
            "high_contrast": False,
            "reduce_motion": False,
            "screen_reader": False,
            "keyboard_navigation": True,
            "font_size": "medium",
        },
        PreferenceCategory.SECURITY: {
            "two_factor_auth": False,
            "login_notifications": True,
            "device_tracking": True,
            "session_timeout": 30,
            "password_change_reminder": 90,
        },
    }
    
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
        if hasattr(preference, 'language') and not isinstance(preference.language, Language):
            issues.append("Invalid language setting")
        
        # Validate theme
        if hasattr(preference, 'theme') and preference.theme not in ["light", "dark", "auto"]:
            issues.append("Invalid theme")
        
        # Validate email digest frequency
        if hasattr(preference, 'email_digest_frequency') and preference.email_digest_frequency not in ["daily", "weekly", "monthly", "never"]:
            issues.append("Invalid email digest frequency")
        
        # Validate message settings
        if hasattr(preference, 'allow_messages_from') and preference.allow_messages_from not in ["all", "contacts", "none"]:
            issues.append("Invalid message permission setting")
        
        # Validate notification channels
        if hasattr(preference, 'notification_settings'):
            valid_channels = ["email", "sms", "push", "in_app"]
            for notif_type, settings in preference.notification_settings.items():
                if "channels" in settings:
                    invalid_channels = [c for c in settings["channels"] if c not in valid_channels]
                    if invalid_channels:
                        issues.append(f"Invalid notification channels for {notif_type}: {invalid_channels}")
        
        return issues
    
    @staticmethod
    def get_preferences(
        user: User,
        category: PreferenceCategory | None = None
    ) -> dict[str, Any]:
        """
        Get user preferences, optionally filtered by category.
        
        Args:
            user: User aggregate
            category: Optional category filter
            
        Returns:
            Dictionary of preferences
        """
        if not hasattr(user, '_preferences'):
            user._preferences = []
        
        preferences = {}
        
        # Get user's actual preferences
        for pref in user._preferences:
            if category is None or pref.category == category:
                if pref.category not in preferences:
                    preferences[pref.category] = {}
                preferences[pref.category][pref.key] = pref.value
        
        # Fill in defaults for missing preferences
        categories = [category] if category else list(PreferenceCategory)
        for cat in categories:
            if cat not in preferences:
                preferences[cat] = {}
            
            # Add default values for missing keys
            defaults = PreferenceService.DEFAULT_PREFERENCES.get(cat, {})
            for key, default_value in defaults.items():
                if key not in preferences[cat]:
                    preferences[cat][key] = default_value
        
        return preferences[category] if category else preferences
    
    @staticmethod
    def update_preferences(
        user: User,
        updates: dict[str, Any],
        updated_by: UUID | None = None
    ) -> None:
        """
        Update user preferences with validation.
        
        Args:
            user: User aggregate
            updates: Dictionary of preference updates {category: {key: value}}
            updated_by: ID of user performing update
        """
        if not hasattr(user, '_preferences'):
            user._preferences = []
        
        updated_count = 0
        updated_categories = set()
        
        for category_str, prefs in updates.items():
            # Convert category string to enum
            try:
                category = PreferenceCategory(category_str)
            except ValueError:
                continue  # Skip invalid categories
            
            for key, value in prefs.items():
                # Validate preference
                if not PreferenceService._validate_preference(category, key, value):
                    continue
                
                # Find existing preference
                existing = next(
                    (p for p in user._preferences 
                     if p.category == category and p.key == key),
                    None
                )
                
                if existing:
                    # Update existing preference
                    if existing.value != value:
                        existing.value = value
                        existing.updated_at = datetime.now(UTC)
                        updated_count += 1
                        updated_categories.add(category)
                else:
                    # Create new preference
                    pref = Preference.create(
                        user_id=user.id,
                        category=category,
                        key=key,
                        value=value,
                        preference_type=PreferenceService._get_preference_type(value)
                    )
                    user._preferences.append(pref)
                    updated_count += 1
                    updated_categories.add(category)
        
        # Update user timestamp and add event if preferences were changed
        if updated_count > 0:
            user.updated_at = datetime.now(UTC)
            
            user.add_domain_event(UserPreferencesUpdated(
                user_id=user.id,
                updated_by=updated_by or user.id,
                categories=list(updated_categories),
                preference_count=updated_count,
                timestamp=user.updated_at
            ))
    
    @staticmethod
    def reset_preferences(
        user: User,
        category: PreferenceCategory | None = None
    ) -> None:
        """
        Reset preferences to defaults.
        
        Args:
            user: User aggregate
            category: Optional category to reset (None resets all)
        """
        if not hasattr(user, '_preferences'):
            user._preferences = []
        
        if category:
            # Remove preferences for specific category
            user._preferences = [
                p for p in user._preferences 
                if p.category != category
            ]
        else:
            # Remove all preferences
            user._preferences.clear()
        
        user.updated_at = datetime.now(UTC)
        
        # Add event
        user.add_domain_event(UserPreferencesUpdated(
            user_id=user.id,
            updated_by=user.id,
            categories=[category] if category else list(PreferenceCategory),
            preference_count=0,  # 0 indicates reset
            timestamp=user.updated_at
        ))
    
    @staticmethod
    def get_notification_preferences(user: User) -> dict[str, bool]:
        """Get notification-specific preferences."""
        prefs = PreferenceService.get_preferences(user, PreferenceCategory.NOTIFICATION)
        return prefs.get(PreferenceCategory.NOTIFICATION, {})
    
    @staticmethod
    def get_privacy_preferences(user: User) -> dict[str, Any]:
        """Get privacy-specific preferences."""
        prefs = PreferenceService.get_preferences(user, PreferenceCategory.PRIVACY)
        return prefs.get(PreferenceCategory.PRIVACY, {})
    
    @staticmethod
    def get_display_preferences(user: User) -> dict[str, Any]:
        """Get display-specific preferences."""
        prefs = PreferenceService.get_preferences(user, PreferenceCategory.DISPLAY)
        return prefs.get(PreferenceCategory.DISPLAY, {})
    
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
        
        if not hasattr(preference, 'notification_settings'):
            preference.notification_settings = {}
            
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
        
        if not hasattr(preference, 'privacy_settings'):
            preference.privacy_settings = {}
            
        preference.privacy_settings[key] = value
    
    def _update_accessibility_setting(self, preference: UserPreference, key: str, value: Any) -> None:
        """Update accessibility setting with validation."""
        # Validate specific accessibility settings
        if key == "font_size" and value not in ["small", "medium", "large", "extra-large"]:
            raise ValueError("Font size must be 'small', 'medium', 'large', or 'extra-large'")
        
        if key in ["high_contrast", "reduce_motion", "screen_reader_optimized"] and not isinstance(value, bool):
            raise ValueError(f"{key} must be boolean")
        
        if not hasattr(preference, 'accessibility_settings'):
            preference.accessibility_settings = {}
            
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
    
    @staticmethod
    def _validate_preference(
        category: PreferenceCategory,
        key: str,
        value: Any
    ) -> bool:
        """Validate preference value based on category and key."""
        # Check if key is valid for category
        defaults = PreferenceService.DEFAULT_PREFERENCES.get(category, {})
        if key not in defaults:
            return False
        
        # Type validation based on default value type
        default_value = defaults[key]
        if isinstance(default_value, bool):
            return isinstance(value, bool)
        elif isinstance(default_value, int):
            return isinstance(value, int) and value >= 0
        elif isinstance(default_value, str):
            # Additional validation for specific keys
            if key == "theme":
                return value in ["light", "dark", "system"]
            elif key == "profile_visibility":
                return value in ["public", "private", "friends"]
            elif key == "font_size":
                return value in ["small", "medium", "large", "extra-large"]
            elif key == "time_format":
                return value in ["12h", "24h"]
            elif key == "first_day_of_week":
                return value in ["sunday", "monday"]
            return isinstance(value, str)
        
        return True
    
    @staticmethod
    def _get_preference_type(value: Any) -> PreferenceType:
        """Determine preference type from value."""
        if isinstance(value, bool):
            return PreferenceType.BOOLEAN
        elif isinstance(value, int):
            return PreferenceType.INTEGER
        elif isinstance(value, float):
            return PreferenceType.FLOAT
        elif isinstance(value, list):
            return PreferenceType.LIST
        elif isinstance(value, dict):
            return PreferenceType.JSON
        else:
            return PreferenceType.STRING
