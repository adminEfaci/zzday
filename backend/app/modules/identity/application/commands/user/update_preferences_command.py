"""
Update preferences command implementation.

Handles updating user preferences and settings.
"""

from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
    require_self_or_permission,
    validate_request,
)
from app.modules.identity.application.dtos.request import UpdatePreferencesRequest
from app.modules.identity.application.dtos.response import PreferencesResponse
from app.modules.identity.domain.entities import User, UserPreferences
from app.modules.identity.domain.enums import (
    AuditAction,
    Language,
    NotificationChannel,
    PrivacyLevel,
    Theme,
)
from app.modules.identity.domain.events import UserPreferencesUpdated
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    UserNotFoundError,
    ValidationError,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import SecurityService


class UpdatePreferencesCommand(Command[PreferencesResponse]):
    """Command to update user preferences."""
    
    def __init__(
        self,
        user_id: UUID,
        language: Language | None = None,
        timezone: str | None = None,
        theme: Theme | None = None,
        notification_preferences: dict[str, Any] | None = None,
        privacy_settings: dict[str, Any] | None = None,
        feature_flags: dict[str, bool] | None = None,
        custom_settings: dict[str, Any] | None = None,
        reset_to_defaults: bool = False,
        updated_by: UUID | None = None
    ):
        self.user_id = user_id
        self.language = language
        self.timezone = timezone
        self.theme = theme
        self.notification_preferences = notification_preferences
        self.privacy_settings = privacy_settings
        self.feature_flags = feature_flags
        self.custom_settings = custom_settings
        self.reset_to_defaults = reset_to_defaults
        self.updated_by = updated_by or user_id


class UpdatePreferencesCommandHandler(CommandHandler[UpdatePreferencesCommand, PreferencesResponse]):
    """Handler for updating user preferences."""
    
    SUPPORTED_TIMEZONES: ClassVar[list[str]] = [
        "UTC", "America/New_York", "America/Chicago", "America/Denver",
        "America/Los_Angeles", "Europe/London", "Europe/Paris",
        "Europe/Berlin", "Asia/Tokyo", "Asia/Shanghai", "Asia/Dubai",
        "Australia/Sydney", "Pacific/Auckland"
    ]
    
    def __init__(
        self,
        user_repository: IUserRepository,
        preferences_repository: IUserPreferencesRepository,
        security_service: SecurityService,
        cache_service: ICacheService,
        feature_flag_service: IFeatureFlagService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._preferences_repository = preferences_repository
        self._security_service = security_service
        self._cache_service = cache_service
        self._feature_flag_service = feature_flag_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.PREFERENCES_UPDATED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=True
    )
    @require_auth
    @require_self_or_permission(
        permission="users.update_preferences",
        resource_type="user",
        resource_id_attr="user_id"
    )
    @validate_request(UpdatePreferencesRequest)
    @rate_limit(
        max_requests=20,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: UpdatePreferencesCommand) -> PreferencesResponse:
        """
        Update user preferences.
        
        Process:
        1. Validate user exists
        2. Load or create preferences
        3. Reset to defaults if requested
        4. Validate and apply updates
        5. Save preferences
        6. Clear caches
        7. Publish event
        
        Returns:
            PreferencesResponse with updated preferences
            
        Raises:
            UserNotFoundError: If user not found
            ValidationError: If invalid preferences
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Load or create preferences
            preferences = await self._preferences_repository.get_by_user_id(
                command.user_id
            )
            
            if not preferences:
                preferences = UserPreferences(
                    id=UUID(),
                    user_id=command.user_id,
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC)
                )
            
            # 3. Store old preferences for comparison
            old_preferences = self._copy_preferences(preferences)
            
            # 4. Reset to defaults if requested
            if command.reset_to_defaults:
                preferences = self._reset_to_defaults(preferences)
            else:
                # 5. Apply updates
                await self._apply_updates(preferences, command)
            
            # 6. Update timestamps
            preferences.updated_at = datetime.now(UTC)
            
            # 7. Save preferences
            if preferences.id in [None, UUID(int=0)]:
                await self._preferences_repository.add(preferences)
            else:
                await self._preferences_repository.update(preferences)
            
            # 8. Clear caches
            await self._clear_preferences_caches(command.user_id)
            
            # 9. Log if updated by admin
            if command.updated_by != command.user_id:
                await self._log_admin_update(
                    user=user,
                    preferences=preferences,
                    updated_by=command.updated_by
                )
            
            # 10. Track changes
            changes = self._identify_changes(old_preferences, preferences)
            
            # 11. Publish event
            await self._event_bus.publish(
                UserPreferencesUpdated(
                    aggregate_id=user.id,
                    old_preferences=self._preferences_to_dict(old_preferences),
                    new_preferences=self._preferences_to_dict(preferences),
                    changes=changes,
                    updated_by=command.updated_by
                )
            )
            
            # 12. Commit transaction
            await self._unit_of_work.commit()
            
            return PreferencesResponse(
                language=preferences.language,
                timezone=preferences.timezone,
                theme=preferences.theme,
                notification_preferences=preferences.notification_preferences,
                privacy_settings=preferences.privacy_settings,
                feature_flags=preferences.feature_flags,
                custom_settings=preferences.custom_settings,
                updated_at=preferences.updated_at,
                success=True,
                message="Preferences updated successfully"
            )
    
    async def _apply_updates(
        self,
        preferences: UserPreferences,
        command: UpdatePreferencesCommand
    ) -> None:
        """Apply preference updates."""
        # Update language
        if command.language is not None:
            preferences.language = command.language
        
        # Update timezone
        if command.timezone is not None:
            self._validate_timezone(command.timezone)
            preferences.timezone = command.timezone
        
        # Update theme
        if command.theme is not None:
            preferences.theme = command.theme
        
        # Update notification preferences
        if command.notification_preferences is not None:
            preferences.notification_preferences = await self._validate_notification_preferences(
                command.notification_preferences
            )
        
        # Update privacy settings
        if command.privacy_settings is not None:
            preferences.privacy_settings = self._validate_privacy_settings(
                command.privacy_settings
            )
        
        # Update feature flags
        if command.feature_flags is not None:
            preferences.feature_flags = await self._validate_feature_flags(
                command.feature_flags,
                command.user_id
            )
        
        # Update custom settings
        if command.custom_settings is not None:
            preferences.custom_settings = self._validate_custom_settings(
                command.custom_settings
            )
    
    def _validate_timezone(self, timezone: str) -> None:
        """Validate timezone string."""
        # Check if timezone is supported
        if timezone not in self.SUPPORTED_TIMEZONES:
            # Try to validate with pytz if available
            try:
                import pytz
                if timezone not in pytz.all_timezones:
                    raise ValidationError(f"Invalid timezone: {timezone}")
            except ImportError as e:
                # Fallback to basic validation
                if timezone not in self.SUPPORTED_TIMEZONES:
                    raise ValidationError(
                        f"Unsupported timezone. Supported: {', '.join(self.SUPPORTED_TIMEZONES)}"
                    ) from e
    
    async def _validate_notification_preferences(
        self,
        preferences: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate notification preferences."""
        validated = {}
        
        # Validate channels
        if 'channels' in preferences:
            channels = preferences['channels']
            validated['channels'] = {}
            
            for channel, enabled in channels.items():
                try:
                    channel_enum = NotificationChannel(channel)
                    validated['channels'][channel_enum.value] = bool(enabled)
                except ValueError as e:
                    raise ValidationError(f"Invalid notification channel: {channel}") from e
        
        # Validate categories
        if 'categories' in preferences:
            validated['categories'] = {}
            valid_categories = [
                'security', 'account', 'marketing', 'updates',
                'reminders', 'alerts', 'social'
            ]
            
            for category, enabled in preferences['categories'].items():
                if category not in valid_categories:
                    raise ValidationError(f"Invalid notification category: {category}")
                validated['categories'][category] = bool(enabled)
        
        # Validate frequency
        if 'frequency' in preferences:
            valid_frequencies = ['realtime', 'hourly', 'daily', 'weekly']
            if preferences['frequency'] not in valid_frequencies:
                raise ValidationError("Invalid notification frequency")
            validated['frequency'] = preferences['frequency']
        
        # Validate quiet hours
        if 'quiet_hours' in preferences:
            quiet_hours = preferences['quiet_hours']
            if 'enabled' in quiet_hours:
                validated['quiet_hours'] = {
                    'enabled': bool(quiet_hours['enabled']),
                    'start': quiet_hours.get('start', '22:00'),
                    'end': quiet_hours.get('end', '08:00'),
                    'timezone': quiet_hours.get('timezone', 'local')
                }
        
        return validated
    
    def _validate_privacy_settings(
        self,
        settings: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate privacy settings."""
        validated = {}
        
        # Validate privacy level
        if 'profile_visibility' in settings:
            try:
                level = PrivacyLevel(settings['profile_visibility'])
                validated['profile_visibility'] = level.value
            except ValueError as e:
                raise ValidationError("Invalid privacy level") from e
        
        # Validate specific privacy options
        privacy_options = [
            'show_email', 'show_phone', 'show_activity',
            'show_online_status', 'allow_messages', 'allow_friend_requests',
            'searchable', 'show_location'
        ]
        
        for option in privacy_options:
            if option in settings:
                validated[option] = bool(settings[option])
        
        # Validate blocked users list
        if 'blocked_users' in settings:
            if isinstance(settings['blocked_users'], list):
                validated['blocked_users'] = [
                    str(user_id) for user_id in settings['blocked_users']
                ]
            else:
                raise ValidationError("Blocked users must be a list")
        
        return validated
    
    async def _validate_feature_flags(
        self,
        flags: dict[str, bool],
        user_id: UUID
    ) -> dict[str, bool]:
        """Validate feature flags."""
        validated = {}
        
        # Get available features for user
        available_features = await self._feature_flag_service.get_available_features(
            user_id
        )
        
        for feature, enabled in flags.items():
            if feature not in available_features:
                raise ValidationError(f"Feature not available: {feature}")
            
            # Check if user can modify this feature
            if not await self._feature_flag_service.can_user_toggle(user_id, feature):
                raise InvalidOperationError(
                    f"Cannot modify feature: {feature}"
                )
            
            validated[feature] = bool(enabled)
        
        return validated
    
    def _validate_custom_settings(
        self,
        settings: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate custom settings."""
        # Size limit for custom settings
        max_settings_size = 10 * 1024  # 10KB
        
        import json
        settings_json = json.dumps(settings)
        
        if len(settings_json) > max_settings_size:
            raise ValidationError(
                f"Custom settings too large (max {max_settings_size} bytes)"
            )
        
        # Validate no sensitive data in keys
        sensitive_patterns = [
            'password', 'secret', 'token', 'key', 'credential'
        ]
        
        for key in settings:
            for pattern in sensitive_patterns:
                if pattern in key.lower():
                    raise ValidationError(
                        "Custom settings cannot contain sensitive data"
                    )
        
        return settings
    
    def _reset_to_defaults(self, preferences: UserPreferences) -> UserPreferences:
        """Reset preferences to defaults."""
        preferences.language = Language.ENGLISH
        preferences.timezone = "UTC"
        preferences.theme = Theme.LIGHT
        preferences.notification_preferences = {
            'channels': {
                'email': True,
                'push': True,
                'sms': False
            },
            'categories': {
                'security': True,
                'account': True,
                'marketing': False,
                'updates': True
            },
            'frequency': 'realtime'
        }
        preferences.privacy_settings = {
            'profile_visibility': PrivacyLevel.PRIVATE.value,
            'show_email': False,
            'show_phone': False,
            'show_activity': True,
            'show_online_status': True,
            'allow_messages': True,
            'searchable': True
        }
        preferences.feature_flags = {}
        preferences.custom_settings = {}
        
        return preferences
    
    def _copy_preferences(self, preferences: UserPreferences) -> UserPreferences:
        """Create a copy of preferences."""
        return UserPreferences(
            id=preferences.id,
            user_id=preferences.user_id,
            language=preferences.language,
            timezone=preferences.timezone,
            theme=preferences.theme,
            notification_preferences=preferences.notification_preferences.copy() if preferences.notification_preferences else {},
            privacy_settings=preferences.privacy_settings.copy() if preferences.privacy_settings else {},
            feature_flags=preferences.feature_flags.copy() if preferences.feature_flags else {},
            custom_settings=preferences.custom_settings.copy() if preferences.custom_settings else {},
            created_at=preferences.created_at,
            updated_at=preferences.updated_at
        )
    
    def _identify_changes(
        self,
        old: UserPreferences,
        new: UserPreferences
    ) -> dict[str, Any]:
        """Identify what changed between preferences."""
        changes = {}
        
        if old.language != new.language:
            changes['language'] = {
                'old': old.language.value if old.language else None,
                'new': new.language.value if new.language else None
            }
        
        if old.timezone != new.timezone:
            changes['timezone'] = {
                'old': old.timezone,
                'new': new.timezone
            }
        
        if old.theme != new.theme:
            changes['theme'] = {
                'old': old.theme.value if old.theme else None,
                'new': new.theme.value if new.theme else None
            }
        
        if old.notification_preferences != new.notification_preferences:
            changes['notification_preferences'] = True
        
        if old.privacy_settings != new.privacy_settings:
            changes['privacy_settings'] = True
        
        if old.feature_flags != new.feature_flags:
            changes['feature_flags'] = True
        
        if old.custom_settings != new.custom_settings:
            changes['custom_settings'] = True
        
        return changes
    
    def _preferences_to_dict(self, preferences: UserPreferences) -> dict[str, Any]:
        """Convert preferences to dictionary."""
        return {
            'language': preferences.language.value if preferences.language else None,
            'timezone': preferences.timezone,
            'theme': preferences.theme.value if preferences.theme else None,
            'notification_preferences': preferences.notification_preferences,
            'privacy_settings': preferences.privacy_settings,
            'feature_flags': preferences.feature_flags,
            'custom_settings': preferences.custom_settings
        }
    
    async def _clear_preferences_caches(self, user_id: UUID) -> None:
        """Clear preferences-related caches."""
        cache_keys = [
            f"user_preferences:{user_id}",
            f"user_settings:{user_id}",
            f"user_features:{user_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _log_admin_update(
        self,
        user: User,
        preferences: UserPreferences,
        updated_by: UUID
    ) -> None:
        """Log administrative preferences update."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="preferences_updated_by_admin",
            details={
                "updated_by": str(updated_by),
                "changes_made": True
            }
        )