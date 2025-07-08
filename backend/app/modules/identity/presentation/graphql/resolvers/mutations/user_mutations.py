"""
User management mutation resolvers for GraphQL.

This module implements comprehensive user management mutations including
CRUD operations, profile updates, preferences, avatar uploads, and
user lifecycle management with transaction support and audit logging.
"""

import uuid
from datetime import datetime
from typing import Any

from strawberry import mutation
from strawberry.types import Info

from app.core.cache import get_cache
from app.core.database import get_db_context
from app.core.enums import EventType, UserStatus
from app.core.errors import (
    AuthorizationError,
    BusinessRuleError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.interfaces import (
    IFileStorageService,
    INotificationService,
    ISecurityEventRepository,
    IUserPreferencesRepository,
    IUserProfileRepository,
    IUserRepository,
)
from app.modules.identity.presentation.graphql.types import (
    Upload,
    UserCreateInput,
    UserPreferencesUpdateInput,
    UserProfileUpdateInput,
    UserResponse,
    UserUpdateInput,
)

logger = get_logger(__name__)


class UserMutations:
    """User management GraphQL mutations."""

    def __init__(
        self,
        user_repository: IUserRepository,
        user_profile_repository: IUserProfileRepository,
        user_preferences_repository: IUserPreferencesRepository,
        security_event_repository: ISecurityEventRepository,
        file_storage_service: IFileStorageService,
        notification_service: INotificationService
    ):
        self.user_repository = user_repository
        self.user_profile_repository = user_profile_repository
        self.user_preferences_repository = user_preferences_repository
        self.security_event_repository = security_event_repository
        self.file_storage_service = file_storage_service
        self.notification_service = notification_service
        self.cache = get_cache()
        self.logger = logger

    @mutation
    async def create_user(self, info: Info, input: UserCreateInput) -> UserResponse:
        """
        Create new user account with comprehensive validation.
        
        Args:
            input: User creation data
            
        Returns:
            UserResponse with created user data
            
        Raises:
            ValidationError: Invalid input data
            ConflictError: User already exists
            AuthorizationError: Insufficient permissions
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_user_create_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to create user")

                # Validate input
                await self._validate_user_create_input(input)

                # Check if user exists
                existing_user = await self.user_repository.find_by_email(input.email)
                if existing_user:
                    raise ConflictError("User with this email already exists")

                # Create user with optimistic concurrency control
                user_data = await self._prepare_user_data(input)
                user = await self.user_repository.create(user_data)

                # Create user profile
                profile_data = await self._prepare_profile_data(user.id, input)
                profile = await self.user_profile_repository.create(profile_data)

                # Create default preferences
                preferences_data = await self._prepare_default_preferences(user.id)
                preferences = await self.user_preferences_repository.create(preferences_data)

                # Log user creation
                await self._log_security_event(
                    user.id,
                    EventType.USER_CREATED,
                    f"User created by admin: {current_user.id}",
                    info
                )

                # Send welcome notification
                await self.notification_service.send_welcome_email(user)

                # Clear cache
                await self._invalidate_user_cache(user.id)

                await db.commit()

                return UserResponse(
                    user=user,
                    profile=profile,
                    preferences=preferences
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User creation failed: {e!s}")
                raise

    @mutation
    async def update_user(
        self,
        info: Info,
        id: str,
        input: UserUpdateInput
    ) -> UserResponse:
        """
        Update existing user with optimistic concurrency control.
        
        Args:
            id: User ID
            input: User update data
            
        Returns:
            UserResponse with updated user data
            
        Raises:
            NotFoundError: User not found
            ValidationError: Invalid input data
            AuthorizationError: Insufficient permissions
        """
        async with get_db_context() as db:
            try:
                # Get current user and check authorization
                current_user = info.context.get("current_user")
                if not current_user:
                    raise AuthorizationError("Authentication required")

                # Find target user
                user = await self.user_repository.find_by_id(id)
                if not user:
                    raise NotFoundError("User not found")

                # Check authorization
                if not self._can_update_user(current_user, user):
                    raise AuthorizationError("Insufficient permissions to update user")

                # Validate input
                await self._validate_user_update_input(input, user)

                # Check optimistic concurrency
                if hasattr(input, 'version') and input.version != user.version:
                    raise ConflictError("User has been modified by another process")

                # Update user data
                updated_data = await self._prepare_user_update_data(input, user)

                # Apply updates
                for key, value in updated_data.items():
                    setattr(user, key, value)

                user.updated_at = datetime.utcnow()
                user.version += 1

                updated_user = await self.user_repository.update(user)

                # Get profile and preferences
                profile = await self.user_profile_repository.find_by_user_id(user.id)
                preferences = await self.user_preferences_repository.find_by_user_id(user.id)

                # Log user update
                await self._log_security_event(
                    user.id,
                    EventType.USER_UPDATED,
                    f"User updated by: {current_user.id}",
                    info,
                    metadata={"updated_fields": list(updated_data.keys())}
                )

                # Clear cache
                await self._invalidate_user_cache(user.id)

                await db.commit()

                return UserResponse(
                    user=updated_user,
                    profile=profile,
                    preferences=preferences
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User update failed: {e!s}")
                raise

    @mutation
    async def delete_user(self, info: Info, id: str) -> bool:
        """
        Delete user with proper cleanup and audit trail.
        
        Args:
            id: User ID
            
        Returns:
            True if user deleted successfully
            
        Raises:
            NotFoundError: User not found
            AuthorizationError: Insufficient permissions
            BusinessRuleError: Cannot delete user
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_user_delete_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to delete user")

                # Find user
                user = await self.user_repository.find_by_id(id)
                if not user:
                    raise NotFoundError("User not found")

                # Check business rules
                if user.id == current_user.id:
                    raise BusinessRuleError("Cannot delete your own account")

                if user.is_system_user:
                    raise BusinessRuleError("Cannot delete system user")

                # Perform soft delete
                user.is_deleted = True
                user.deleted_at = datetime.utcnow()
                user.deleted_by = current_user.id
                user.status = UserStatus.DELETED

                await self.user_repository.update(user)

                # Anonymize user data
                await self._anonymize_user_data(user)

                # Invalidate all sessions
                await self._invalidate_all_user_sessions(user.id)

                # Log user deletion
                await self._log_security_event(
                    user.id,
                    EventType.USER_DELETED,
                    f"User deleted by admin: {current_user.id}",
                    info
                )

                # Clear cache
                await self._invalidate_user_cache(user.id)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User deletion failed: {e!s}")
                raise

    @mutation
    async def suspend_user(
        self,
        info: Info,
        id: str,
        reason: str
    ) -> bool:
        """
        Suspend user account.
        
        Args:
            id: User ID
            reason: Suspension reason
            
        Returns:
            True if user suspended
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_user_suspend_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to suspend user")

                # Find user
                user = await self.user_repository.find_by_id(id)
                if not user:
                    raise NotFoundError("User not found")

                # Update user status
                user.status = UserStatus.SUSPENDED
                user.suspended_at = datetime.utcnow()
                user.suspended_by = current_user.id
                user.suspension_reason = reason

                await self.user_repository.update(user)

                # Invalidate all sessions
                await self._invalidate_all_user_sessions(user.id)

                # Log suspension
                await self._log_security_event(
                    user.id,
                    EventType.USER_SUSPENDED,
                    f"User suspended by admin: {current_user.id}. Reason: {reason}",
                    info
                )

                # Send notification
                await self.notification_service.send_suspension_notification(user, reason)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User suspension failed: {e!s}")
                raise

    @mutation
    async def reactivate_user(
        self,
        info: Info,
        id: str,
        reason: str
    ) -> bool:
        """
        Reactivate suspended user account.
        
        Args:
            id: User ID
            reason: Reactivation reason
            
        Returns:
            True if user reactivated
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_user_suspend_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to reactivate user")

                # Find user
                user = await self.user_repository.find_by_id(id)
                if not user:
                    raise NotFoundError("User not found")

                # Update user status
                user.status = UserStatus.ACTIVE
                user.suspended_at = None
                user.suspended_by = None
                user.suspension_reason = None
                user.reactivated_at = datetime.utcnow()
                user.reactivated_by = current_user.id

                await self.user_repository.update(user)

                # Log reactivation
                await self._log_security_event(
                    user.id,
                    EventType.USER_REACTIVATED,
                    f"User reactivated by admin: {current_user.id}. Reason: {reason}",
                    info
                )

                # Send notification
                await self.notification_service.send_reactivation_notification(user)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User reactivation failed: {e!s}")
                raise

    @mutation
    async def update_user_profile(
        self,
        info: Info,
        id: str,
        input: UserProfileUpdateInput
    ) -> UserResponse:
        """
        Update user profile information.
        
        Args:
            id: User ID
            input: Profile update data
            
        Returns:
            UserResponse with updated profile
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user:
                    raise AuthorizationError("Authentication required")

                # Find user
                user = await self.user_repository.find_by_id(id)
                if not user:
                    raise NotFoundError("User not found")

                # Check authorization
                if not self._can_update_user_profile(current_user, user):
                    raise AuthorizationError("Insufficient permissions to update profile")

                # Find or create profile
                profile = await self.user_profile_repository.find_by_user_id(user.id)
                if not profile:
                    profile_data = await self._prepare_profile_data(user.id, input)
                    profile = await self.user_profile_repository.create(profile_data)
                else:
                    # Update existing profile
                    updated_data = await self._prepare_profile_update_data(input)

                    for key, value in updated_data.items():
                        setattr(profile, key, value)

                    profile.updated_at = datetime.utcnow()
                    profile = await self.user_profile_repository.update(profile)

                # Get preferences
                preferences = await self.user_preferences_repository.find_by_user_id(user.id)

                # Log profile update
                await self._log_security_event(
                    user.id,
                    EventType.PROFILE_UPDATED,
                    f"Profile updated by: {current_user.id}",
                    info
                )

                # Clear cache
                await self._invalidate_user_cache(user.id)

                await db.commit()

                return UserResponse(
                    user=user,
                    profile=profile,
                    preferences=preferences
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Profile update failed: {e!s}")
                raise

    @mutation
    async def update_user_preferences(
        self,
        info: Info,
        id: str,
        input: UserPreferencesUpdateInput
    ) -> UserResponse:
        """
        Update user preferences.
        
        Args:
            id: User ID
            input: Preferences update data
            
        Returns:
            UserResponse with updated preferences
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user:
                    raise AuthorizationError("Authentication required")

                # Find user
                user = await self.user_repository.find_by_id(id)
                if not user:
                    raise NotFoundError("User not found")

                # Check authorization
                if not self._can_update_user_preferences(current_user, user):
                    raise AuthorizationError("Insufficient permissions to update preferences")

                # Find or create preferences
                preferences = await self.user_preferences_repository.find_by_user_id(user.id)
                if not preferences:
                    preferences_data = await self._prepare_preferences_data(user.id, input)
                    preferences = await self.user_preferences_repository.create(preferences_data)
                else:
                    # Update existing preferences
                    updated_data = await self._prepare_preferences_update_data(input)

                    for key, value in updated_data.items():
                        setattr(preferences, key, value)

                    preferences.updated_at = datetime.utcnow()
                    preferences = await self.user_preferences_repository.update(preferences)

                # Get profile
                profile = await self.user_profile_repository.find_by_user_id(user.id)

                # Log preferences update
                await self._log_security_event(
                    user.id,
                    EventType.PREFERENCES_UPDATED,
                    f"Preferences updated by: {current_user.id}",
                    info
                )

                # Clear cache
                await self._invalidate_user_cache(user.id)

                await db.commit()

                return UserResponse(
                    user=user,
                    profile=profile,
                    preferences=preferences
                )

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Preferences update failed: {e!s}")
                raise

    @mutation
    async def upload_user_avatar(
        self,
        info: Info,
        id: str,
        avatar: Upload
    ) -> str:
        """
        Upload user avatar image.
        
        Args:
            id: User ID
            avatar: Avatar image file
            
        Returns:
            Avatar URL
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user:
                    raise AuthorizationError("Authentication required")

                # Find user
                user = await self.user_repository.find_by_id(id)
                if not user:
                    raise NotFoundError("User not found")

                # Check authorization
                if not self._can_update_user_profile(current_user, user):
                    raise AuthorizationError("Insufficient permissions to upload avatar")

                # Validate file
                await self._validate_avatar_file(avatar)

                # Upload file
                avatar_url = await self.file_storage_service.upload_avatar(
                    user.id,
                    avatar
                )

                # Update user profile
                profile = await self.user_profile_repository.find_by_user_id(user.id)
                if profile:
                    # Delete old avatar if exists
                    if profile.avatar_url:
                        await self.file_storage_service.delete_file(profile.avatar_url)

                    profile.avatar_url = avatar_url
                    profile.updated_at = datetime.utcnow()
                    await self.user_profile_repository.update(profile)

                # Log avatar upload
                await self._log_security_event(
                    user.id,
                    EventType.AVATAR_UPLOADED,
                    f"Avatar uploaded by: {current_user.id}",
                    info
                )

                # Clear cache
                await self._invalidate_user_cache(user.id)

                await db.commit()
                return avatar_url

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Avatar upload failed: {e!s}")
                raise

    @mutation
    async def anonymize_user(self, info: Info, id: str) -> bool:
        """
        Anonymize user data for GDPR compliance.
        
        Args:
            id: User ID
            
        Returns:
            True if user anonymized
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_user_delete_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to anonymize user")

                # Find user
                user = await self.user_repository.find_by_id(id)
                if not user:
                    raise NotFoundError("User not found")

                # Anonymize user data
                await self._anonymize_user_data(user)

                # Log anonymization
                await self._log_security_event(
                    user.id,
                    EventType.USER_ANONYMIZED,
                    f"User anonymized by admin: {current_user.id}",
                    info
                )

                # Clear cache
                await self._invalidate_user_cache(user.id)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User anonymization failed: {e!s}")
                raise

    # Helper methods

    def _has_user_create_permission(self, user: User) -> bool:
        """Check if user has permission to create users."""
        return user.has_permission("user:create")

    def _has_user_delete_permission(self, user: User) -> bool:
        """Check if user has permission to delete users."""
        return user.has_permission("user:delete")

    def _has_user_suspend_permission(self, user: User) -> bool:
        """Check if user has permission to suspend users."""
        return user.has_permission("user:suspend")

    def _can_update_user(self, current_user: User, target_user: User) -> bool:
        """Check if current user can update target user."""
        if current_user.id == target_user.id:
            return True
        return current_user.has_permission("user:update")

    def _can_update_user_profile(self, current_user: User, target_user: User) -> bool:
        """Check if current user can update target user profile."""
        if current_user.id == target_user.id:
            return True
        return current_user.has_permission("user:update")

    def _can_update_user_preferences(self, current_user: User, target_user: User) -> bool:
        """Check if current user can update target user preferences."""
        if current_user.id == target_user.id:
            return True
        return current_user.has_permission("user:update")

    async def _validate_user_create_input(self, input: UserCreateInput) -> None:
        """Validate user creation input."""
        if not input.email or "@" not in input.email:
            raise ValidationError("Valid email address is required")

        if not input.first_name or not input.last_name:
            raise ValidationError("First name and last name are required")

        if hasattr(input, 'password') and input.password:
            await self._validate_password(input.password)

    async def _validate_user_update_input(
        self,
        input: UserUpdateInput,
        user: User
    ) -> None:
        """Validate user update input."""
        if hasattr(input, 'email') and input.email:
            if input.email != user.email:
                existing_user = await self.user_repository.find_by_email(input.email)
                if existing_user:
                    raise ConflictError("Email address already in use")

    async def _validate_avatar_file(self, avatar: Upload) -> None:
        """Validate avatar file."""
        # Check file size (max 5MB)
        if avatar.size > 5 * 1024 * 1024:
            raise ValidationError("Avatar file size cannot exceed 5MB")

        # Check file type
        allowed_types = ['image/jpeg', 'image/png', 'image/gif']
        if avatar.content_type not in allowed_types:
            raise ValidationError("Avatar must be a JPEG, PNG, or GIF image")

    async def _validate_password(self, password: str) -> None:
        """Validate password strength."""
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters")

    async def _prepare_user_data(self, input: UserCreateInput) -> dict[str, Any]:
        """Prepare user data for creation."""
        return {
            "id": str(uuid.uuid4()),
            "email": input.email.lower().strip(),
            "first_name": input.first_name.strip(),
            "last_name": input.last_name.strip(),
            "is_active": getattr(input, "is_active", True),
            "status": UserStatus.ACTIVE,
            "created_at": datetime.utcnow(),
            "version": 1
        }

    async def _prepare_user_update_data(
        self,
        input: UserUpdateInput,
        user: User
    ) -> dict[str, Any]:
        """Prepare user data for update."""
        data = {}

        if hasattr(input, 'email') and input.email:
            data['email'] = input.email.lower().strip()

        if hasattr(input, 'first_name') and input.first_name:
            data['first_name'] = input.first_name.strip()

        if hasattr(input, 'last_name') and input.last_name:
            data['last_name'] = input.last_name.strip()

        if hasattr(input, 'is_active') and input.is_active is not None:
            data['is_active'] = input.is_active

        return data

    async def _prepare_profile_data(
        self,
        user_id: str,
        input: Any
    ) -> dict[str, Any]:
        """Prepare profile data."""
        return {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "phone_number": getattr(input, "phone_number", None),
            "bio": getattr(input, "bio", None),
            "website": getattr(input, "website", None),
            "location": getattr(input, "location", None),
            "created_at": datetime.utcnow()
        }

    async def _prepare_profile_update_data(
        self,
        input: UserProfileUpdateInput
    ) -> dict[str, Any]:
        """Prepare profile update data."""
        data = {}

        if hasattr(input, 'phone_number'):
            data['phone_number'] = input.phone_number

        if hasattr(input, 'bio'):
            data['bio'] = input.bio

        if hasattr(input, 'website'):
            data['website'] = input.website

        if hasattr(input, 'location'):
            data['location'] = input.location

        return data

    async def _prepare_default_preferences(self, user_id: str) -> dict[str, Any]:
        """Prepare default user preferences."""
        return {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "language": "en",
            "timezone": "UTC",
            "theme": "light",
            "email_notifications": True,
            "push_notifications": True,
            "sms_notifications": False,
            "created_at": datetime.utcnow()
        }

    async def _prepare_preferences_data(
        self,
        user_id: str,
        input: UserPreferencesUpdateInput
    ) -> dict[str, Any]:
        """Prepare preferences data."""
        data = await self._prepare_default_preferences(user_id)

        if hasattr(input, 'language') and input.language:
            data['language'] = input.language

        if hasattr(input, 'timezone') and input.timezone:
            data['timezone'] = input.timezone

        if hasattr(input, 'theme') and input.theme:
            data['theme'] = input.theme

        return data

    async def _prepare_preferences_update_data(
        self,
        input: UserPreferencesUpdateInput
    ) -> dict[str, Any]:
        """Prepare preferences update data."""
        data = {}

        if hasattr(input, 'language'):
            data['language'] = input.language

        if hasattr(input, 'timezone'):
            data['timezone'] = input.timezone

        if hasattr(input, 'theme'):
            data['theme'] = input.theme

        if hasattr(input, 'email_notifications'):
            data['email_notifications'] = input.email_notifications

        if hasattr(input, 'push_notifications'):
            data['push_notifications'] = input.push_notifications

        if hasattr(input, 'sms_notifications'):
            data['sms_notifications'] = input.sms_notifications

        return data

    async def _anonymize_user_data(self, user: User) -> None:
        """Anonymize user data."""
        # Generate anonymous identifier
        anonymous_id = f"anonymous_{uuid.uuid4().hex[:8]}"

        # Update user data
        user.email = f"{anonymous_id}@anonymized.local"
        user.first_name = "Anonymous"
        user.last_name = "User"
        user.phone_number = None
        user.is_anonymized = True
        user.anonymized_at = datetime.utcnow()

        await self.user_repository.update(user)

        # Anonymize profile
        profile = await self.user_profile_repository.find_by_user_id(user.id)
        if profile:
            profile.bio = None
            profile.website = None
            profile.location = None
            profile.avatar_url = None
            await self.user_profile_repository.update(profile)

    async def _invalidate_all_user_sessions(self, user_id: str) -> None:
        """Invalidate all user sessions."""
        # This would integrate with session management
        await self.cache.delete(f"user_sessions:{user_id}")

    async def _invalidate_user_cache(self, user_id: str) -> None:
        """Invalidate user cache."""
        cache_keys = [
            f"user:{user_id}",
            f"user_profile:{user_id}",
            f"user_preferences:{user_id}",
            f"user_permissions:{user_id}"
        ]

        for key in cache_keys:
            await self.cache.delete(key)

    async def _log_security_event(
        self,
        user_id: str,
        event_type: EventType,
        description: str,
        info: Info,
        metadata: dict[str, Any] | None = None
    ) -> None:
        """Log security event."""
        event_data = {
            "user_id": user_id,
            "event_type": event_type,
            "description": description,
            "ip_address": info.context.get("ip_address"),
            "user_agent": info.context.get("user_agent"),
            "metadata": metadata,
            "created_at": datetime.utcnow()
        }

        await self.security_event_repository.create(event_data)
