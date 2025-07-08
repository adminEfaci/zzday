"""
Update profile command implementation.

Handles user profile updates with authorization and validation.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    ICacheService,
    IUserProfileRepository,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_self_or_permission,
    validate_request,
)
from app.modules.identity.application.dtos.request import UpdateProfileRequest
from app.modules.identity.application.dtos.response import (
    UserProfileResponse,
)
from app.modules.identity.domain.entities import User, UserProfile
from app.modules.identity.domain.enums import AuditAction
from app.modules.identity.domain.events import UserProfileUpdated
from app.modules.identity.domain.exceptions import (
    UserNotFoundError,
    ValidationError,
)
from app.modules.identity.domain.services import AuthorizationService
from app.modules.identity.domain.specifications import ValidDateOfBirthSpecification


class UpdateProfileCommand(Command[UserProfileResponse]):
    """Command to update user profile."""
    
    def __init__(
        self,
        target_user_id: UUID,
        first_name: str | None = None,
        last_name: str | None = None,
        bio: str | None = None,
        date_of_birth: datetime | None = None,
        gender: str | None = None,
        language: str | None = None,
        timezone: str | None = None,
        metadata: dict[str, Any] | None = None,
        updated_by: UUID | None = None,
        ip_address: str | None = None
    ):
        self.target_user_id = target_user_id
        self.first_name = first_name
        self.last_name = last_name
        self.bio = bio
        self.date_of_birth = date_of_birth
        self.gender = gender
        self.language = language
        self.timezone = timezone
        self.metadata = metadata
        self.updated_by = updated_by
        self.ip_address = ip_address


class UpdateProfileCommandHandler(CommandHandler[UpdateProfileCommand, UserProfileResponse]):
    """Handler for updating user profiles."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        profile_repository: IUserProfileRepository,
        authorization_service: AuthorizationService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._profile_repository = profile_repository
        self._authorization_service = authorization_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.PROFILE_UPDATED,
        resource_type="user_profile",
        resource_id_attr="target_user_id",
        include_request=True
    )
    @validate_request(UpdateProfileRequest)
    @rate_limit(
        max_requests=30,
        window_seconds=3600,
        strategy='user'
    )
    @require_self_or_permission(
        permission="users.update_profile",
        resource_type="user",
        target_user_id_attr="target_user_id"
    )
    async def handle(self, command: UpdateProfileCommand) -> UserProfileResponse:
        """
        Update user profile with validation and authorization.
        
        Process:
        1. Load user and profile
        2. Validate authorization
        3. Validate profile data
        4. Update profile fields
        5. Calculate completion percentage
        6. Save changes
        7. Invalidate cache
        8. Publish events
        
        Returns:
            UserProfileResponse with updated profile
            
        Raises:
            UserNotFoundError: If user not found
            ValidationError: If profile data invalid
            UnauthorizedError: If lacks permission
        """
        async with self._unit_of_work:
            # 1. Load user and ensure exists
            user = await self._user_repository.get_by_id(command.target_user_id)
            if not user:
                raise UserNotFoundError(
                    f"User {command.target_user_id} not found"
                )
            
            # 2. Load or create profile
            profile = await self._profile_repository.get_by_user_id(user.id)
            if not profile:
                profile = UserProfile.create(user_id=user.id)
                await self._profile_repository.add(profile)
            
            # 3. Track changes for audit
            changes = {}
            
            # 4. Update user fields if provided
            if command.first_name is not None:
                if command.first_name != user.first_name:
                    changes['first_name'] = {
                        'old': user.first_name,
                        'new': command.first_name
                    }
                    user.update_profile(
                        first_name=command.first_name,
                        last_name=user.last_name
                    )
            
            if command.last_name is not None:
                if command.last_name != user.last_name:
                    changes['last_name'] = {
                        'old': user.last_name,
                        'new': command.last_name
                    }
                    user.update_profile(
                        first_name=user.first_name,
                        last_name=command.last_name
                    )
            
            # 5. Update profile fields
            if command.bio is not None:
                if len(command.bio) > 500:
                    raise ValidationError("Bio must be 500 characters or less")
                if command.bio != profile.bio:
                    changes['bio'] = {
                        'old': profile.bio,
                        'new': command.bio
                    }
                    profile.bio = command.bio
            
            if command.date_of_birth is not None:
                if not ValidDateOfBirthSpecification().is_satisfied_by(command.date_of_birth):
                    raise ValidationError("Invalid date of birth")
                if command.date_of_birth != profile.date_of_birth:
                    changes['date_of_birth'] = {
                        'old': profile.date_of_birth,
                        'new': command.date_of_birth
                    }
                    profile.date_of_birth = command.date_of_birth
            
            if command.gender is not None:
                if command.gender not in ['male', 'female', 'other', 'prefer_not_to_say']:
                    raise ValidationError("Invalid gender value")
                if command.gender != profile.gender:
                    changes['gender'] = {
                        'old': profile.gender,
                        'new': command.gender
                    }
                    profile.gender = command.gender
            
            if command.language is not None:
                # Validate language code (ISO 639-1)
                if not self._is_valid_language_code(command.language):
                    raise ValidationError(f"Invalid language code: {command.language}")
                if command.language != profile.language:
                    changes['language'] = {
                        'old': profile.language,
                        'new': command.language
                    }
                    profile.language = command.language
            
            if command.timezone is not None:
                # Validate timezone
                if not self._is_valid_timezone(command.timezone):
                    raise ValidationError(f"Invalid timezone: {command.timezone}")
                if command.timezone != profile.timezone:
                    changes['timezone'] = {
                        'old': profile.timezone,
                        'new': command.timezone
                    }
                    profile.timezone = command.timezone
            
            if command.metadata is not None:
                # Merge metadata
                profile.metadata = {**profile.metadata, **command.metadata}
                changes['metadata'] = {'updated': True}
            
            # 6. Calculate profile completion
            completion = self._calculate_profile_completion(user, profile)
            profile.completion_percentage = completion
            
            # 7. Update timestamps
            profile.updated_at = datetime.now(UTC)
            
            # 8. Save changes
            await self._user_repository.update(user)
            await self._profile_repository.update(profile)
            
            # 9. Invalidate cache
            await self._cache_service.delete(f"user:{user.id}")
            await self._cache_service.delete(f"profile:{user.id}")
            
            # 10. Publish event if changes made
            if changes:
                await self._event_bus.publish(
                    UserProfileUpdated(
                        aggregate_id=user.id,
                        updated_by=command.updated_by,
                        changes=changes,
                        completion_percentage=completion
                    )
                )
            
            # 11. Commit transaction
            await self._unit_of_work.commit()
            
            return UserProfileResponse(
                id=profile.id,
                user_id=user.id,
                bio=profile.bio,
                date_of_birth=profile.date_of_birth,
                gender=profile.gender,
                language=profile.language,
                timezone=profile.timezone,
                preferences=profile.preferences,
                social_links=profile.social_links,
                completion_percentage=completion,
                updated_at=profile.updated_at
            )
    
    def _calculate_profile_completion(self, user: User, profile: UserProfile) -> float:
        """Calculate profile completion percentage."""
        fields = [
            user.first_name,
            user.last_name,
            user.email_verified,
            profile.bio,
            profile.date_of_birth,
            profile.gender,
            profile.language != 'en',  # Non-default language
            profile.timezone != 'UTC',  # Non-default timezone
            bool(profile.avatar_url),
            user.phone_number
        ]
        
        completed = sum(1 for field in fields if field)
        return (completed / len(fields)) * 100
    
    def _is_valid_language_code(self, code: str) -> bool:
        """Validate ISO 639-1 language code."""
        # Simplified validation - in production would use a proper library
        valid_codes = {
            'en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko',
            'ar', 'hi', 'tr', 'pl', 'nl', 'sv', 'da', 'no', 'fi', 'he'
        }
        return code.lower() in valid_codes
    
    def _is_valid_timezone(self, timezone: str) -> bool:
        """Validate timezone string."""
        # Simplified validation - in production would use pytz
        return timezone in [
            'UTC', 'America/New_York', 'America/Chicago', 'America/Denver',
            'America/Los_Angeles', 'Europe/London', 'Europe/Paris',
            'Europe/Berlin', 'Asia/Tokyo', 'Asia/Shanghai', 'Australia/Sydney'
        ]