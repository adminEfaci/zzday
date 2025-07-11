"""
Consolidated User Management Command Handler

Consolidates user-related commands into a single handler.
Addresses the service explosion issue by grouping related user operations.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.core.cqrs import Command
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAvatarService,
    ICacheService,
    IEmailService,
    IStorageService,
    IUserPreferenceRepository,
    IUserProfileRepository,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    authorize,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import (
    CreateUserParams,
    UpdatePreferencesParams,
    UpdateProfileParams,
    UserMergeParams,
)
from app.modules.identity.application.dtos.request import (
    CreateUserRequest,
    UpdatePreferencesRequest,
    UpdateProfileRequest,
)
from app.modules.identity.application.dtos.response import (
    CreateUserResponse,
    DeleteUserResponse,
    UpdatePreferencesResponse,
    UpdateProfileResponse,
    UserMergeResponse,
)
from app.modules.identity.application.services.shared.validation_utils import (
    ValidationUtils,
)
from app.modules.identity.domain.entities import User, UserPreferences, UserProfile
from app.modules.identity.domain.enums import (
    AuditAction,
    Permission,
    UserStatus,
)
from app.modules.identity.domain.events import (
    UserCreated,
    UserDeactivated,
    UserDeleted,
    UserMerged,
    UserProfileUpdated,
    UserReactivated,
)
from app.modules.identity.domain.exceptions import (
    DuplicateEmailError,
    InvalidOperationError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import UserDomainService
from app.modules.identity.domain.specifications import (
    EmailAvailableSpecification,
)
from app.modules.identity.domain.value_objects import Email, PhoneNumber, UserId


# Consolidated Commands
@dataclass
class CreateUserCommand(Command[CreateUserResponse]):
    """Command to create a new user."""
    params: CreateUserParams


@dataclass
class UpdateProfileCommand(Command[UpdateProfileResponse]):
    """Command to update user profile."""
    user_id: UUID
    params: UpdateProfileParams


@dataclass
class UpdatePreferencesCommand(Command[UpdatePreferencesResponse]):
    """Command to update user preferences."""
    user_id: UUID
    params: UpdatePreferencesParams


@dataclass
class DeactivateUserCommand(Command[None]):
    """Command to deactivate a user."""
    user_id: UUID
    reason: str
    performed_by: UUID


@dataclass
class ReactivateUserCommand(Command[None]):
    """Command to reactivate a user."""
    user_id: UUID
    performed_by: UUID


@dataclass
class DeleteUserCommand(Command[DeleteUserResponse]):
    """Command to permanently delete a user."""
    user_id: UUID
    hard_delete: bool = False
    performed_by: UUID | None = None


@dataclass
class MergeUsersCommand(Command[UserMergeResponse]):
    """Command to merge two user accounts."""
    params: UserMergeParams
    performed_by: UUID


@dataclass
class UpdateContactInfoCommand(Command[UpdateProfileResponse]):
    """Command to update user contact information."""
    user_id: UUID
    email: str | None = None
    phone_number: str | None = None
    performed_by: UUID | None = None


@dataclass
class UploadAvatarCommand(Command[UpdateProfileResponse]):
    """Command to upload user avatar."""
    user_id: UUID
    file_data: bytes
    file_name: str
    content_type: str


@dataclass
class DeleteAvatarCommand(Command[UpdateProfileResponse]):
    """Command to delete user avatar."""
    user_id: UUID


@dataclass
class GenerateAvatarCommand(Command[UpdateProfileResponse]):
    """Command to generate avatar from initials."""
    user_id: UUID


@dataclass
class TransferUserDataCommand(Command[None]):
    """Command to transfer user data."""
    source_user_id: UUID
    target_user_id: UUID
    data_types: list[str]
    performed_by: UUID


# Dependency Groups
@dataclass
class UserManagementRepositories:
    """Repository dependencies for user management operations."""
    user_repository: IUserRepository
    user_profile_repository: IUserProfileRepository
    user_preference_repository: IUserPreferenceRepository


@dataclass
class UserManagementServices:
    """Service dependencies for user management operations."""
    user_domain_service: UserDomainService
    email_service: IEmailService
    storage_service: IStorageService
    avatar_service: IAvatarService
    cache_service: ICacheService


@dataclass
class UserManagementInfrastructure:
    """Infrastructure dependencies for user management operations."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class UserManagementCommandHandler:
    """
    Consolidated handler for all user management commands.
    
    Replaces individual handlers for:
    - CreateUserCommandHandler
    - UpdateProfileCommandHandler
    - UpdatePreferencesCommandHandler
    - DeactivateUserCommandHandler
    - ReactivateUserCommandHandler
    - DeleteUserCommandHandler
    - MergeUsersCommandHandler
    - UpdateContactInfoCommandHandler
    - UploadAvatarCommandHandler
    - DeleteAvatarCommandHandler
    - GenerateAvatarCommandHandler
    - TransferUserDataCommandHandler
    """
    
    def __init__(
        self,
        repositories: UserManagementRepositories,
        services: UserManagementServices,
        infrastructure: UserManagementInfrastructure,
    ):
        # Repository dependencies
        self._user_repository = repositories.user_repository
        self._user_profile_repository = repositories.user_profile_repository
        self._user_preference_repository = repositories.user_preference_repository
        
        # Service dependencies
        self._user_domain_service = services.user_domain_service
        self._email_service = services.email_service
        self._storage_service = services.storage_service
        self._avatar_service = services.avatar_service
        self._cache_service = services.cache_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work

    @audit_action(action=AuditAction.USER_CREATE, resource_type="user")
    @validate_request(CreateUserRequest)
    @rate_limit(max_requests=10, window_seconds=3600, strategy='ip')
    async def handle_create_user(self, command: CreateUserCommand) -> CreateUserResponse:
        """Create a new user account."""
        async with self._unit_of_work:
            # Validate email availability
            email = Email(command.params.email)
            if not await EmailAvailableSpecification(self._user_repository).is_satisfied_by(email):
                raise DuplicateEmailError(f"Email {email.value} is already registered")
            
            # Create user entity
            user = User(
                id=UserId(uuid4()),
                email=email,
                first_name=command.params.first_name,
                last_name=command.params.last_name,
                status=UserStatus.PENDING_VERIFICATION,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            
            # Set password if provided
            if command.params.password:
                user.set_password(command.params.password)
            
            # Create user profile
            profile = UserProfile(
                user_id=user.id,
                display_name=f"{user.first_name} {user.last_name}",
                bio=command.params.bio or "",
                location=command.params.location or "",
                website=command.params.website or "",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            
            # Create default preferences
            preferences = UserPreferences(
                user_id=user.id,
                language=command.params.language or "en",
                timezone=command.params.timezone or "UTC",
                theme="light",
                notifications_enabled=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            
            # Save entities
            await self._user_repository.create(user)
            await self._user_profile_repository.create(profile)
            await self._user_preference_repository.create(preferences)
            
            # Send welcome email
            if command.params.send_welcome_email:
                await self._email_service.send_welcome_email(
                    to=email.value,
                    name=user.first_name,
                    verification_token=user.generate_verification_token()
                )
            
            # Publish user created event
            await self._event_bus.publish(
                UserCreated(
                    aggregate_id=user.id.value,
                    email=email.value,
                    first_name=user.first_name,
                    last_name=user.last_name,
                    created_by=command.params.created_by
                )
            )
            
            await self._unit_of_work.commit()
            
            return CreateUserResponse(
                user_id=user.id.value,
                email=email.value,
                status=user.status,
                created_at=user.created_at,
                success=True,
                message="User created successfully"
            )

    @audit_action(action=AuditAction.USER_UPDATE, resource_type="user")
    @authorize(Permission.USER_UPDATE_SELF)
    @validate_request(UpdateProfileRequest)
    async def handle_update_profile(self, command: UpdateProfileCommand) -> UpdateProfileResponse:
        """Update user profile information."""
        async with self._unit_of_work:
            user = await self._user_repository.get_by_id(UserId(command.user_id))
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            profile = await self._user_profile_repository.get_by_user_id(UserId(command.user_id))
            if not profile:
                # Create profile if it doesn't exist
                profile = UserProfile(
                    user_id=UserId(command.user_id),
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC)
                )
            
            # Update user fields
            if command.params.first_name:
                user.first_name = command.params.first_name
            if command.params.last_name:
                user.last_name = command.params.last_name
            
            # Update profile fields
            if command.params.display_name:
                profile.display_name = command.params.display_name
            if command.params.bio is not None:
                profile.bio = ValidationUtils.sanitize_user_input(command.params.bio, max_length=500)
            if command.params.location is not None:
                profile.location = command.params.location
            if command.params.website is not None:
                if command.params.website and not ValidationUtils.is_valid_url(command.params.website):
                    raise ValueError("Invalid website URL")
                profile.website = command.params.website
            if command.params.date_of_birth:
                profile.date_of_birth = command.params.date_of_birth
            if command.params.phone_number:
                profile.phone_number = PhoneNumber(command.params.phone_number)
            
            # Update timestamps
            user.updated_at = datetime.now(UTC)
            profile.updated_at = datetime.now(UTC)
            
            # Save changes
            await self._user_repository.update(user)
            await self._user_profile_repository.update(profile)
            
            # Publish profile updated event
            await self._event_bus.publish(
                UserProfileUpdated(
                    aggregate_id=user.id.value,
                    updated_fields=list(command.params.dict(exclude_none=True).keys()),
                    updated_by=command.user_id
                )
            )
            
            # Invalidate cache
            await self._cache_service.delete(f"user_profile:{command.user_id}")
            
            await self._unit_of_work.commit()
            
            return UpdateProfileResponse(
                user_id=user.id.value,
                profile=profile.to_dict(),
                success=True,
                message="Profile updated successfully"
            )

    @audit_action(action=AuditAction.USER_UPDATE, resource_type="user_preferences")
    @authorize(Permission.USER_UPDATE_SELF)
    @validate_request(UpdatePreferencesRequest)
    async def handle_update_preferences(self, command: UpdatePreferencesCommand) -> UpdatePreferencesResponse:
        """Update user preferences."""
        async with self._unit_of_work:
            preferences = await self._user_preference_repository.get_by_user_id(UserId(command.user_id))
            if not preferences:
                preferences = UserPreferences(
                    user_id=UserId(command.user_id),
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC)
                )
            
            # Update preference fields
            if command.params.language:
                if not ValidationUtils.is_valid_language_code(command.params.language):
                    raise ValueError("Invalid language code")
                preferences.language = command.params.language
            
            if command.params.timezone:
                if not ValidationUtils.is_valid_timezone(command.params.timezone):
                    raise ValueError("Invalid timezone")
                preferences.timezone = command.params.timezone
            
            if command.params.theme:
                if command.params.theme not in ["light", "dark", "auto"]:
                    raise ValueError("Invalid theme")
                preferences.theme = command.params.theme
            
            if command.params.notifications_enabled is not None:
                preferences.notifications_enabled = command.params.notifications_enabled
            
            if command.params.email_notifications is not None:
                preferences.email_notifications = command.params.email_notifications
            
            if command.params.sms_notifications is not None:
                preferences.sms_notifications = command.params.sms_notifications
            
            if command.params.marketing_consent is not None:
                preferences.marketing_consent = command.params.marketing_consent
            
            preferences.updated_at = datetime.now(UTC)
            
            # Save changes
            await self._user_preference_repository.update(preferences)
            
            # Invalidate cache
            await self._cache_service.delete(f"user_preferences:{command.user_id}")
            
            await self._unit_of_work.commit()
            
            return UpdatePreferencesResponse(
                user_id=command.user_id,
                preferences=preferences.to_dict(),
                success=True,
                message="Preferences updated successfully"
            )

    @audit_action(action=AuditAction.USER_DEACTIVATE, resource_type="user")
    @authorize(Permission.USER_MANAGE)
    async def handle_deactivate_user(self, command: DeactivateUserCommand) -> None:
        """Deactivate a user account."""
        async with self._unit_of_work:
            user = await self._user_repository.get_by_id(UserId(command.user_id))
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            if user.status == UserStatus.DEACTIVATED:
                raise InvalidOperationError("User is already deactivated")
            
            # Deactivate user
            user.deactivate(reason=command.reason)
            await self._user_repository.update(user)
            
            # Publish deactivation event
            await self._event_bus.publish(
                UserDeactivated(
                    aggregate_id=user.id.value,
                    reason=command.reason,
                    deactivated_by=command.performed_by,
                    deactivated_at=datetime.now(UTC)
                )
            )
            
            await self._unit_of_work.commit()

    @audit_action(action=AuditAction.USER_REACTIVATE, resource_type="user")
    @authorize(Permission.USER_MANAGE)
    async def handle_reactivate_user(self, command: ReactivateUserCommand) -> None:
        """Reactivate a deactivated user account."""
        async with self._unit_of_work:
            user = await self._user_repository.get_by_id(UserId(command.user_id))
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            if user.status != UserStatus.DEACTIVATED:
                raise InvalidOperationError("User is not deactivated")
            
            # Reactivate user
            user.reactivate()
            await self._user_repository.update(user)
            
            # Publish reactivation event
            await self._event_bus.publish(
                UserReactivated(
                    aggregate_id=user.id.value,
                    reactivated_by=command.performed_by,
                    reactivated_at=datetime.now(UTC)
                )
            )
            
            await self._unit_of_work.commit()

    @audit_action(action=AuditAction.USER_DELETE, resource_type="user")
    @authorize(Permission.USER_DELETE)
    async def handle_delete_user(self, command: DeleteUserCommand) -> DeleteUserResponse:
        """Delete a user account (soft or hard delete)."""
        async with self._unit_of_work:
            user = await self._user_repository.get_by_id(UserId(command.user_id))
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            if command.hard_delete:
                # Permanent deletion
                await self._user_repository.delete(user.id)
                await self._user_profile_repository.delete_by_user_id(user.id)
                await self._user_preference_repository.delete_by_user_id(user.id)
                
                # Delete avatar if exists
                profile = await self._user_profile_repository.get_by_user_id(user.id)
                if profile and profile.avatar_url:
                    await self._storage_service.delete(profile.avatar_url)
            else:
                # Soft delete
                user.mark_deleted()
                await self._user_repository.update(user)
            
            # Publish deletion event
            await self._event_bus.publish(
                UserDeleted(
                    aggregate_id=user.id.value,
                    deleted_by=command.performed_by,
                    hard_delete=command.hard_delete,
                    deleted_at=datetime.now(UTC)
                )
            )
            
            await self._unit_of_work.commit()
            
            return DeleteUserResponse(
                success=True,
                message=f"User {'permanently deleted' if command.hard_delete else 'marked as deleted'}"
            )

    @audit_action(action=AuditAction.USER_MERGE, resource_type="user")
    @authorize(Permission.USER_MERGE)
    async def handle_merge_users(self, command: MergeUsersCommand) -> UserMergeResponse:
        """Merge two user accounts."""
        async with self._unit_of_work:
            source_user = await self._user_repository.get_by_id(UserId(command.params.source_user_id))
            target_user = await self._user_repository.get_by_id(UserId(command.params.target_user_id))
            
            if not source_user or not target_user:
                raise UserNotFoundError("One or both users not found")
            
            # Perform merge using domain service
            merge_result = await self._user_domain_service.merge_users(
                source_user=source_user,
                target_user=target_user,
                merge_strategy=command.params.merge_strategy
            )
            
            # Update users
            await self._user_repository.update(target_user)
            await self._user_repository.update(source_user)
            
            # Publish merge event
            await self._event_bus.publish(
                UserMerged(
                    source_user_id=source_user.id.value,
                    target_user_id=target_user.id.value,
                    merged_by=command.performed_by,
                    merge_strategy=command.params.merge_strategy,
                    merged_at=datetime.now(UTC)
                )
            )
            
            await self._unit_of_work.commit()
            
            return UserMergeResponse(
                target_user_id=target_user.id.value,
                merged_data=merge_result,
                success=True,
                message="Users merged successfully"
            )

    @audit_action(action=AuditAction.USER_UPDATE, resource_type="user_contact")
    @authorize(Permission.USER_UPDATE_SELF)
    async def handle_update_contact_info(self, command: UpdateContactInfoCommand) -> UpdateProfileResponse:
        """Update user contact information."""
        async with self._unit_of_work:
            user = await self._user_repository.get_by_id(UserId(command.user_id))
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            profile = await self._user_profile_repository.get_by_user_id(UserId(command.user_id))
            
            # Update email if provided
            if command.email:
                new_email = Email(command.email)
                if not await EmailAvailableSpecification(self._user_repository).is_satisfied_by(new_email):
                    raise DuplicateEmailError(f"Email {new_email.value} is already in use")
                
                # Initiate email change process
                user.initiate_email_change(new_email)
                await self._email_service.send_email_change_confirmation(
                    old_email=user.email.value,
                    new_email=new_email.value,
                    token=user.generate_email_change_token()
                )
            
            # Update phone number if provided
            if command.phone_number and profile:
                profile.phone_number = PhoneNumber(command.phone_number)
                profile.phone_verified = False  # Require re-verification
                profile.updated_at = datetime.now(UTC)
                await self._user_profile_repository.update(profile)
            
            user.updated_at = datetime.now(UTC)
            await self._user_repository.update(user)
            
            await self._unit_of_work.commit()
            
            return UpdateProfileResponse(
                user_id=user.id.value,
                profile=profile.to_dict() if profile else {},
                success=True,
                message="Contact information updated"
            )

    @audit_action(action=AuditAction.USER_UPDATE, resource_type="user_avatar")
    @rate_limit(max_requests=5, window_seconds=3600, strategy='user')
    async def handle_upload_avatar(self, command: UploadAvatarCommand) -> UpdateProfileResponse:
        """Upload user avatar image."""
        async with self._unit_of_work:
            profile = await self._user_profile_repository.get_by_user_id(UserId(command.user_id))
            if not profile:
                raise UserNotFoundError(f"User profile for {command.user_id} not found")
            
            # Validate file
            if len(command.file_data) > 5 * 1024 * 1024:  # 5MB limit
                raise ValueError("Avatar file size must be less than 5MB")
            
            if command.content_type not in ["image/jpeg", "image/png", "image/gif", "image/webp"]:
                raise ValueError("Invalid image format")
            
            # Delete old avatar if exists
            if profile.avatar_url:
                await self._storage_service.delete(profile.avatar_url)
            
            # Process and upload new avatar
            processed_avatar = await self._avatar_service.process_avatar(
                file_data=command.file_data,
                content_type=command.content_type
            )
            
            avatar_url = await self._storage_service.upload(
                file_data=processed_avatar,
                file_name=f"avatars/{command.user_id}/{command.file_name}",
                content_type=command.content_type
            )
            
            # Update profile
            profile.avatar_url = avatar_url
            profile.updated_at = datetime.now(UTC)
            await self._user_profile_repository.update(profile)
            
            # Invalidate cache
            await self._cache_service.delete(f"user_profile:{command.user_id}")
            
            await self._unit_of_work.commit()
            
            return UpdateProfileResponse(
                user_id=command.user_id,
                profile=profile.to_dict(),
                success=True,
                message="Avatar uploaded successfully"
            )

    @audit_action(action=AuditAction.USER_UPDATE, resource_type="user_avatar")
    async def handle_delete_avatar(self, command: DeleteAvatarCommand) -> UpdateProfileResponse:
        """Delete user avatar."""
        async with self._unit_of_work:
            profile = await self._user_profile_repository.get_by_user_id(UserId(command.user_id))
            if not profile:
                raise UserNotFoundError(f"User profile for {command.user_id} not found")
            
            if profile.avatar_url:
                await self._storage_service.delete(profile.avatar_url)
                profile.avatar_url = None
                profile.updated_at = datetime.now(UTC)
                await self._user_profile_repository.update(profile)
                
                # Invalidate cache
                await self._cache_service.delete(f"user_profile:{command.user_id}")
            
            await self._unit_of_work.commit()
            
            return UpdateProfileResponse(
                user_id=command.user_id,
                profile=profile.to_dict(),
                success=True,
                message="Avatar deleted successfully"
            )

    @audit_action(action=AuditAction.USER_UPDATE, resource_type="user_avatar")
    async def handle_generate_avatar(self, command: GenerateAvatarCommand) -> UpdateProfileResponse:
        """Generate avatar from user initials."""
        async with self._unit_of_work:
            user = await self._user_repository.get_by_id(UserId(command.user_id))
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            profile = await self._user_profile_repository.get_by_user_id(UserId(command.user_id))
            if not profile:
                raise UserNotFoundError(f"User profile for {command.user_id} not found")
            
            # Generate avatar from initials
            initials = f"{user.first_name[0]}{user.last_name[0]}".upper()
            avatar_data = await self._avatar_service.generate_from_initials(
                initials=initials,
                background_color=self._get_user_color(command.user_id)
            )
            
            # Upload generated avatar
            avatar_url = await self._storage_service.upload(
                file_data=avatar_data,
                file_name=f"avatars/{command.user_id}/generated.png",
                content_type="image/png"
            )
            
            # Update profile
            if profile.avatar_url:
                await self._storage_service.delete(profile.avatar_url)
            
            profile.avatar_url = avatar_url
            profile.updated_at = datetime.now(UTC)
            await self._user_profile_repository.update(profile)
            
            # Invalidate cache
            await self._cache_service.delete(f"user_profile:{command.user_id}")
            
            await self._unit_of_work.commit()
            
            return UpdateProfileResponse(
                user_id=command.user_id,
                profile=profile.to_dict(),
                success=True,
                message="Avatar generated successfully"
            )

    @audit_action(action=AuditAction.USER_DATA_TRANSFER, resource_type="user")
    @authorize(Permission.USER_DATA_TRANSFER)
    async def handle_transfer_user_data(self, command: TransferUserDataCommand) -> None:
        """Transfer data between users."""
        async with self._unit_of_work:
            source_user = await self._user_repository.get_by_id(UserId(command.source_user_id))
            target_user = await self._user_repository.get_by_id(UserId(command.target_user_id))
            
            if not source_user or not target_user:
                raise UserNotFoundError("One or both users not found")
            
            # Perform data transfer using domain service
            await self._user_domain_service.transfer_data(
                source_user=source_user,
                target_user=target_user,
                data_types=command.data_types
            )
            
            await self._unit_of_work.commit()

    # Private helper methods
    def _get_user_color(self, user_id: UUID) -> str:
        """Generate consistent color for user based on ID."""
        # Use hash of user ID to generate color
        hash_value = hash(str(user_id))
        colors = ["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4", "#FECA57", "#48C9B0", "#5DADE2", "#F7DC6F"]
        return colors[hash_value % len(colors)]