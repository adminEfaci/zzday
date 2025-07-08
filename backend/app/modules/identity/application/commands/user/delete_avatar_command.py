"""
Delete avatar command implementation.

Handles user avatar deletion and fallback to default.
"""

import contextlib
from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAvatarGenerationService,
    ICacheService,
    IFileStorageService,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
    require_self_or_permission,
)
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction, AvatarStyle
from app.modules.identity.domain.events import UserAvatarDeleted
from app.modules.identity.domain.exceptions import (
    UserNotFoundError,
)
from app.modules.identity.domain.services import SecurityService


class DeleteAvatarCommand(Command[BaseResponse]):
    """Command to delete user avatar."""
    
    def __init__(
        self,
        user_id: UUID,
        generate_default: bool = True,
        default_style: AvatarStyle | None = None,
        deleted_by: UUID | None = None,
        reason: str | None = None
    ):
        self.user_id = user_id
        self.generate_default = generate_default
        self.default_style = default_style or AvatarStyle.INITIALS
        self.deleted_by = deleted_by or user_id
        self.reason = reason


class DeleteAvatarCommandHandler(CommandHandler[DeleteAvatarCommand, BaseResponse]):
    """Handler for avatar deletion."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        file_storage_service: IFileStorageService,
        avatar_generation_service: IAvatarGenerationService,
        security_service: SecurityService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._file_storage_service = file_storage_service
        self._avatar_generation_service = avatar_generation_service
        self._security_service = security_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.AVATAR_DELETED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=True
    )
    @require_auth
    @require_self_or_permission(
        permission="users.manage_avatar",
        resource_type="user",
        resource_id_attr="user_id"
    )
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: DeleteAvatarCommand) -> BaseResponse:
        """
        Delete user avatar.
        
        Process:
        1. Validate user exists
        2. Check if avatar exists
        3. Delete avatar files
        4. Generate default if requested
        5. Update user record
        6. Clear caches
        7. Log administrative action
        8. Publish event
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            UserNotFoundError: If user not found
            InvalidOperationError: If no avatar to delete
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.get_by_id(command.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Check if avatar exists
            if not user.avatar_url:
                return BaseResponse(
                    success=True,
                    message="No avatar to delete"
                )
            
            # 3. Store old avatar info
            old_avatar_url = user.avatar_url
            
            # 4. Delete avatar files
            try:
                await self._delete_avatar_files(user)
            except Exception as e:
                # Log but continue - files might already be deleted
                await self._log_deletion_error(user, e)
            
            # 5. Generate default avatar if requested
            default_avatar_url = None
            default_thumbnail_url = None
            
            if command.generate_default:
                try:
                    default_avatars = await self._generate_default_avatar(
                        user=user,
                        style=command.default_style
                    )
                    default_avatar_url = default_avatars.get('large')
                    default_thumbnail_url = default_avatars.get('thumbnail')
                except Exception as e:
                    # Log but continue without default
                    await self._log_default_generation_error(user, e)
            
            # 6. Update user record
            user.avatar_url = default_avatar_url
            user.avatar_thumbnail_url = default_thumbnail_url
            user.avatar_generated = command.generate_default
            user.avatar_style = command.default_style if command.generate_default else None
            user.updated_at = datetime.now(UTC)
            
            await self._user_repository.update(user)
            
            # 7. Clear caches
            await self._clear_user_caches(command.user_id)
            
            # 8. Log if deleted by admin
            if command.deleted_by != command.user_id:
                await self._log_admin_deletion(
                    user=user,
                    deleted_by=command.deleted_by,
                    reason=command.reason
                )
            
            # 9. Log security event if avatar was inappropriate
            if command.reason and 'inappropriate' in command.reason.lower():
                await self._log_inappropriate_avatar(
                    user=user,
                    deleted_by=command.deleted_by,
                    reason=command.reason
                )
            
            # 10. Publish event
            await self._event_bus.publish(
                UserAvatarDeleted(
                    aggregate_id=user.id,
                    old_avatar_url=old_avatar_url,
                    new_avatar_url=default_avatar_url,
                    deleted_by=command.deleted_by,
                    reason=command.reason,
                    default_generated=command.generate_default
                )
            )
            
            # 11. Commit transaction
            await self._unit_of_work.commit()
            
            message = "Avatar deleted successfully"
            if command.generate_default:
                message += f" and replaced with {command.default_style.value} avatar"
            
            return BaseResponse(
                success=True,
                message=message
            )
    
    async def _delete_avatar_files(self, user: User) -> None:
        """Delete all avatar files for user."""
        # Delete all files under user's avatar directory
        await self._file_storage_service.delete_files_by_prefix(
            prefix=f"avatars/{user.id}/"
        )
        
        # Also try to delete specific URLs if stored
        if user.avatar_url:
            with contextlib.suppress(Exception):
                # URL might be external or already deleted
                await self._file_storage_service.delete_file_by_url(
                    url=user.avatar_url
                )
    
    async def _generate_default_avatar(
        self,
        user: User,
        style: AvatarStyle
    ) -> dict:
        """Generate default avatar for user."""
        # Generate simple default avatar
        if style == AvatarStyle.INITIALS:
            initials = self._extract_initials(user)
            avatar_data = await self._avatar_generation_service.generate_initials_avatar(
                initials=initials,
                size=256,
                background_color='#6366f1',  # Default indigo
                text_color='#ffffff'
            )
        else:
            # Use identicon as fallback
            seed = f"{user.id}:{user.username}"
            avatar_data = await self._avatar_generation_service.generate_identicon(
                seed=seed,
                size=256
            )
        
        # Generate basic sizes
        sizes = {
            'thumbnail': 64,
            'small': 128,
            'large': 256
        }
        
        avatar_urls = {}
        
        for size_name, size in sizes.items():
            # Process image
            if size != 256:
                processed = await self._avatar_generation_service.resize_image(
                    image_data=avatar_data,
                    size=size
                )
            else:
                processed = avatar_data
            
            # Upload
            file_name = f"avatars/{user.id}/default_{size_name}.webp"
            url = await self._file_storage_service.upload_file(
                file_path=file_name,
                file_data=processed,
                content_type='image/webp',
                metadata={
                    'user_id': str(user.id),
                    'type': 'default',
                    'size': size_name
                }
            )
            
            avatar_urls[size_name] = url
        
        return avatar_urls
    
    def _extract_initials(self, user: User) -> str:
        """Extract initials from user name."""
        if user.full_name:
            parts = user.full_name.split()
            if len(parts) >= 2:
                return f"{parts[0][0]}{parts[-1][0]}".upper()
            if parts:
                return parts[0][:2].upper()
        
        return user.username[:2].upper()
    
    async def _clear_user_caches(self, user_id: UUID) -> None:
        """Clear user-related caches."""
        cache_keys = [
            f"user:{user_id}",
            f"user_profile:{user_id}",
            f"user_avatar:{user_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _log_deletion_error(self, user: User, error: Exception) -> None:
        """Log avatar deletion error."""
        await self._security_service.log_error(
            error_type="avatar_deletion_failed",
            details={
                "user_id": str(user.id),
                "error": str(error),
                "avatar_url": user.avatar_url
            }
        )
    
    async def _log_default_generation_error(self, user: User, error: Exception) -> None:
        """Log default avatar generation error."""
        await self._security_service.log_error(
            error_type="default_avatar_generation_failed",
            details={
                "user_id": str(user.id),
                "error": str(error)
            }
        )
    
    async def _log_admin_deletion(
        self,
        user: User,
        deleted_by: UUID,
        reason: str | None
    ) -> None:
        """Log administrative avatar deletion."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="avatar_deleted_by_admin",
            details={
                "deleted_by": str(deleted_by),
                "reason": reason,
                "previous_avatar": user.avatar_url
            }
        )
    
    async def _log_inappropriate_avatar(
        self,
        user: User,
        deleted_by: UUID,
        reason: str
    ) -> None:
        """Log inappropriate avatar incident."""
        await self._security_service.log_security_incident(
            incident_type="inappropriate_avatar",
            severity="medium",
            user_id=user.id,
            details={
                "deleted_by": str(deleted_by),
                "reason": reason,
                "avatar_url": user.avatar_url,
                "action_taken": "avatar_deleted"
            }
        )