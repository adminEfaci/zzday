"""
Upload avatar command implementation.

Handles user avatar upload with validation and processing.
"""

import hashlib
from datetime import UTC, datetime
from typing import ClassVar
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    ICacheService,
    IFileStorageService,
    IImageProcessingService,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
    require_self_or_permission,
    validate_request,
)
from app.modules.identity.application.dtos.request import UploadAvatarRequest
from app.modules.identity.application.dtos.response import AvatarResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction
from app.modules.identity.domain.events import UserAvatarUpdated
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    UserNotFoundError,
    ValidationError,
)
from app.modules.identity.domain.services import SecurityService


class UploadAvatarCommand(Command[AvatarResponse]):
    """Command to upload user avatar."""
    
    def __init__(
        self,
        user_id: UUID,
        file_data: bytes,
        file_name: str,
        content_type: str,
        uploaded_by: UUID | None = None
    ):
        self.user_id = user_id
        self.file_data = file_data
        self.file_name = file_name
        self.content_type = content_type
        self.uploaded_by = uploaded_by or user_id


class UploadAvatarCommandHandler(CommandHandler[UploadAvatarCommand, AvatarResponse]):
    """Handler for avatar upload."""
    
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_CONTENT_TYPES: ClassVar[set[str]] = {
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp'
    }
    AVATAR_SIZES: ClassVar[dict[str, tuple[int, int]]] = {
        'thumbnail': (64, 64),
        'small': (128, 128),
        'medium': (256, 256),
        'large': (512, 512)
    }
    
    def __init__(
        self,
        user_repository: IUserRepository,
        file_storage_service: IFileStorageService,
        image_processing_service: IImageProcessingService,
        security_service: SecurityService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._file_storage_service = file_storage_service
        self._image_processing_service = image_processing_service
        self._security_service = security_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.AVATAR_UPLOADED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=False  # Don't log file data
    )
    @require_auth
    @require_self_or_permission(
        permission="users.manage_avatar",
        resource_type="user",
        resource_id_attr="user_id"
    )
    @validate_request(UploadAvatarRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: UploadAvatarCommand) -> AvatarResponse:
        """
        Upload and process user avatar.
        
        Process:
        1. Validate user exists
        2. Validate file
        3. Scan for malicious content
        4. Process image (resize, optimize)
        5. Delete old avatar
        6. Upload new avatar variants
        7. Update user record
        8. Clear caches
        9. Publish event
        
        Returns:
            AvatarResponse with avatar URLs
            
        Raises:
            UserNotFoundError: If user not found
            ValidationError: If invalid file
            InvalidOperationError: If security issues
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.get_by_id(command.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Validate file
            self._validate_file(command)
            
            # 3. Scan for malicious content
            is_safe = await self._security_service.scan_file(
                file_data=command.file_data,
                file_name=command.file_name,
                content_type=command.content_type
            )
            
            if not is_safe:
                raise InvalidOperationError(
                    "File failed security scan"
                )
            
            # 4. Process image
            processed_images = await self._process_avatar_image(command)
            
            # 5. Delete old avatars if exist
            if user.avatar_url:
                await self._delete_old_avatars(user)
            
            # 6. Upload new avatar variants
            avatar_urls = await self._upload_avatar_variants(
                user_id=command.user_id,
                images=processed_images
            )
            
            # 7. Update user avatar
            old_avatar = user.avatar_url
            user.avatar_url = avatar_urls['large']
            user.avatar_thumbnail_url = avatar_urls['thumbnail']
            user.updated_at = datetime.now(UTC)
            
            await self._user_repository.update(user)
            
            # 8. Clear caches
            await self._clear_user_caches(command.user_id)
            
            # 9. Log if uploaded by admin
            if command.uploaded_by != command.user_id:
                await self._log_admin_upload(
                    user=user,
                    uploaded_by=command.uploaded_by
                )
            
            # 10. Publish event
            await self._event_bus.publish(
                UserAvatarUpdated(
                    aggregate_id=user.id,
                    old_avatar_url=old_avatar,
                    new_avatar_url=avatar_urls['large'],
                    avatar_urls=avatar_urls,
                    uploaded_by=command.uploaded_by
                )
            )
            
            # 11. Commit transaction
            await self._unit_of_work.commit()
            
            return AvatarResponse(
                avatar_url=avatar_urls['large'],
                thumbnail_url=avatar_urls['thumbnail'],
                small_url=avatar_urls['small'],
                medium_url=avatar_urls['medium'],
                large_url=avatar_urls['large'],
                upload_timestamp=datetime.now(UTC),
                file_size=len(command.file_data),
                content_type=command.content_type,
                success=True,
                message="Avatar uploaded successfully"
            )
    
    def _validate_file(self, command: UploadAvatarCommand) -> None:
        """Validate uploaded file."""
        # Check file size
        if len(command.file_data) > self.MAX_FILE_SIZE:
            raise ValidationError(
                f"File size exceeds maximum of {self.MAX_FILE_SIZE // 1024 // 1024}MB"
            )
        
        # Check content type
        if command.content_type not in self.ALLOWED_CONTENT_TYPES:
            raise ValidationError(
                f"Invalid file type. Allowed types: {', '.join(self.ALLOWED_CONTENT_TYPES)}"
            )
        
        # Validate file extension matches content type
        extension = command.file_name.lower().split('.')[-1]
        expected_extensions = {
            'image/jpeg': ['jpg', 'jpeg'],
            'image/png': ['png'],
            'image/gif': ['gif'],
            'image/webp': ['webp']
        }
        
        valid_extensions = expected_extensions.get(command.content_type, [])
        if extension not in valid_extensions:
            raise ValidationError(
                "File extension doesn't match content type"
            )
    
    async def _process_avatar_image(
        self,
        command: UploadAvatarCommand
    ) -> dict:
        """Process avatar image into multiple sizes."""
        processed_images = {}
        
        for size_name, dimensions in self.AVATAR_SIZES.items():
            # Resize and optimize
            processed = await self._image_processing_service.process_image(
                image_data=command.file_data,
                width=dimensions[0],
                height=dimensions[1],
                format='webp',  # Convert to WebP for optimization
                quality=85,
                crop='center'  # Center crop for consistent avatars
            )
            
            processed_images[size_name] = processed
        
        return processed_images
    
    async def _upload_avatar_variants(
        self,
        user_id: UUID,
        images: dict
    ) -> dict:
        """Upload avatar variants to storage."""
        avatar_urls = {}
        
        # Generate unique prefix for this user's avatars
        prefix = f"avatars/{user_id}/{datetime.now(UTC).timestamp()}"
        
        for size_name, image_data in images.items():
            # Generate file name with hash to enable CDN caching
            file_hash = hashlib.sha256(image_data).hexdigest()[:8]
            file_name = f"{prefix}/{size_name}_{file_hash}.webp"
            
            # Upload to storage
            url = await self._file_storage_service.upload_file(
                file_path=file_name,
                file_data=image_data,
                content_type='image/webp',
                metadata={
                    'user_id': str(user_id),
                    'size': size_name,
                    'uploaded_at': datetime.now(UTC).isoformat()
                }
            )
            
            avatar_urls[size_name] = url
        
        return avatar_urls
    
    async def _delete_old_avatars(self, user: User) -> None:
        """Delete old avatar files."""
        if not user.avatar_url:
            return
        
        # Extract path from URL
        # Assuming URL format: https://storage.example.com/bucket/avatars/...
        try:
            # Delete all size variants
            for size_name in self.AVATAR_SIZES:
                await self._file_storage_service.delete_file(
                    file_path=f"avatars/{user.id}/{size_name}_*.webp"
                )
        except Exception as e:
            # Log but don't fail if deletion fails
            await self._security_service.log_error(
                error_type="avatar_deletion_failed",
                details={
                    "user_id": str(user.id),
                    "error": str(e)
                }
            )
    
    async def _clear_user_caches(self, user_id: UUID) -> None:
        """Clear user-related caches."""
        cache_keys = [
            f"user:{user_id}",
            f"user_profile:{user_id}",
            f"user_avatar:{user_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _log_admin_upload(
        self,
        user: User,
        uploaded_by: UUID
    ) -> None:
        """Log when avatar uploaded by admin."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="avatar_uploaded_by_admin",
            details={
                "uploaded_by": str(uploaded_by),
                "previous_avatar": user.avatar_url
            }
        )