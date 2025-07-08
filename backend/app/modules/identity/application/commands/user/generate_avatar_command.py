"""
Generate avatar command implementation.

Handles automatic avatar generation using various methods.
"""

import hashlib
from datetime import UTC, datetime
from typing import ClassVar
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAvatarGenerationService,
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
from app.modules.identity.application.dtos.request import GenerateAvatarRequest
from app.modules.identity.application.dtos.response import AvatarResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction, AvatarStyle
from app.modules.identity.domain.events import UserAvatarGenerated
from app.modules.identity.domain.exceptions import (
    ExternalServiceError,
    InvalidOperationError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import SecurityService


class GenerateAvatarCommand(Command[AvatarResponse]):
    """Command to generate avatar automatically."""
    
    def __init__(
        self,
        user_id: UUID,
        style: AvatarStyle,
        seed: str | None = None,
        colors: dict[str, str] | None = None,
        generated_by: UUID | None = None
    ):
        self.user_id = user_id
        self.style = style
        self.seed = seed
        self.colors = colors
        self.generated_by = generated_by or user_id


class GenerateAvatarCommandHandler(CommandHandler[GenerateAvatarCommand, AvatarResponse]):
    """Handler for avatar generation."""
    
    AVATAR_SIZES: ClassVar[dict[str, tuple[int, int]]] = {
        'thumbnail': (64, 64),
        'small': (128, 128),
        'medium': (256, 256),
        'large': (512, 512)
    }
    
    def __init__(
        self,
        user_repository: IUserRepository,
        avatar_generation_service: IAvatarGenerationService,
        file_storage_service: IFileStorageService,
        image_processing_service: IImageProcessingService,
        security_service: SecurityService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._avatar_generation_service = avatar_generation_service
        self._file_storage_service = file_storage_service
        self._image_processing_service = image_processing_service
        self._security_service = security_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.AVATAR_GENERATED,
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
    @validate_request(GenerateAvatarRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: GenerateAvatarCommand) -> AvatarResponse:
        """
        Generate avatar for user.
        
        Process:
        1. Validate user exists
        2. Generate seed if not provided
        3. Generate avatar based on style
        4. Process into multiple sizes
        5. Delete old avatar
        6. Upload new avatar variants
        7. Update user record
        8. Clear caches
        9. Publish event
        
        Returns:
            AvatarResponse with generated avatar URLs
            
        Raises:
            UserNotFoundError: If user not found
            ExternalServiceError: If generation fails
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.get_by_id(command.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Generate seed if not provided
            seed = command.seed or self._generate_seed(user)
            
            # 3. Generate avatar based on style
            try:
                avatar_data = await self._generate_avatar(
                    style=command.style,
                    seed=seed,
                    colors=command.colors,
                    user=user
                )
            except Exception as e:
                raise ExternalServiceError(
                    f"Avatar generation failed: {e!s}"
                ) from e
            
            # 4. Process into multiple sizes
            processed_images = await self._process_generated_avatar(
                avatar_data=avatar_data,
                original_size=self.AVATAR_SIZES['large']
            )
            
            # 5. Delete old avatars if exist
            if user.avatar_url:
                await self._delete_old_avatars(user)
            
            # 6. Upload avatar variants
            avatar_urls = await self._upload_avatar_variants(
                user_id=command.user_id,
                images=processed_images
            )
            
            # 7. Update user avatar
            old_avatar = user.avatar_url
            user.avatar_url = avatar_urls['large']
            user.avatar_thumbnail_url = avatar_urls['thumbnail']
            user.avatar_generated = True
            user.avatar_style = command.style
            user.updated_at = datetime.now(UTC)
            
            await self._user_repository.update(user)
            
            # 8. Clear caches
            await self._clear_user_caches(command.user_id)
            
            # 9. Log generation details
            await self._log_generation_details(
                user=user,
                command=command,
                seed=seed
            )
            
            # 10. Publish event
            await self._event_bus.publish(
                UserAvatarGenerated(
                    aggregate_id=user.id,
                    old_avatar_url=old_avatar,
                    new_avatar_url=avatar_urls['large'],
                    avatar_urls=avatar_urls,
                    style=command.style,
                    seed=seed,
                    generated_by=command.generated_by
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
                style=command.style,
                seed=seed,
                generated=True,
                upload_timestamp=datetime.now(UTC),
                success=True,
                message=f"Avatar generated successfully using {command.style.value} style"
            )
    
    def _generate_seed(self, user: User) -> str:
        """Generate consistent seed for user."""
        # Use combination of user ID and username for consistency
        seed_data = f"{user.id}:{user.username}:{user.email}"
        return hashlib.sha256(seed_data.encode()).hexdigest()[:16]
    
    async def _generate_avatar(
        self,
        style: AvatarStyle,
        seed: str,
        colors: dict[str, str] | None,
        user: User
    ) -> bytes:
        """Generate avatar based on style."""
        if style == AvatarStyle.IDENTICON:
            return await self._avatar_generation_service.generate_identicon(
                seed=seed,
                size=self.AVATAR_SIZES['large'][0],
                colors=colors
            )
        
        if style == AvatarStyle.INITIALS:
            initials = self._extract_initials(user)
            return await self._avatar_generation_service.generate_initials_avatar(
                initials=initials,
                size=self.AVATAR_SIZES['large'][0],
                background_color=colors.get('background') if colors else None,
                text_color=colors.get('text') if colors else None
            )
        
        if style == AvatarStyle.PATTERN:
            return await self._avatar_generation_service.generate_pattern_avatar(
                seed=seed,
                size=self.AVATAR_SIZES['large'][0],
                pattern_type='geometric',
                colors=colors
            )
        
        if style == AvatarStyle.GRADIENT:
            return await self._avatar_generation_service.generate_gradient_avatar(
                seed=seed,
                size=self.AVATAR_SIZES['large'][0],
                gradient_type='linear',
                colors=colors
            )
        
        if style == AvatarStyle.EMOJI:
            # Select emoji based on seed
            emoji = self._select_emoji_from_seed(seed)
            return await self._avatar_generation_service.generate_emoji_avatar(
                emoji=emoji,
                size=self.AVATAR_SIZES['large'][0],
                background_color=colors.get('background') if colors else None
            )
        
        if style == AvatarStyle.ROBOT:
            return await self._avatar_generation_service.generate_robohash(
                seed=seed,
                size=self.AVATAR_SIZES['large'][0],
                robot_set='set1'
            )
        
        if style == AvatarStyle.MONSTER:
            return await self._avatar_generation_service.generate_monster_avatar(
                seed=seed,
                size=self.AVATAR_SIZES['large'][0],
                monster_type='cute'
            )
        
        if style == AvatarStyle.ABSTRACT:
            return await self._avatar_generation_service.generate_abstract_art(
                seed=seed,
                size=self.AVATAR_SIZES['large'][0],
                complexity='medium',
                colors=colors
            )
        
        raise InvalidOperationError(f"Unsupported avatar style: {style}")
    
    def _extract_initials(self, user: User) -> str:
        """Extract initials from user name."""
        if user.full_name:
            parts = user.full_name.split()
            if len(parts) >= 2:
                return f"{parts[0][0]}{parts[-1][0]}".upper()
            if parts:
                return parts[0][:2].upper()
        
        # Fallback to username
        return user.username[:2].upper()
    
    def _select_emoji_from_seed(self, seed: str) -> str:
        """Select emoji based on seed for consistency."""
        emojis = [
            "😀", "😎", "🤖", "🦄", "🐱", "🐶", "🦊", "🐼", 
            "🐨", "🐯", "🦁", "🐸", "🐧", "🦉", "🦋", "🐢",
            "🌟", "🌈", "🎨", "🎭", "🎪", "🎯", "🎲", "🎸"
        ]
        
        # Use seed to select emoji consistently
        index = int(hashlib.md5(seed.encode()).hexdigest(), 16) % len(emojis)
        return emojis[index]
    
    async def _process_generated_avatar(
        self,
        avatar_data: bytes,
        original_size: tuple
    ) -> dict:
        """Process generated avatar into multiple sizes."""
        processed_images = {}
        
        for size_name, dimensions in self.AVATAR_SIZES.items():
            if dimensions == original_size:
                # Original size, just optimize
                processed = await self._image_processing_service.optimize_image(
                    image_data=avatar_data,
                    format='webp',
                    quality=90
                )
            else:
                # Resize
                processed = await self._image_processing_service.process_image(
                    image_data=avatar_data,
                    width=dimensions[0],
                    height=dimensions[1],
                    format='webp',
                    quality=85,
                    maintain_aspect_ratio=True
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
        
        # Generate unique prefix
        prefix = f"avatars/{user_id}/generated_{datetime.now(UTC).timestamp()}"
        
        for size_name, image_data in images.items():
            file_hash = hashlib.sha256(image_data).hexdigest()[:8]
            file_name = f"{prefix}/{size_name}_{file_hash}.webp"
            
            url = await self._file_storage_service.upload_file(
                file_path=file_name,
                file_data=image_data,
                content_type='image/webp',
                metadata={
                    'user_id': str(user_id),
                    'size': size_name,
                    'generated': 'true',
                    'uploaded_at': datetime.now(UTC).isoformat()
                }
            )
            
            avatar_urls[size_name] = url
        
        return avatar_urls
    
    async def _delete_old_avatars(self, user: User) -> None:
        """Delete old avatar files."""
        if not user.avatar_url:
            return
        
        try:
            # Delete all size variants
            await self._file_storage_service.delete_files_by_prefix(
                prefix=f"avatars/{user.id}/"
            )
        except Exception as e:
            # Log but don't fail
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
    
    async def _log_generation_details(
        self,
        user: User,
        command: GenerateAvatarCommand,
        seed: str
    ) -> None:
        """Log avatar generation details."""
        details = {
            "style": command.style.value,
            "seed": seed[:8] + "...",  # Truncate for privacy
            "has_colors": bool(command.colors),
            "previous_avatar": bool(user.avatar_url),
            "generated_by": str(command.generated_by)
        }
        
        if command.generated_by != user.id:
            details["admin_generated"] = True
        
        await self._security_service.log_event(
            event_type="avatar_generated",
            user_id=user.id,
            details=details
        )