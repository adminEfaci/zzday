"""
File Storage Service Adapter

Production-ready implementation for file storage, particularly user avatars.
"""

import hashlib
import os
from datetime import UTC, datetime
from io import BytesIO
from typing import BinaryIO
from uuid import UUID

from PIL import Image

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.infrastructure.file_storage_port import (
    IFileStoragePort,
)


class FileStorageAdapter(IFileStoragePort):
    """Production file storage adapter."""

    def __init__(
        self,
        s3_client=None,
        cloudinary_client=None,
        local_storage_path="/tmp/avatars",
        cdn_base_url="https://cdn.example.com",
        max_file_size_mb=5,
        allowed_formats=None,
    ):
        """Initialize file storage adapter.

        Args:
            s3_client: AWS S3 client
            cloudinary_client: Cloudinary client
            local_storage_path: Local storage path for development
            cdn_base_url: CDN base URL
            max_file_size_mb: Maximum file size in MB
            allowed_formats: Allowed image formats
        """
        self._s3_client = s3_client
        self._cloudinary = cloudinary_client
        self._local_path = local_storage_path
        self._cdn_base_url = cdn_base_url
        self._max_file_size = max_file_size_mb * 1024 * 1024
        self._allowed_formats = allowed_formats or ["JPEG", "PNG", "GIF", "WEBP"]
        
        # Ensure local storage directory exists
        os.makedirs(self._local_path, exist_ok=True)
        
        # Thumbnail sizes
        self._thumbnail_sizes = {
            "small": (32, 32),
            "medium": (64, 64),
            "large": (128, 128),
            "xlarge": (256, 256),
        }

    async def store_avatar(
        self, user_id: UUID, file_data: BinaryIO, content_type: str
    ) -> dict[str, any]:
        """Store user avatar."""
        try:
            # Read file data
            file_content = file_data.read()
            file_size = len(file_content)
            
            # Validate file size
            if file_size > self._max_file_size:
                raise ValueError(f"File size {file_size} exceeds maximum {self._max_file_size}")
            
            # Validate and process image
            image = Image.open(BytesIO(file_content))
            
            # Validate format
            if image.format not in self._allowed_formats:
                raise ValueError(f"Unsupported format {image.format}")
            
            # Generate file metadata
            file_hash = hashlib.sha256(file_content).hexdigest()
            filename = f"{user_id}_{file_hash}.{image.format.lower()}"
            
            # Store the avatar
            storage_path = await self._store_file(filename, file_content, content_type)
            
            # Create AvatarStorage-like dict
            avatar_storage = {
                "user_id": str(user_id),
                "file_path": storage_path,
                "filename": filename,
                "content_type": content_type,
                "file_size": file_size,
                "file_hash": file_hash,
                "dimensions": {
                    "width": image.width,
                    "height": image.height,
                },
                "format": image.format,
                "storage_provider": self._get_storage_provider(),
                "cdn_url": f"{self._cdn_base_url}/avatars/{filename}",
                "uploaded_at": datetime.now(UTC).isoformat(),
                "expires_at": None,  # Avatars don't expire
            }

            logger.info(f"Avatar stored for user {user_id}: {filename} ({file_size} bytes)")
            return avatar_storage

        except Exception as e:
            logger.error(f"Error storing avatar for user {user_id}: {e}")
            raise

    async def delete_avatar(self, user_id: UUID) -> bool:
        """Delete user avatar."""
        try:
            # Find existing avatar files
            avatar_files = await self._find_user_avatar_files(user_id)
            
            if not avatar_files:
                logger.warning(f"No avatar files found for user {user_id}")
                return False
            
            # Delete all avatar files and thumbnails
            deleted_count = 0
            for file_path in avatar_files:
                if await self._delete_file(file_path):
                    deleted_count += 1
            
            # Delete thumbnails
            thumbnail_count = await self._delete_thumbnails(user_id)
            
            logger.info(f"Deleted {deleted_count} avatar files and {thumbnail_count} thumbnails for user {user_id}")
            return deleted_count > 0

        except Exception as e:
            logger.error(f"Error deleting avatar for user {user_id}: {e}")
            return False

    async def generate_avatar_url(
        self, user_id: UUID, size: int | None = None
    ) -> str:
        """Generate avatar URL."""
        try:
            # Find user's avatar file
            avatar_files = await self._find_user_avatar_files(user_id)
            
            if not avatar_files:
                # Return default avatar URL
                return f"{self._cdn_base_url}/default-avatar.png"
            
            # Get the main avatar file
            main_avatar = avatar_files[0]
            filename = os.path.basename(main_avatar)
            
            # Generate URL based on size
            if size:
                # Return thumbnail URL
                size_name = self._get_thumbnail_size_name(size)
                return f"{self._cdn_base_url}/avatars/thumbs/{size_name}/{filename}"
            # Return original URL
            return f"{self._cdn_base_url}/avatars/{filename}"

        except Exception as e:
            logger.error(f"Error generating avatar URL for user {user_id}: {e}")
            return f"{self._cdn_base_url}/default-avatar.png"

    async def process_avatar_thumbnails(
        self, user_id: UUID, avatar_storage: dict[str, any]
    ) -> dict[str, any]:
        """Process avatar thumbnails."""
        try:
            original_path = avatar_storage["file_path"]
            
            # Load original image
            with Image.open(original_path) as original_image:
                thumbnails = {}
                
                # Generate thumbnails for each size
                for size_name, (width, height) in self._thumbnail_sizes.items():
                    thumbnail = await self._create_thumbnail(
                        original_image, user_id, size_name, width, height
                    )
                    thumbnails[size_name] = thumbnail
                
                # Create ThumbnailSet-like dict
                thumbnail_set = {
                    "user_id": str(user_id),
                    "original_avatar": avatar_storage,
                    "thumbnails": thumbnails,
                    "created_at": datetime.now(UTC).isoformat(),
                    "total_thumbnails": len(thumbnails),
                }
                
                logger.info(f"Generated {len(thumbnails)} thumbnails for user {user_id}")
                return thumbnail_set

        except Exception as e:
            logger.error(f"Error processing avatar thumbnails for user {user_id}: {e}")
            # Return empty thumbnail set
            return {
                "user_id": str(user_id),
                "original_avatar": avatar_storage,
                "thumbnails": {},
                "created_at": datetime.now(UTC).isoformat(),
                "total_thumbnails": 0,
                "error": str(e),
            }

    async def _store_file(self, filename: str, file_content: bytes, content_type: str) -> str:
        """Store file using configured storage provider."""
        if self._s3_client:
            return await self._store_to_s3(filename, file_content, content_type)
        if self._cloudinary:
            return await self._store_to_cloudinary(filename, file_content, content_type)
        return await self._store_to_local(filename, file_content)

    async def _store_to_s3(self, filename: str, file_content: bytes, content_type: str) -> str:
        """Store file to AWS S3."""
        try:
            key = f"avatars/{filename}"
            
            # Upload to S3
            await self._s3_client.put_object(
                Bucket="user-avatars",
                Key=key,
                Body=file_content,
                ContentType=content_type,
                CacheControl="max-age=31536000",  # 1 year
            )
            
            return f"s3://user-avatars/{key}"
            
        except Exception as e:
            logger.error(f"Error storing file to S3: {e}")
            raise

    async def _store_to_cloudinary(self, filename: str, file_content: bytes, content_type: str) -> str:
        """Store file to Cloudinary."""
        try:
            # Upload to Cloudinary
            result = await self._cloudinary.uploader.upload(
                file_content,
                public_id=f"avatars/{filename}",
                resource_type="image",
                overwrite=True,
            )
            
            return result["secure_url"]
            
        except Exception as e:
            logger.error(f"Error storing file to Cloudinary: {e}")
            raise

    async def _store_to_local(self, filename: str, file_content: bytes) -> str:
        """Store file to local filesystem."""
        try:
            file_path = os.path.join(self._local_path, filename)
            
            with open(file_path, "wb") as f:
                f.write(file_content)
            
            return file_path
            
        except Exception as e:
            logger.error(f"Error storing file locally: {e}")
            raise

    async def _find_user_avatar_files(self, user_id: UUID) -> list[str]:
        """Find all avatar files for user."""
        try:
            user_id_str = str(user_id)
            avatar_files = []
            
            if self._s3_client:
                # Search S3
                response = await self._s3_client.list_objects_v2(
                    Bucket="user-avatars",
                    Prefix=f"avatars/{user_id_str}_",
                )
                
                for obj in response.get("Contents", []):
                    avatar_files.append(f"s3://user-avatars/{obj['Key']}")
            
            elif self._cloudinary:
                # Search Cloudinary
                search_result = await self._cloudinary.search.expression(
                    f"public_id:avatars/{user_id_str}_*"
                ).execute()
                
                for resource in search_result.get("resources", []):
                    avatar_files.append(resource["secure_url"])
            
            else:
                # Search local filesystem
                for filename in os.listdir(self._local_path):
                    if filename.startswith(f"{user_id_str}_"):
                        avatar_files.append(os.path.join(self._local_path, filename))
            
            return avatar_files
            
        except Exception as e:
            logger.error(f"Error finding avatar files for user {user_id}: {e}")
            return []

    async def _delete_file(self, file_path: str) -> bool:
        """Delete a file."""
        try:
            if file_path.startswith("s3://"):
                # Delete from S3
                bucket, key = file_path.replace("s3://", "").split("/", 1)
                await self._s3_client.delete_object(Bucket=bucket, Key=key)
                return True
            
            if file_path.startswith("http"):
                # Delete from Cloudinary
                public_id = file_path.split("/")[-1].split(".")[0]
                await self._cloudinary.uploader.destroy(f"avatars/{public_id}")
                return True
            
            # Delete from local filesystem
            if os.path.exists(file_path):
                os.remove(file_path)
                return True
                
        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {e}")
            
        return False

    async def _delete_thumbnails(self, user_id: UUID) -> int:
        """Delete all thumbnails for user."""
        try:
            deleted_count = 0
            user_id_str = str(user_id)
            
            # Delete thumbnails for each size
            for size_name in self._thumbnail_sizes:
                thumb_path = f"avatars/thumbs/{size_name}/{user_id_str}_"
                
                if self._s3_client:
                    # Delete from S3
                    response = await self._s3_client.list_objects_v2(
                        Bucket="user-avatars",
                        Prefix=thumb_path,
                    )
                    
                    for obj in response.get("Contents", []):
                        await self._s3_client.delete_object(
                            Bucket="user-avatars",
                            Key=obj["Key"]
                        )
                        deleted_count += 1
                
                elif self._cloudinary:
                    # Delete from Cloudinary
                    search_result = await self._cloudinary.search.expression(
                        f"public_id:{thumb_path}*"
                    ).execute()
                    
                    for resource in search_result.get("resources", []):
                        await self._cloudinary.uploader.destroy(resource["public_id"])
                        deleted_count += 1
                
                else:
                    # Delete from local filesystem
                    thumb_dir = os.path.join(self._local_path, "thumbs", size_name)
                    if os.path.exists(thumb_dir):
                        for filename in os.listdir(thumb_dir):
                            if filename.startswith(f"{user_id_str}_"):
                                os.remove(os.path.join(thumb_dir, filename))
                                deleted_count += 1
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error deleting thumbnails for user {user_id}: {e}")
            return 0

    async def _create_thumbnail(
        self, original_image: Image.Image, user_id: UUID, size_name: str, width: int, height: int
    ) -> dict[str, any]:
        """Create a thumbnail."""
        try:
            # Create thumbnail
            thumbnail = original_image.copy()
            thumbnail.thumbnail((width, height), Image.Resampling.LANCZOS)
            
            # Save thumbnail
            thumbnail_filename = f"{user_id}_{size_name}_thumbnail.png"
            thumbnail_path = await self._store_thumbnail(thumbnail, thumbnail_filename, size_name)
            
            return {
                "size_name": size_name,
                "width": width,
                "height": height,
                "file_path": thumbnail_path,
                "filename": thumbnail_filename,
                "url": f"{self._cdn_base_url}/avatars/thumbs/{size_name}/{thumbnail_filename}",
                "created_at": datetime.now(UTC).isoformat(),
            }
            
        except Exception as e:
            logger.error(f"Error creating thumbnail {size_name} for user {user_id}: {e}")
            return {}

    async def _store_thumbnail(self, thumbnail: Image.Image, filename: str, size_name: str) -> str:
        """Store thumbnail."""
        try:
            # Convert to bytes
            thumbnail_bytes = BytesIO()
            thumbnail.save(thumbnail_bytes, format="PNG")
            thumbnail_bytes.seek(0)
            
            if self._s3_client:
                # Store to S3
                key = f"avatars/thumbs/{size_name}/{filename}"
                await self._s3_client.put_object(
                    Bucket="user-avatars",
                    Key=key,
                    Body=thumbnail_bytes.getvalue(),
                    ContentType="image/png",
                    CacheControl="max-age=31536000",
                )
                return f"s3://user-avatars/{key}"
            
            if self._cloudinary:
                # Store to Cloudinary
                result = await self._cloudinary.uploader.upload(
                    thumbnail_bytes.getvalue(),
                    public_id=f"avatars/thumbs/{size_name}/{filename}",
                    resource_type="image",
                    overwrite=True,
                )
                return result["secure_url"]
            
            # Store locally
            thumb_dir = os.path.join(self._local_path, "thumbs", size_name)
            os.makedirs(thumb_dir, exist_ok=True)

            file_path = os.path.join(thumb_dir, filename)
            with open(file_path, "wb") as f:
                f.write(thumbnail_bytes.getvalue())

            return file_path
                
        except Exception as e:
            logger.error(f"Error storing thumbnail {filename}: {e}")
            raise

    def _get_storage_provider(self) -> str:
        """Get the current storage provider."""
        if self._s3_client:
            return "s3"
        if self._cloudinary:
            return "cloudinary"
        return "local"

    def _get_thumbnail_size_name(self, size: int) -> str:
        """Get thumbnail size name for given pixel size."""
        if size <= 32:
            return "small"
        if size <= 64:
            return "medium"
        if size <= 128:
            return "large"
        return "xlarge"