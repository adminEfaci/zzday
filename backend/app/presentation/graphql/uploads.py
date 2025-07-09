"""
GraphQL File Uploads and Handling

Provides comprehensive file upload capabilities for GraphQL including multipart form data,
file validation, storage management, and progressive upload support.
"""

import asyncio
import hashlib
import logging
import mimetypes
import os
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse

import aiofiles
import aiofiles.os
from PIL import Image
from strawberry import GraphQLError
from strawberry.file_uploads import Upload
from strawberry.types import Info

logger = logging.getLogger(__name__)


class FileStatus(Enum):
    """File upload status."""
    PENDING = "pending"
    UPLOADING = "uploading"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DELETED = "deleted"


class FileType(Enum):
    """Supported file types."""
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    CODE = "code"
    OTHER = "other"


@dataclass
class FileMetadata:
    """File metadata information."""
    id: str
    filename: str
    original_filename: str
    content_type: str
    file_type: FileType
    size: int
    checksum: str
    
    # Upload information
    uploaded_by: Optional[str] = None
    uploaded_at: datetime = field(default_factory=datetime.utcnow)
    
    # Storage information
    storage_path: Optional[str] = None
    public_url: Optional[str] = None
    
    # Processing information
    status: FileStatus = FileStatus.PENDING
    processing_started_at: Optional[datetime] = None
    processing_completed_at: Optional[datetime] = None
    
    # File variants (thumbnails, different sizes, etc.)
    variants: Dict[str, str] = field(default_factory=dict)
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Access control
    is_public: bool = False
    expires_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Initialize file metadata."""
        if not self.id:
            self.id = str(uuid.uuid4())
    
    @property
    def is_expired(self) -> bool:
        """Check if file has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    @property
    def file_extension(self) -> str:
        """Get file extension."""
        return Path(self.filename).suffix.lower()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'content_type': self.content_type,
            'file_type': self.file_type.value,
            'size': self.size,
            'checksum': self.checksum,
            'uploaded_by': self.uploaded_by,
            'uploaded_at': self.uploaded_at.isoformat(),
            'storage_path': self.storage_path,
            'public_url': self.public_url,
            'status': self.status.value,
            'variants': self.variants,
            'metadata': self.metadata,
            'is_public': self.is_public,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }


@dataclass
class UploadProgress:
    """Upload progress tracking."""
    file_id: str
    bytes_uploaded: int
    total_bytes: int
    speed_bytes_per_second: float = 0.0
    eta_seconds: Optional[float] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def progress_percent(self) -> float:
        """Get progress percentage."""
        if self.total_bytes == 0:
            return 0.0
        return (self.bytes_uploaded / self.total_bytes) * 100
    
    @property
    def is_complete(self) -> bool:
        """Check if upload is complete."""
        return self.bytes_uploaded >= self.total_bytes


class FileValidator:
    """File validation utilities."""
    
    # Default file size limits (in bytes)
    DEFAULT_LIMITS = {
        FileType.IMAGE: 10 * 1024 * 1024,  # 10MB
        FileType.VIDEO: 100 * 1024 * 1024,  # 100MB
        FileType.AUDIO: 50 * 1024 * 1024,  # 50MB
        FileType.DOCUMENT: 20 * 1024 * 1024,  # 20MB
        FileType.ARCHIVE: 50 * 1024 * 1024,  # 50MB
        FileType.CODE: 5 * 1024 * 1024,  # 5MB
        FileType.OTHER: 10 * 1024 * 1024,  # 10MB
    }
    
    # Allowed file extensions by type
    ALLOWED_EXTENSIONS = {
        FileType.IMAGE: {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'},
        FileType.VIDEO: {'.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm'},
        FileType.AUDIO: {'.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a'},
        FileType.DOCUMENT: {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf'},
        FileType.ARCHIVE: {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'},
        FileType.CODE: {'.py', '.js', '.html', '.css', '.json', '.xml', '.yaml', '.yml', '.sql'},
    }
    
    def __init__(self, size_limits: Optional[Dict[FileType, int]] = None):
        self.size_limits = size_limits or self.DEFAULT_LIMITS
    
    def validate_file(self, upload: Upload, file_type: FileType) -> None:
        """Validate uploaded file."""
        # Check file size
        max_size = self.size_limits.get(file_type, self.DEFAULT_LIMITS[FileType.OTHER])
        if upload.size > max_size:
            raise GraphQLError(
                f"File size {upload.size} exceeds maximum allowed size {max_size}",
                extensions={'code': 'FILE_TOO_LARGE'}
            )
        
        # Check file extension
        file_ext = Path(upload.filename).suffix.lower()
        allowed_extensions = self.ALLOWED_EXTENSIONS.get(file_type, set())
        
        if allowed_extensions and file_ext not in allowed_extensions:
            raise GraphQLError(
                f"File extension {file_ext} not allowed for {file_type.value} files",
                extensions={'code': 'INVALID_FILE_TYPE'}
            )
        
        # Check content type
        expected_content_type = self._get_expected_content_type(file_type, file_ext)
        if expected_content_type and not upload.content_type.startswith(expected_content_type):
            raise GraphQLError(
                f"Content type {upload.content_type} doesn't match file extension {file_ext}",
                extensions={'code': 'CONTENT_TYPE_MISMATCH'}
            )
    
    def _get_expected_content_type(self, file_type: FileType, file_ext: str) -> Optional[str]:
        """Get expected content type for file type and extension."""
        content_type_map = {
            FileType.IMAGE: 'image/',
            FileType.VIDEO: 'video/',
            FileType.AUDIO: 'audio/',
            FileType.DOCUMENT: None,  # Mixed content types
            FileType.ARCHIVE: 'application/',
            FileType.CODE: 'text/',
        }
        
        return content_type_map.get(file_type)
    
    def detect_file_type(self, filename: str, content_type: str) -> FileType:
        """Detect file type from filename and content type."""
        file_ext = Path(filename).suffix.lower()
        
        # Check by extension first
        for file_type, extensions in self.ALLOWED_EXTENSIONS.items():
            if file_ext in extensions:
                return file_type
        
        # Check by content type
        if content_type.startswith('image/'):
            return FileType.IMAGE
        elif content_type.startswith('video/'):
            return FileType.VIDEO
        elif content_type.startswith('audio/'):
            return FileType.AUDIO
        elif content_type.startswith('text/'):
            return FileType.CODE
        elif content_type.startswith('application/'):
            if any(archive_type in content_type for archive_type in ['zip', 'rar', '7z', 'tar', 'gzip']):
                return FileType.ARCHIVE
            else:
                return FileType.DOCUMENT
        
        return FileType.OTHER


class FileProcessor:
    """File processing utilities."""
    
    def __init__(self, storage_path: str = "/tmp/uploads"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
    
    async def process_file(self, file_metadata: FileMetadata, file_content: bytes) -> FileMetadata:
        """Process uploaded file."""
        file_metadata.status = FileStatus.PROCESSING
        file_metadata.processing_started_at = datetime.utcnow()
        
        try:
            # Generate unique filename
            unique_filename = f"{file_metadata.id}_{file_metadata.filename}"
            file_path = self.storage_path / unique_filename
            
            # Save file
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(file_content)
            
            file_metadata.storage_path = str(file_path)
            
            # Process based on file type
            if file_metadata.file_type == FileType.IMAGE:
                await self._process_image(file_metadata, file_path)
            elif file_metadata.file_type == FileType.VIDEO:
                await self._process_video(file_metadata, file_path)
            elif file_metadata.file_type == FileType.AUDIO:
                await self._process_audio(file_metadata, file_path)
            
            # Generate checksum
            file_metadata.checksum = await self._calculate_checksum(file_path)
            
            # Extract metadata
            file_metadata.metadata = await self._extract_metadata(file_metadata, file_path)
            
            file_metadata.status = FileStatus.COMPLETED
            file_metadata.processing_completed_at = datetime.utcnow()
            
        except Exception as e:
            file_metadata.status = FileStatus.FAILED
            logger.error(f"File processing failed for {file_metadata.id}: {e}")
            raise
        
        return file_metadata
    
    async def _process_image(self, file_metadata: FileMetadata, file_path: Path):
        """Process image file."""
        try:
            # Create thumbnails
            image = Image.open(file_path)
            
            # Generate thumbnail variants
            variants = {
                'thumbnail': (150, 150),
                'small': (300, 300),
                'medium': (600, 600),
                'large': (1200, 1200)
            }
            
            for variant_name, size in variants.items():
                variant_path = file_path.with_suffix(f'.{variant_name}{file_path.suffix}')
                
                # Create thumbnail
                thumbnail = image.copy()
                thumbnail.thumbnail(size, Image.Resampling.LANCZOS)
                thumbnail.save(variant_path, optimize=True, quality=85)
                
                file_metadata.variants[variant_name] = str(variant_path)
            
            # Extract image metadata
            file_metadata.metadata.update({
                'width': image.width,
                'height': image.height,
                'format': image.format,
                'mode': image.mode
            })
            
        except Exception as e:
            logger.error(f"Image processing failed: {e}")
    
    async def _process_video(self, file_metadata: FileMetadata, file_path: Path):
        """Process video file."""
        # Video processing would require ffmpeg
        # For now, just extract basic metadata
        file_metadata.metadata.update({
            'duration': None,  # Would extract with ffprobe
            'resolution': None,
            'bitrate': None,
            'codec': None
        })
    
    async def _process_audio(self, file_metadata: FileMetadata, file_path: Path):
        """Process audio file."""
        # Audio processing would require ffmpeg or mutagen
        file_metadata.metadata.update({
            'duration': None,  # Would extract with ffprobe
            'bitrate': None,
            'sample_rate': None,
            'channels': None
        })
    
    async def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate file checksum."""
        hasher = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    async def _extract_metadata(self, file_metadata: FileMetadata, file_path: Path) -> Dict[str, Any]:
        """Extract additional metadata from file."""
        metadata = {}
        
        # Get file stats
        stat = await aiofiles.os.stat(file_path)
        metadata.update({
            'size_on_disk': stat.st_size,
            'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified_at': datetime.fromtimestamp(stat.st_mtime).isoformat()
        })
        
        return metadata


class FileUploadManager:
    """Manages file uploads and storage."""
    
    def __init__(
        self,
        storage_path: str = "/tmp/uploads",
        max_file_size: int = 100 * 1024 * 1024,  # 100MB
        cleanup_interval: int = 3600  # 1 hour
    ):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        self.max_file_size = max_file_size
        self.cleanup_interval = cleanup_interval
        
        # File tracking
        self.files: Dict[str, FileMetadata] = {}
        self.upload_progress: Dict[str, UploadProgress] = {}
        
        # Processing
        self.validator = FileValidator()
        self.processor = FileProcessor(storage_path)
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self):
        """Start the file upload manager."""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("File upload manager started")
    
    async def stop(self):
        """Stop the file upload manager."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
        logger.info("File upload manager stopped")
    
    async def upload_file(
        self,
        upload: Upload,
        user_id: Optional[str] = None,
        file_type: Optional[FileType] = None,
        is_public: bool = False,
        expires_in: Optional[int] = None
    ) -> FileMetadata:
        """Upload a file."""
        # Detect file type if not provided
        if not file_type:
            file_type = self.validator.detect_file_type(upload.filename, upload.content_type)
        
        # Validate file
        self.validator.validate_file(upload, file_type)
        
        # Create file metadata
        file_metadata = FileMetadata(
            id=str(uuid.uuid4()),
            filename=self._generate_unique_filename(upload.filename),
            original_filename=upload.filename,
            content_type=upload.content_type,
            file_type=file_type,
            size=upload.size,
            checksum="",  # Will be calculated during processing
            uploaded_by=user_id,
            is_public=is_public,
            expires_at=datetime.utcnow() + timedelta(seconds=expires_in) if expires_in else None
        )
        
        # Track upload progress
        progress = UploadProgress(
            file_id=file_metadata.id,
            bytes_uploaded=0,
            total_bytes=upload.size
        )
        self.upload_progress[file_metadata.id] = progress
        
        try:
            # Read file content
            file_content = await upload.read()
            
            # Update progress
            progress.bytes_uploaded = len(file_content)
            progress.updated_at = datetime.utcnow()
            
            # Process file
            file_metadata = await self.processor.process_file(file_metadata, file_content)
            
            # Store metadata
            self.files[file_metadata.id] = file_metadata
            
            logger.info(f"File uploaded successfully: {file_metadata.id}")
            return file_metadata
            
        except Exception as e:
            # Clean up on error
            if file_metadata.id in self.upload_progress:
                del self.upload_progress[file_metadata.id]
            raise
    
    async def get_file(self, file_id: str) -> Optional[FileMetadata]:
        """Get file metadata by ID."""
        return self.files.get(file_id)
    
    async def delete_file(self, file_id: str, user_id: Optional[str] = None) -> bool:
        """Delete a file."""
        file_metadata = self.files.get(file_id)
        if not file_metadata:
            return False
        
        # Check permissions
        if user_id and file_metadata.uploaded_by != user_id:
            raise GraphQLError("Permission denied", extensions={'code': 'PERMISSION_DENIED'})
        
        try:
            # Delete file from storage
            if file_metadata.storage_path:
                storage_path = Path(file_metadata.storage_path)
                if storage_path.exists():
                    await aiofiles.os.remove(storage_path)
                
                # Delete variants
                for variant_path in file_metadata.variants.values():
                    variant_file = Path(variant_path)
                    if variant_file.exists():
                        await aiofiles.os.remove(variant_file)
            
            # Update metadata
            file_metadata.status = FileStatus.DELETED
            
            logger.info(f"File deleted: {file_id}")
            return True
            
        except Exception as e:
            logger.error(f"File deletion failed: {e}")
            return False
    
    async def get_upload_progress(self, file_id: str) -> Optional[UploadProgress]:
        """Get upload progress for a file."""
        return self.upload_progress.get(file_id)
    
    async def cleanup_expired_files(self):
        """Clean up expired files."""
        now = datetime.utcnow()
        expired_files = [
            file_id for file_id, metadata in self.files.items()
            if metadata.is_expired
        ]
        
        for file_id in expired_files:
            await self.delete_file(file_id)
            del self.files[file_id]
        
        logger.info(f"Cleaned up {len(expired_files)} expired files")
    
    def _generate_unique_filename(self, original_filename: str) -> str:
        """Generate unique filename."""
        name = Path(original_filename).stem
        extension = Path(original_filename).suffix
        unique_id = str(uuid.uuid4())[:8]
        return f"{name}_{unique_id}{extension}"
    
    async def _cleanup_loop(self):
        """Background task for cleaning up expired files."""
        while self._running:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup_expired_files()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get file upload statistics."""
        total_files = len(self.files)
        total_size = sum(f.size for f in self.files.values())
        
        status_counts = {}
        for status in FileStatus:
            status_counts[status.value] = sum(
                1 for f in self.files.values() if f.status == status
            )
        
        type_counts = {}
        for file_type in FileType:
            type_counts[file_type.value] = sum(
                1 for f in self.files.values() if f.file_type == file_type
            )
        
        return {
            'total_files': total_files,
            'total_size_bytes': total_size,
            'active_uploads': len(self.upload_progress),
            'status_breakdown': status_counts,
            'type_breakdown': type_counts,
            'storage_path': str(self.storage_path)
        }


# Global file upload manager instance
file_upload_manager = FileUploadManager()


def create_file_upload_manager(
    storage_path: str = "/tmp/uploads",
    max_file_size: int = 100 * 1024 * 1024,
    cleanup_interval: int = 3600
) -> FileUploadManager:
    """Create and configure a file upload manager."""
    return FileUploadManager(
        storage_path=storage_path,
        max_file_size=max_file_size,
        cleanup_interval=cleanup_interval
    )


__all__ = [
    'FileUploadManager',
    'FileMetadata',
    'FileValidator',
    'FileProcessor',
    'UploadProgress',
    'FileStatus',
    'FileType',
    'file_upload_manager',
    'create_file_upload_manager',
]