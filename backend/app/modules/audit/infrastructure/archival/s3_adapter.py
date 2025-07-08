"""S3 adapter for audit data archival.

This module provides integration with AWS S3 or compatible object storage
for long-term archival of audit data.
"""

from datetime import datetime, timedelta
from typing import Any

import aioboto3
from botocore.exceptions import ClientError

from app.core.errors import InfrastructureError
from app.core.logging import get_logger

logger = get_logger(__name__)


class S3Adapter:
    """
    S3 adapter for audit archival operations.

    Provides reliable storage and retrieval of audit archives in S3
    with support for lifecycle policies and efficient access patterns.
    """

    def __init__(
        self,
        bucket_name: str,
        region_name: str = "us-east-1",
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        endpoint_url: str | None = None,  # For S3-compatible services
        prefix: str = "audit-archives/",
    ):
        """
        Initialize S3 adapter.

        Args:
            bucket_name: S3 bucket name
            region_name: AWS region
            access_key_id: AWS access key ID
            secret_access_key: AWS secret access key
            endpoint_url: Custom endpoint URL for S3-compatible services
            prefix: Prefix for all archive objects
        """
        self.bucket_name = bucket_name
        self.region_name = region_name
        self.prefix = prefix.rstrip("/") + "/"

        # Session configuration
        self._session_config = {"region_name": region_name}

        if access_key_id and secret_access_key:
            self._session_config.update(
                {
                    "aws_access_key_id": access_key_id,
                    "aws_secret_access_key": secret_access_key,
                }
            )

        if endpoint_url:
            self._session_config["endpoint_url"] = endpoint_url

        self._session = None
        self._client = None

    async def initialize(self) -> None:
        """Initialize S3 connection and verify bucket access."""
        try:
            self._session = aioboto3.Session()

            async with self._session.client("s3", **self._session_config) as s3:
                # Verify bucket exists and we have access
                await s3.head_bucket(Bucket=self.bucket_name)

                # Set up lifecycle policy for automatic archival tiers
                await self._setup_lifecycle_policy(s3)

            logger.info(
                "S3 adapter initialized",
                bucket=self.bucket_name,
                region=self.region_name,
            )

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "404":
                raise InfrastructureError(f"S3 bucket '{self.bucket_name}' not found")
            if error_code == "403":
                raise InfrastructureError(
                    f"Access denied to S3 bucket '{self.bucket_name}'"
                )
            raise InfrastructureError(f"S3 initialization failed: {e!s}")
        except Exception as e:
            raise InfrastructureError(f"S3 initialization failed: {e!s}")

    async def upload_archive(
        self,
        archive_id: str,
        data: bytes,
        metadata: dict[str, Any],
        storage_class: str = "STANDARD_IA",
    ) -> str:
        """
        Upload archive data to S3.

        Args:
            archive_id: Unique archive identifier
            data: Archive data (compressed)
            metadata: Archive metadata
            storage_class: S3 storage class

        Returns:
            S3 object key
        """
        # Generate object key
        date_prefix = datetime.utcnow().strftime("%Y/%m/%d")
        object_key = f"{self.prefix}{date_prefix}/{archive_id}.gz"

        try:
            async with self._session.client("s3", **self._session_config) as s3:
                # Prepare metadata
                s3_metadata = {
                    "archive-id": archive_id,
                    "created-at": datetime.utcnow().isoformat(),
                    "original-size": str(metadata.get("original_size", 0)),
                    "compressed-size": str(len(data)),
                    "entry-count": str(metadata.get("entry_count", 0)),
                    "time-range-start": metadata.get("time_range_start", ""),
                    "time-range-end": metadata.get("time_range_end", ""),
                }

                # Upload with server-side encryption
                await s3.put_object(
                    Bucket=self.bucket_name,
                    Key=object_key,
                    Body=data,
                    StorageClass=storage_class,
                    ServerSideEncryption="AES256",
                    Metadata=s3_metadata,
                    ContentType="application/gzip",
                    ContentEncoding="gzip",
                )

                # Add tags for better organization
                tags = {
                    "Type": "audit-archive",
                    "Year": datetime.utcnow().strftime("%Y"),
                    "Month": datetime.utcnow().strftime("%m"),
                }

                await s3.put_object_tagging(
                    Bucket=self.bucket_name,
                    Key=object_key,
                    Tagging={
                        "TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]
                    },
                )

                logger.info(
                    "Archive uploaded to S3",
                    archive_id=archive_id,
                    object_key=object_key,
                    size_bytes=len(data),
                    storage_class=storage_class,
                )

                return object_key

        except ClientError as e:
            logger.exception(
                "Failed to upload archive to S3", archive_id=archive_id, error=str(e)
            )
            raise InfrastructureError(f"S3 upload failed: {e!s}")

    async def download_archive(self, object_key: str) -> bytes:
        """
        Download archive data from S3.

        Args:
            object_key: S3 object key

        Returns:
            Archive data (compressed)
        """
        try:
            async with self._session.client("s3", **self._session_config) as s3:
                response = await s3.get_object(Bucket=self.bucket_name, Key=object_key)

                # Read data
                data = await response["Body"].read()

                logger.info(
                    "Archive downloaded from S3",
                    object_key=object_key,
                    size_bytes=len(data),
                )

                return data

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                raise InfrastructureError(f"Archive not found: {object_key}")
            logger.exception(
                "Failed to download archive from S3",
                object_key=object_key,
                error=str(e),
            )
            raise InfrastructureError(f"S3 download failed: {e!s}")

    async def get_archive_metadata(self, object_key: str) -> dict[str, Any]:
        """
        Get archive metadata without downloading the full archive.

        Args:
            object_key: S3 object key

        Returns:
            Archive metadata
        """
        try:
            async with self._session.client("s3", **self._session_config) as s3:
                response = await s3.head_object(Bucket=self.bucket_name, Key=object_key)

                metadata = {
                    "size_bytes": response["ContentLength"],
                    "last_modified": response["LastModified"],
                    "storage_class": response.get("StorageClass", "STANDARD"),
                    "server_side_encryption": response.get("ServerSideEncryption"),
                    "custom_metadata": response.get("Metadata", {}),
                }

                # Get tags
                try:
                    tag_response = await s3.get_object_tagging(
                        Bucket=self.bucket_name, Key=object_key
                    )
                    metadata["tags"] = {
                        tag["Key"]: tag["Value"] for tag in tag_response["TagSet"]
                    }
                except:
                    metadata["tags"] = {}

                return metadata

        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFound":
                raise InfrastructureError(f"Archive not found: {object_key}")
            raise InfrastructureError(f"Failed to get archive metadata: {e!s}")

    async def list_archives(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        max_results: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        List archives within date range.

        Args:
            start_date: Start of date range
            end_date: End of date range
            max_results: Maximum results to return

        Returns:
            List of archive metadata
        """
        archives = []

        try:
            async with self._session.client("s3", **self._session_config) as s3:
                # Build prefix for date filtering
                if start_date and end_date:
                    # For simplicity, list all and filter
                    # In production, could optimize with date-based prefixes
                    prefix = self.prefix
                else:
                    prefix = self.prefix

                # List objects
                paginator = s3.get_paginator("list_objects_v2")

                async for page in paginator.paginate(
                    Bucket=self.bucket_name, Prefix=prefix, MaxKeys=max_results
                ):
                    if "Contents" not in page:
                        continue

                    for obj in page["Contents"]:
                        # Filter by date if specified
                        if start_date and obj["LastModified"] < start_date:
                            continue
                        if end_date and obj["LastModified"] > end_date:
                            continue

                        archives.append(
                            {
                                "key": obj["Key"],
                                "size_bytes": obj["Size"],
                                "last_modified": obj["LastModified"],
                                "storage_class": obj.get("StorageClass", "STANDARD"),
                            }
                        )

                        if len(archives) >= max_results:
                            break

                    if len(archives) >= max_results:
                        break

                logger.info(
                    "Listed archives from S3",
                    count=len(archives),
                    start_date=start_date,
                    end_date=end_date,
                )

                return archives

        except ClientError as e:
            logger.exception("Failed to list archives from S3", error=str(e))
            raise InfrastructureError(f"S3 list failed: {e!s}")

    async def delete_archive(self, object_key: str) -> bool:
        """
        Delete an archive from S3.

        Args:
            object_key: S3 object key

        Returns:
            True if deleted, False if not found
        """
        try:
            async with self._session.client("s3", **self._session_config) as s3:
                await s3.delete_object(Bucket=self.bucket_name, Key=object_key)

                logger.info("Archive deleted from S3", object_key=object_key)

                return True

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                return False
            logger.exception(
                "Failed to delete archive from S3", object_key=object_key, error=str(e)
            )
            raise InfrastructureError(f"S3 delete failed: {e!s}")

    async def cleanup_old_archives(
        self, retention_days: int, dry_run: bool = False
    ) -> int:
        """
        Clean up archives older than retention period.

        Args:
            retention_days: Keep archives for this many days
            dry_run: If True, only list what would be deleted

        Returns:
            Number of archives deleted/would be deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        deleted_count = 0

        try:
            # List old archives
            archives = await self.list_archives(end_date=cutoff_date, max_results=10000)

            if dry_run:
                logger.info(
                    "Dry run: would delete old archives",
                    count=len(archives),
                    cutoff_date=cutoff_date,
                )
                return len(archives)

            # Delete archives
            async with self._session.client("s3", **self._session_config) as s3:
                for archive in archives:
                    try:
                        await s3.delete_object(
                            Bucket=self.bucket_name, Key=archive["key"]
                        )
                        deleted_count += 1
                    except Exception as e:
                        logger.warning(
                            "Failed to delete archive", key=archive["key"], error=str(e)
                        )

            logger.info(
                "Cleaned up old archives",
                deleted_count=deleted_count,
                retention_days=retention_days,
            )

            return deleted_count

        except Exception as e:
            logger.exception("Archive cleanup failed", error=str(e))
            raise InfrastructureError(f"Archive cleanup failed: {e!s}")

    async def get_storage_statistics(self) -> dict[str, Any]:
        """Get storage usage statistics."""
        try:
            stats = {
                "total_objects": 0,
                "total_size_bytes": 0,
                "storage_class_distribution": {},
                "size_by_month": {},
            }

            async with self._session.client("s3", **self._session_config) as s3:
                paginator = s3.get_paginator("list_objects_v2")

                async for page in paginator.paginate(
                    Bucket=self.bucket_name, Prefix=self.prefix
                ):
                    if "Contents" not in page:
                        continue

                    for obj in page["Contents"]:
                        stats["total_objects"] += 1
                        stats["total_size_bytes"] += obj["Size"]

                        # Storage class distribution
                        storage_class = obj.get("StorageClass", "STANDARD")
                        stats["storage_class_distribution"][storage_class] = (
                            stats["storage_class_distribution"].get(storage_class, 0)
                            + 1
                        )

                        # Size by month
                        month_key = obj["LastModified"].strftime("%Y-%m")
                        stats["size_by_month"][month_key] = (
                            stats["size_by_month"].get(month_key, 0) + obj["Size"]
                        )

            # Convert to human-readable sizes
            stats["total_size_gb"] = stats["total_size_bytes"] / (1024**3)
            stats["average_size_mb"] = (
                stats["total_size_bytes"] / stats["total_objects"] / (1024**2)
                if stats["total_objects"] > 0
                else 0
            )

            return stats

        except Exception as e:
            logger.exception("Failed to get storage statistics", error=str(e))
            raise InfrastructureError(f"Failed to get statistics: {e!s}")

    async def _setup_lifecycle_policy(self, s3_client) -> None:
        """Set up S3 lifecycle policy for automatic archival transitions."""
        lifecycle_policy = {
            "Rules": [
                {
                    "ID": "AuditArchiveLifecycle",
                    "Status": "Enabled",
                    "Filter": {"Prefix": self.prefix},
                    "Transitions": [
                        {
                            # Move to Infrequent Access after 30 days
                            "Days": 30,
                            "StorageClass": "STANDARD_IA",
                        },
                        {
                            # Move to Glacier after 90 days
                            "Days": 90,
                            "StorageClass": "GLACIER",
                        },
                        {
                            # Move to Deep Archive after 180 days
                            "Days": 180,
                            "StorageClass": "DEEP_ARCHIVE",
                        },
                    ],
                }
            ]
        }

        try:
            await s3_client.put_bucket_lifecycle_configuration(
                Bucket=self.bucket_name, LifecycleConfiguration=lifecycle_policy
            )

            logger.info("S3 lifecycle policy configured", bucket=self.bucket_name)
        except ClientError as e:
            # Ignore if already exists or no permission
            if e.response["Error"]["Code"] not in [
                "NoSuchLifecycleConfiguration",
                "AccessDenied",
            ]:
                logger.warning("Failed to set lifecycle policy", error=str(e))


__all__ = ["S3Adapter"]
