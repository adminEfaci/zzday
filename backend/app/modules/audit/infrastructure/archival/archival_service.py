"""Archival service for audit data management.

This module provides high-level archival operations combining compression
and storage for efficient long-term audit data retention.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.core.errors import InfrastructureError
from app.core.logging import get_logger
from app.modules.audit.domain.aggregates.audit_log import AuditLog
from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.domain.enums.audit_enums import AuditStatus, RetentionPolicy
from app.modules.audit.infrastructure.archival.compression_service import (
    CompressionService,
)
from app.modules.audit.infrastructure.archival.s3_adapter import S3Adapter

logger = get_logger(__name__)


class ArchivalService:
    """
    Service for managing audit data archival.

    Orchestrates the archival process including compression, storage,
    and retrieval of audit data with retention policy enforcement.
    """

    def __init__(
        self,
        s3_adapter: S3Adapter,
        compression_service: CompressionService,
        batch_size: int = 10000,
        parallel_workers: int = 4,
    ):
        """
        Initialize archival service.

        Args:
            s3_adapter: S3 storage adapter
            compression_service: Compression service
            batch_size: Number of entries to process per batch
            parallel_workers: Number of parallel archive workers
        """
        self.s3_adapter = s3_adapter
        self.compression_service = compression_service
        self.batch_size = batch_size
        self.parallel_workers = parallel_workers
        self._archive_queue = asyncio.Queue()
        self._workers = []

    async def initialize(self) -> None:
        """Initialize the archival service."""
        try:
            # Initialize S3 adapter
            await self.s3_adapter.initialize()

            # Start archive workers
            for i in range(self.parallel_workers):
                worker = asyncio.create_task(self._archive_worker(i))
                self._workers.append(worker)

            logger.info("Archival service initialized", workers=self.parallel_workers)

        except Exception as e:
            logger.exception("Failed to initialize archival service", error=str(e))
            raise InfrastructureError(f"Archival initialization failed: {e!s}")

    async def shutdown(self) -> None:
        """Shutdown the archival service."""
        try:
            # Cancel workers
            for worker in self._workers:
                worker.cancel()

            # Wait for workers to finish
            await asyncio.gather(*self._workers, return_exceptions=True)

            # Shutdown compression service
            self.compression_service.shutdown()

            logger.info("Archival service shut down")

        except Exception as e:
            logger.exception("Error during archival service shutdown", error=str(e))

    async def archive_audit_log(
        self, audit_log: AuditLog, entries: list[AuditEntry], priority: str = "balanced"
    ) -> str:
        """
        Archive an audit log with its entries.

        Args:
            audit_log: Audit log to archive
            entries: List of entries in the log
            priority: Compression priority ('speed', 'ratio', 'balanced')

        Returns:
            Archive location (S3 key)
        """
        if audit_log.status != AuditStatus.PENDING_ARCHIVE:
            raise ValueError(
                f"Audit log must be in PENDING_ARCHIVE status, got {audit_log.status}"
            )

        archive_id = (
            f"audit-log-{audit_log.id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        )

        try:
            # Prepare metadata
            metadata = {
                "audit_log_id": str(audit_log.id),
                "title": audit_log.title,
                "retention_policy": str(audit_log.retention_policy),
                "entry_count": len(entries),
                "original_size": sum(len(json.dumps(e.to_dict())) for e in entries),
                "time_range_start": min(e.created_at for e in entries).isoformat()
                if entries
                else None,
                "time_range_end": max(e.created_at for e in entries).isoformat()
                if entries
                else None,
                "archived_at": datetime.utcnow().isoformat(),
            }

            # Select compression algorithm
            algorithm = self.compression_service.select_algorithm(
                metadata["original_size"], priority
            )

            # Compress entries
            compressed_data = await self.compression_service.compress_entries(
                entries, algorithm=algorithm, metadata=metadata
            )

            # Upload to S3
            storage_class = self._determine_storage_class(audit_log.retention_policy)
            s3_key = await self.s3_adapter.upload_archive(
                archive_id, compressed_data, metadata, storage_class=storage_class
            )

            logger.info(
                "Audit log archived",
                audit_log_id=str(audit_log.id),
                entry_count=len(entries),
                compressed_size=len(compressed_data),
                s3_key=s3_key,
            )

            return s3_key

        except Exception as e:
            logger.exception(
                "Failed to archive audit log",
                audit_log_id=str(audit_log.id),
                error=str(e),
            )
            raise InfrastructureError(f"Archive failed: {e!s}")

    async def archive_entries_batch(
        self,
        entries: list[AuditEntry],
        archive_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Archive a batch of entries directly.

        Args:
            entries: List of entries to archive
            archive_name: Name for the archive
            metadata: Additional metadata

        Returns:
            Archive location (S3 key)
        """
        archive_id = f"{archive_name}-{uuid4()}"

        try:
            # Prepare metadata
            archive_metadata = {
                "archive_name": archive_name,
                "entry_count": len(entries),
                "time_range_start": min(e.created_at for e in entries).isoformat()
                if entries
                else None,
                "time_range_end": max(e.created_at for e in entries).isoformat()
                if entries
                else None,
                "archived_at": datetime.utcnow().isoformat(),
            }

            if metadata:
                archive_metadata.update(metadata)

            # Compress entries
            compressed_data = await self.compression_service.compress_entries(
                entries, metadata=archive_metadata
            )

            # Upload to S3
            s3_key = await self.s3_adapter.upload_archive(
                archive_id, compressed_data, archive_metadata
            )

            logger.info(
                "Entry batch archived",
                archive_name=archive_name,
                entry_count=len(entries),
                s3_key=s3_key,
            )

            return s3_key

        except Exception as e:
            logger.exception(
                "Failed to archive entry batch", archive_name=archive_name, error=str(e)
            )
            raise InfrastructureError(f"Batch archive failed: {e!s}")

    async def retrieve_archive(self, archive_location: str) -> list[dict[str, Any]]:
        """
        Retrieve and decompress an archive.

        Args:
            archive_location: S3 key of the archive

        Returns:
            List of entry dictionaries
        """
        try:
            # Download from S3
            compressed_data = await self.s3_adapter.download_archive(archive_location)

            # Decompress
            entries = await self.compression_service.decompress_entries(compressed_data)

            logger.info(
                "Archive retrieved",
                archive_location=archive_location,
                entry_count=len(entries),
            )

            return entries

        except Exception as e:
            logger.exception(
                "Failed to retrieve archive",
                archive_location=archive_location,
                error=str(e),
            )
            raise InfrastructureError(f"Archive retrieval failed: {e!s}")

    async def search_archives(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        audit_log_id: UUID | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search for archives matching criteria.

        Args:
            start_date: Start of date range
            end_date: End of date range
            audit_log_id: Specific audit log ID

        Returns:
            List of archive metadata
        """
        try:
            # List archives from S3
            archives = await self.s3_adapter.list_archives(
                start_date=start_date, end_date=end_date
            )

            results = []

            # Filter by audit log ID if specified
            for archive in archives:
                # Get metadata
                metadata = await self.s3_adapter.get_archive_metadata(archive["key"])

                if audit_log_id:
                    archive_log_id = metadata.get("custom_metadata", {}).get(
                        "audit-log-id"
                    )
                    if archive_log_id != str(audit_log_id):
                        continue

                results.append(
                    {
                        "key": archive["key"],
                        "size_bytes": archive["size_bytes"],
                        "last_modified": archive["last_modified"],
                        "storage_class": archive["storage_class"],
                        "metadata": metadata.get("custom_metadata", {}),
                    }
                )

            logger.info(
                "Archive search completed",
                results=len(results),
                start_date=start_date,
                end_date=end_date,
            )

            return results

        except Exception as e:
            logger.exception("Archive search failed", error=str(e))
            raise InfrastructureError(f"Archive search failed: {e!s}")

    async def enforce_retention_policies(self, dry_run: bool = False) -> dict[str, Any]:
        """
        Enforce retention policies on archived data.

        Args:
            dry_run: If True, only report what would be deleted

        Returns:
            Enforcement statistics
        """
        stats = {
            "archives_checked": 0,
            "archives_deleted": 0,
            "space_freed_bytes": 0,
            "errors": [],
        }

        try:
            # Get all archives
            archives = await self.s3_adapter.list_archives()
            stats["archives_checked"] = len(archives)

            for archive in archives:
                try:
                    # Get metadata
                    metadata = await self.s3_adapter.get_archive_metadata(
                        archive["key"]
                    )
                    custom_metadata = metadata.get("custom_metadata", {})

                    # Check retention policy
                    retention_policy_str = custom_metadata.get("retention-policy")
                    if not retention_policy_str:
                        continue

                    # Parse retention policy
                    try:
                        retention_policy = RetentionPolicy[retention_policy_str]
                    except KeyError:
                        continue

                    if retention_policy.is_permanent():
                        continue

                    # Check if expired
                    archived_at_str = custom_metadata.get("created-at")
                    if not archived_at_str:
                        continue

                    archived_at = datetime.fromisoformat(
                        archived_at_str.replace("Z", "+00:00")
                    )
                    retention_days = retention_policy.get_retention_days()
                    expiry_date = archived_at + timedelta(days=retention_days)

                    if datetime.utcnow() > expiry_date:
                        if not dry_run:
                            # Delete archive
                            await self.s3_adapter.delete_archive(archive["key"])
                            stats["archives_deleted"] += 1
                            stats["space_freed_bytes"] += archive["size_bytes"]
                        else:
                            # Would delete
                            stats["archives_deleted"] += 1
                            stats["space_freed_bytes"] += archive["size_bytes"]

                        logger.info(
                            f"{'Would delete' if dry_run else 'Deleted'} expired archive",
                            key=archive["key"],
                            retention_policy=retention_policy_str,
                            expired_days=(datetime.utcnow() - expiry_date).days,
                        )

                except Exception as e:
                    stats["errors"].append({"archive": archive["key"], "error": str(e)})
                    logger.warning(
                        "Failed to process archive for retention",
                        key=archive["key"],
                        error=str(e),
                    )

            stats["space_freed_gb"] = stats["space_freed_bytes"] / (1024**3)

            logger.info(
                "Retention policy enforcement completed", stats=stats, dry_run=dry_run
            )

            return stats

        except Exception as e:
            logger.exception("Retention policy enforcement failed", error=str(e))
            raise InfrastructureError(f"Retention enforcement failed: {e!s}")

    async def get_archival_statistics(self) -> dict[str, Any]:
        """Get comprehensive archival statistics."""
        try:
            # Get S3 storage statistics
            storage_stats = await self.s3_adapter.get_storage_statistics()

            # Get compression benchmarks on sample data
            sample_data = b"x" * 10000  # 10KB sample
            compression_benchmarks = (
                await self.compression_service.benchmark_algorithms(sample_data)
            )

            # Calculate archive age distribution
            archives = await self.s3_adapter.list_archives(max_results=1000)
            age_distribution = {
                "0-30_days": 0,
                "31-90_days": 0,
                "91-180_days": 0,
                "181-365_days": 0,
                "over_1_year": 0,
            }

            now = datetime.utcnow()
            for archive in archives:
                age_days = (now - archive["last_modified"]).days

                if age_days <= 30:
                    age_distribution["0-30_days"] += 1
                elif age_days <= 90:
                    age_distribution["31-90_days"] += 1
                elif age_days <= 180:
                    age_distribution["91-180_days"] += 1
                elif age_days <= 365:
                    age_distribution["181-365_days"] += 1
                else:
                    age_distribution["over_1_year"] += 1

            return {
                "storage": storage_stats,
                "compression_benchmarks": compression_benchmarks,
                "age_distribution": age_distribution,
                "queue_size": self._archive_queue.qsize(),
            }

        except Exception as e:
            logger.exception("Failed to get archival statistics", error=str(e))
            raise InfrastructureError(f"Failed to get statistics: {e!s}")

    def _determine_storage_class(self, retention_policy: RetentionPolicy) -> str:
        """Determine S3 storage class based on retention policy."""
        if retention_policy in (
            RetentionPolicy.SEVEN_DAYS,
            RetentionPolicy.THIRTY_DAYS,
        ):
            return "STANDARD"
        if retention_policy in (RetentionPolicy.NINETY_DAYS, RetentionPolicy.ONE_YEAR):
            return "STANDARD_IA"
        if retention_policy == RetentionPolicy.THREE_YEARS:
            return "GLACIER"
        if retention_policy == RetentionPolicy.SEVEN_YEARS:
            return "DEEP_ARCHIVE"
        # PERMANENT
        return "DEEP_ARCHIVE"

    async def _archive_worker(self, worker_id: int) -> None:
        """Background worker for processing archive queue."""
        logger.info(f"Archive worker {worker_id} started")

        try:
            while True:
                # Get task from queue
                task = await self._archive_queue.get()

                try:
                    # Process archive task
                    await self._process_archive_task(task)
                except Exception as e:
                    logger.exception(
                        f"Archive worker {worker_id} task failed", error=str(e)
                    )
                finally:
                    self._archive_queue.task_done()

        except asyncio.CancelledError:
            logger.info(f"Archive worker {worker_id} stopped")
            raise

    async def _process_archive_task(self, task: dict[str, Any]) -> None:
        """Process a single archive task."""
        # Implementation depends on task structure
        # This would handle the actual archival work


__all__ = ["ArchivalService"]
