"""Archival service.

This module provides audit data archival and retention management,
supporting compliance requirements and storage optimization.
"""

import json
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.errors import DomainError, ValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)


class ArchivalService:
    """
    Application service for audit data archival.

    Provides comprehensive archival capabilities including
    automated retention management, compression, and compliance.
    """

    def __init__(
        self,
        audit_repository: Any,
        storage_service: Any,
        compression_service: Any,
        retention_policy_service: Any,
    ):
        """
        Initialize archival service.

        Args:
            audit_repository: Repository for audit data
            storage_service: Service for long-term storage
            compression_service: Service for data compression
            retention_policy_service: Service for retention policies
        """
        self.audit_repository = audit_repository
        self.storage_service = storage_service
        self.compression_service = compression_service
        self.retention_policy_service = retention_policy_service

    async def archive_expired_logs(
        self, dry_run: bool = False, batch_size: int = 100
    ) -> dict[str, Any]:
        """
        Archive all expired audit logs based on retention policies.

        Args:
            dry_run: Whether to perform a dry run without actual archival
            batch_size: Number of logs to process in each batch

        Returns:
            Archival operation summary
        """
        logger.info("Starting automated archival process", dry_run=dry_run)

        # Find logs eligible for archival
        expired_logs = await self.audit_repository.find_expired_logs()

        archival_summary = {
            "started_at": datetime.utcnow().isoformat(),
            "dry_run": dry_run,
            "total_logs_found": len(expired_logs),
            "processed_logs": 0,
            "successfully_archived": 0,
            "failed_archives": 0,
            "errors": [],
            "archived_log_ids": [],
            "storage_saved_bytes": 0,
        }

        # Process logs in batches
        for i in range(0, len(expired_logs), batch_size):
            batch = expired_logs[i : i + batch_size]

            for audit_log in batch:
                try:
                    archival_summary["processed_logs"] += 1

                    if dry_run:
                        # Simulate archival
                        logger.debug("DRY RUN: Would archive log", log_id=audit_log.id)
                        archival_summary["successfully_archived"] += 1
                        archival_summary["archived_log_ids"].append(str(audit_log.id))
                    else:
                        # Perform actual archival
                        archive_result = await self._archive_single_log(audit_log)

                        if archive_result["success"]:
                            archival_summary["successfully_archived"] += 1
                            archival_summary["archived_log_ids"].append(
                                str(audit_log.id)
                            )
                            archival_summary[
                                "storage_saved_bytes"
                            ] += archive_result.get("size_bytes", 0)
                        else:
                            archival_summary["failed_archives"] += 1
                            archival_summary["errors"].append(
                                {
                                    "log_id": str(audit_log.id),
                                    "error": archive_result.get("error"),
                                }
                            )

                except Exception as e:
                    archival_summary["failed_archives"] += 1
                    archival_summary["errors"].append(
                        {"log_id": str(audit_log.id), "error": str(e)}
                    )
                    logger.exception(
                        "Failed to archive log", log_id=audit_log.id, error=str(e)
                    )

        archival_summary["completed_at"] = datetime.utcnow().isoformat()

        logger.info(
            "Automated archival process completed",
            processed=archival_summary["processed_logs"],
            successful=archival_summary["successfully_archived"],
            failed=archival_summary["failed_archives"],
        )

        return archival_summary

    async def archive_log_by_id(
        self,
        log_id: UUID,
        archive_location: str | None = None,
        compress: bool = True,
        validate_integrity: bool = True,
    ) -> dict[str, Any]:
        """
        Archive a specific audit log by ID.

        Args:
            log_id: ID of the log to archive
            archive_location: Specific archive location
            compress: Whether to compress the archive
            validate_integrity: Whether to validate data integrity

        Returns:
            Archive operation result
        """
        logger.info("Archiving specific log", log_id=log_id)

        # Retrieve audit log
        audit_log = await self.audit_repository.find_by_id(log_id)
        if not audit_log:
            raise ValidationError(f"Audit log not found: {log_id}")

        # Check if log can be archived
        if not audit_log.is_expired() and audit_log.status.is_active():
            logger.warning("Archiving active non-expired log", log_id=log_id)

        # Perform archival
        return await self._archive_single_log(
            audit_log, archive_location, compress, validate_integrity
        )

    async def restore_archived_log(
        self, log_id: UUID, restore_location: str | None = None
    ) -> dict[str, Any]:
        """
        Restore an archived audit log.

        Args:
            log_id: ID of the log to restore
            restore_location: Optional specific restore location

        Returns:
            Restore operation result
        """
        logger.info("Restoring archived log", log_id=log_id)

        # Find archived log metadata
        archived_log = await self.audit_repository.find_archived_log_metadata(log_id)
        if not archived_log:
            raise ValidationError(f"Archived log not found: {log_id}")

        # Retrieve archive data
        archive_data = await self.storage_service.retrieve_archive(
            archived_log.archive_location
        )

        # Decompress if necessary
        if archive_data.get("compressed", False):
            decompressed_data = await self.compression_service.decompress(
                archive_data["content"]
            )
        else:
            decompressed_data = archive_data["content"]

        # Validate restored data
        validation_result = await self._validate_restored_data(
            decompressed_data, archived_log
        )

        if not validation_result["valid"]:
            raise DomainError(
                f"Restored data validation failed: {validation_result['errors']}"
            )

        # Restore to database if requested
        if restore_location == "database":
            await self._restore_to_database(decompressed_data, log_id)

        restore_result = {
            "log_id": str(log_id),
            "restored_at": datetime.utcnow().isoformat(),
            "archive_location": archived_log.archive_location,
            "data_size_bytes": len(decompressed_data),
            "validation_passed": validation_result["valid"],
            "restored_to_database": restore_location == "database",
        }

        logger.info("Log restoration completed", log_id=log_id)

        return restore_result

    async def get_archival_statistics(
        self, start_date: datetime | None = None, end_date: datetime | None = None
    ) -> dict[str, Any]:
        """
        Get archival statistics and metrics.

        Args:
            start_date: Start of statistics period
            end_date: End of statistics period

        Returns:
            Archival statistics
        """
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()

        # Get archived logs in period
        archived_logs = await self.audit_repository.find_archived_logs_in_period(
            start_date, end_date
        )

        # Calculate statistics
        total_archived = len(archived_logs)
        total_entries_archived = sum(log.entry_count for log in archived_logs)
        total_storage_bytes = sum(log.archive_size_bytes or 0 for log in archived_logs)

        # Group by retention policy
        by_retention_policy = {}
        for log in archived_logs:
            policy = str(log.retention_policy)
            if policy not in by_retention_policy:
                by_retention_policy[policy] = {
                    "count": 0,
                    "entries": 0,
                    "storage_bytes": 0,
                }

            by_retention_policy[policy]["count"] += 1
            by_retention_policy[policy]["entries"] += log.entry_count
            by_retention_policy[policy]["storage_bytes"] += log.archive_size_bytes or 0

        # Get pending archival
        pending_logs = await self.audit_repository.find_logs_pending_archival()

        # Calculate compression ratios
        compression_stats = await self._calculate_compression_statistics(archived_logs)

        return {
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "archived_logs": {
                "total_logs": total_archived,
                "total_entries": total_entries_archived,
                "total_storage_bytes": total_storage_bytes,
                "average_entries_per_log": total_entries_archived
                / max(1, total_archived),
                "by_retention_policy": by_retention_policy,
            },
            "pending_archival": {
                "logs_pending": len(pending_logs),
                "entries_pending": sum(log.entry_count for log in pending_logs),
            },
            "compression_statistics": compression_stats,
            "storage_efficiency": {
                "compression_ratio": compression_stats.get(
                    "average_compression_ratio", 1.0
                ),
                "space_saved_bytes": compression_stats.get("total_space_saved", 0),
                "space_saved_percentage": compression_stats.get(
                    "space_saved_percentage", 0.0
                ),
            },
        }

    async def cleanup_expired_archives(self, dry_run: bool = False) -> dict[str, Any]:
        """
        Clean up archives that have exceeded their retention period.

        Args:
            dry_run: Whether to perform a dry run

        Returns:
            Cleanup operation summary
        """
        logger.info("Starting archive cleanup process", dry_run=dry_run)

        # Find archives eligible for deletion
        expired_archives = await self.audit_repository.find_expired_archives()

        cleanup_summary = {
            "started_at": datetime.utcnow().isoformat(),
            "dry_run": dry_run,
            "total_archives_found": len(expired_archives),
            "successfully_deleted": 0,
            "failed_deletions": 0,
            "errors": [],
            "deleted_archive_ids": [],
            "storage_freed_bytes": 0,
        }

        for archive in expired_archives:
            try:
                if dry_run:
                    logger.debug("DRY RUN: Would delete archive", archive_id=archive.id)
                    cleanup_summary["successfully_deleted"] += 1
                    cleanup_summary["deleted_archive_ids"].append(str(archive.id))
                else:
                    # Delete from storage
                    await self.storage_service.delete_archive(archive.archive_location)

                    # Remove metadata
                    await self.audit_repository.delete_archive_metadata(archive.id)

                    cleanup_summary["successfully_deleted"] += 1
                    cleanup_summary["deleted_archive_ids"].append(str(archive.id))
                    cleanup_summary["storage_freed_bytes"] += (
                        archive.archive_size_bytes or 0
                    )

                    logger.info("Archive deleted successfully", archive_id=archive.id)

            except Exception as e:
                cleanup_summary["failed_deletions"] += 1
                cleanup_summary["errors"].append(
                    {"archive_id": str(archive.id), "error": str(e)}
                )
                logger.exception(
                    "Failed to delete archive", archive_id=archive.id, error=str(e)
                )

        cleanup_summary["completed_at"] = datetime.utcnow().isoformat()

        logger.info(
            "Archive cleanup completed",
            deleted=cleanup_summary["successfully_deleted"],
            failed=cleanup_summary["failed_deletions"],
        )

        return cleanup_summary

    async def _archive_single_log(
        self,
        audit_log: Any,
        archive_location: str | None = None,
        compress: bool = True,
        validate_integrity: bool = True,
    ) -> dict[str, Any]:
        """Archive a single audit log."""
        try:
            logger.debug("Archiving single log", log_id=audit_log.id)

            # Prepare for archival
            audit_log.prepare_for_archive()
            await self.audit_repository.save(audit_log)

            # Export audit data
            export_data = await self._export_log_data(audit_log)

            # Validate integrity if requested
            if validate_integrity:
                integrity_check = await self._validate_export_integrity(
                    export_data, audit_log
                )
                if not integrity_check["valid"]:
                    return {
                        "success": False,
                        "error": f"Integrity validation failed: {integrity_check['errors']}",
                    }

            # Compress data if requested
            final_data = export_data
            compressed_size = None

            if compress:
                compressed_data = await self.compression_service.compress(
                    export_data, compression_method="gzip"
                )
                final_data = compressed_data["data"]
                compressed_size = len(final_data)

            # Generate archive location if not provided
            if not archive_location:
                archive_location = await self._generate_archive_location(audit_log)

            # Store archive
            storage_result = await self.storage_service.store_data(
                final_data,
                archive_location,
                metadata={
                    "log_id": str(audit_log.id),
                    "original_size": len(export_data),
                    "compressed_size": compressed_size,
                    "compressed": compress,
                    "archived_at": datetime.utcnow().isoformat(),
                    "entry_count": audit_log.entry_count,
                    "retention_policy": str(audit_log.retention_policy),
                },
            )

            # Complete archival
            audit_log.complete_archive(
                storage_result["location"], compressed_size or len(export_data)
            )
            await self.audit_repository.save(audit_log)

            return {
                "success": True,
                "log_id": str(audit_log.id),
                "archive_location": storage_result["location"],
                "original_size_bytes": len(export_data),
                "archive_size_bytes": compressed_size or len(export_data),
                "compression_ratio": (
                    len(export_data) / (compressed_size or len(export_data))
                )
                if compressed_size
                else 1.0,
                "archived_at": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            # Revert archival status on failure
            if hasattr(audit_log, "status"):
                from app.modules.audit.domain.enums.audit_enums import AuditStatus

                audit_log.status = AuditStatus.ACTIVE
                audit_log.mark_modified()
                await self.audit_repository.save(audit_log)

            return {"success": False, "error": str(e)}

    async def _export_log_data(self, audit_log: Any) -> bytes:
        """Export audit log data for archival."""
        # Get all entries for the log
        entries = await self.audit_repository.get_entries_for_log(audit_log.id)

        # Build export package
        export_package = {
            "format_version": "1.0",
            "exported_at": datetime.utcnow().isoformat(),
            "audit_log": {
                "id": str(audit_log.id),
                "title": audit_log.title,
                "description": audit_log.description,
                "retention_policy": str(audit_log.retention_policy),
                "created_at": audit_log.created_at.isoformat(),
                "entry_count": audit_log.entry_count,
                "last_entry_at": audit_log.last_entry_at.isoformat()
                if audit_log.last_entry_at
                else None,
            },
            "entries": [
                {
                    "id": str(entry.id),
                    "user_id": str(entry.user_id) if entry.user_id else None,
                    "action": {
                        "action_type": entry.action.action_type,
                        "operation": entry.action.operation,
                        "description": entry.action.description,
                    },
                    "resource": {
                        "resource_type": entry.resource.resource_type,
                        "resource_id": entry.resource.resource_id,
                        "resource_name": entry.resource.resource_name,
                    },
                    "context": {
                        "ip_address": entry.context.ip_address,
                        "user_agent": entry.context.user_agent,
                        "request_id": entry.context.request_id,
                    },
                    "outcome": entry.outcome,
                    "severity": entry.severity.value,
                    "category": entry.category.value,
                    "duration_ms": entry.duration_ms,
                    "error_details": entry.error_details,
                    "session_id": str(entry.session_id) if entry.session_id else None,
                    "correlation_id": entry.correlation_id,
                    "created_at": entry.created_at.isoformat(),
                    "changes": [
                        {
                            "field_name": change.field_name,
                            "old_value": change.old_value,
                            "new_value": change.new_value,
                            "field_type": change.field_type,
                        }
                        for change in (entry.changes or [])
                    ],
                    "metadata": {
                        "tags": entry.metadata.tags if entry.metadata else [],
                        "custom_fields": entry.metadata.custom_fields
                        if entry.metadata
                        else {},
                        "compliance_tags": entry.metadata.compliance_tags
                        if entry.metadata
                        else [],
                    },
                }
                for entry in entries
            ],
            "checksum": await self._calculate_checksum(entries),
        }

        # Serialize to JSON bytes
        return json.dumps(export_package, sort_keys=True).encode("utf-8")

    async def _validate_export_integrity(
        self, export_data: bytes, audit_log: Any
    ) -> dict[str, Any]:
        """Validate integrity of exported data."""
        try:
            # Parse exported data
            export_package = json.loads(export_data.decode("utf-8"))

            # Validate entry count
            exported_count = len(export_package["entries"])
            if exported_count != audit_log.entry_count:
                return {
                    "valid": False,
                    "errors": [
                        f"Entry count mismatch: expected {audit_log.entry_count}, got {exported_count}"
                    ],
                }

            # Validate log metadata
            exported_log = export_package["audit_log"]
            if exported_log["id"] != str(audit_log.id):
                return {"valid": False, "errors": ["Log ID mismatch in exported data"]}

            # Validate checksum
            entries_for_checksum = export_package["entries"]
            calculated_checksum = await self._calculate_checksum_from_data(
                entries_for_checksum
            )
            if calculated_checksum != export_package.get("checksum"):
                return {"valid": False, "errors": ["Checksum validation failed"]}

            return {"valid": True, "errors": []}

        except Exception as e:
            return {"valid": False, "errors": [f"Validation error: {e!s}"]}

    async def _generate_archive_location(self, audit_log: Any) -> str:
        """Generate archive storage location."""
        date_path = audit_log.created_at.strftime("%Y/%m/%d")
        return f"audit-archives/{date_path}/log_{audit_log.id}.json.gz"

    async def _calculate_checksum(self, entries: list[Any]) -> str:
        """Calculate checksum for audit entries."""
        import hashlib

        # Create deterministic representation
        checksum_data = []
        for entry in entries:
            entry_data = f"{entry.id}:{entry.created_at.isoformat()}:{entry.outcome}"
            checksum_data.append(entry_data)

        # Sort for consistency
        checksum_data.sort()

        # Calculate SHA256 hash
        hasher = hashlib.sha256()
        hasher.update("\n".join(checksum_data).encode("utf-8"))

        return hasher.hexdigest()

    async def _calculate_checksum_from_data(
        self, entries_data: list[dict[str, Any]]
    ) -> str:
        """Calculate checksum from serialized entry data."""
        import hashlib

        # Create deterministic representation
        checksum_data = []
        for entry in entries_data:
            entry_data = f"{entry['id']}:{entry['created_at']}:{entry['outcome']}"
            checksum_data.append(entry_data)

        # Sort for consistency
        checksum_data.sort()

        # Calculate SHA256 hash
        hasher = hashlib.sha256()
        hasher.update("\n".join(checksum_data).encode("utf-8"))

        return hasher.hexdigest()

    async def _calculate_compression_statistics(
        self, archived_logs: list[Any]
    ) -> dict[str, Any]:
        """Calculate compression statistics for archived logs."""
        if not archived_logs:
            return {
                "total_logs": 0,
                "compressed_logs": 0,
                "average_compression_ratio": 1.0,
                "total_space_saved": 0,
                "space_saved_percentage": 0.0,
            }

        compressed_logs = []
        total_original_size = 0
        total_compressed_size = 0

        for log in archived_logs:
            if hasattr(log, "original_size_bytes") and hasattr(
                log, "archive_size_bytes"
            ):
                original_size = log.original_size_bytes or 0
                compressed_size = log.archive_size_bytes or 0

                if original_size > 0 and compressed_size > 0:
                    total_original_size += original_size
                    total_compressed_size += compressed_size

                    compression_ratio = original_size / compressed_size
                    compressed_logs.append(compression_ratio)

        if compressed_logs:
            average_compression_ratio = sum(compressed_logs) / len(compressed_logs)
            total_space_saved = total_original_size - total_compressed_size
            space_saved_percentage = (
                (total_space_saved / total_original_size) * 100
                if total_original_size > 0
                else 0
            )
        else:
            average_compression_ratio = 1.0
            total_space_saved = 0
            space_saved_percentage = 0.0

        return {
            "total_logs": len(archived_logs),
            "compressed_logs": len(compressed_logs),
            "average_compression_ratio": round(average_compression_ratio, 2),
            "total_space_saved": total_space_saved,
            "space_saved_percentage": round(space_saved_percentage, 2),
        }

    async def _validate_restored_data(
        self, restored_data: bytes, archived_log_metadata: Any
    ) -> dict[str, Any]:
        """Validate restored archive data."""
        try:
            # Parse restored data
            export_package = json.loads(restored_data.decode("utf-8"))

            # Basic structure validation
            required_fields = ["format_version", "audit_log", "entries", "checksum"]
            for field in required_fields:
                if field not in export_package:
                    return {
                        "valid": False,
                        "errors": [f"Missing required field: {field}"],
                    }

            # Validate checksum
            entries = export_package["entries"]
            calculated_checksum = await self._calculate_checksum_from_data(entries)
            if calculated_checksum != export_package["checksum"]:
                return {"valid": False, "errors": ["Checksum validation failed"]}

            return {"valid": True, "errors": []}

        except Exception as e:
            return {"valid": False, "errors": [f"Validation error: {e!s}"]}

    async def _restore_to_database(self, restored_data: bytes, log_id: UUID) -> None:
        """Restore archived data back to the database."""
        # Parse data
        json.loads(restored_data.decode("utf-8"))

        # This would recreate the audit log and entries in the database
        # Implementation would depend on the specific repository interface
        logger.info("Restoring data to database", log_id=log_id)

        # For now, just log that restoration would occur
        # In a real implementation, this would:
        # 1. Recreate the audit log entity
        # 2. Recreate all audit entries
        # 3. Restore relationships and metadata
        # 4. Update the log status to active


__all__ = ["ArchivalService"]
