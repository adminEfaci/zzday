"""Archive audit log command.

This module implements the command and handler for archiving audit logs,
supporting compliance retention and storage management.
"""

from datetime import datetime
from uuid import UUID

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import DomainError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.audit.domain.aggregates.audit_log import AuditLog

logger = get_logger(__name__)


class ArchiveAuditLogCommand(Command):
    """
    Command to archive an audit log.

    Archives audit logs for long-term storage while maintaining
    compliance with retention policies.
    """

    def __init__(
        self,
        audit_log_id: UUID,
        archive_location: str,
        compress: bool = True,
        validate_integrity: bool = True,
        force_archive: bool = False,
    ):
        """
        Initialize archive audit log command.

        Args:
            audit_log_id: ID of the audit log to archive
            archive_location: Storage location for the archive
            compress: Whether to compress the archive
            validate_integrity: Whether to validate data integrity
            force_archive: Force archive even if not expired
        """
        super().__init__()

        self.audit_log_id = self._validate_audit_log_id(audit_log_id)
        self.archive_location = self._validate_archive_location(archive_location)
        self.compress = compress
        self.validate_integrity = validate_integrity
        self.force_archive = force_archive

        self._freeze()

    def _validate_audit_log_id(self, audit_log_id: UUID) -> UUID:
        """Validate audit log ID."""
        if not isinstance(audit_log_id, UUID):
            raise ValidationError("Audit log ID must be a valid UUID")
        return audit_log_id

    def _validate_archive_location(self, location: str) -> str:
        """Validate archive location."""
        if not location or not location.strip():
            raise ValidationError("Archive location cannot be empty")

        # Basic validation - real implementation would check path validity
        if not (location.startswith(("s3://", "/", "gs://"))):
            raise ValidationError("Archive location must be a valid storage path")

        return location.strip()


class ArchiveAuditLogCommandHandler(CommandHandler[ArchiveAuditLogCommand, None]):
    """
    Handler for archiving audit logs.

    This handler manages the archival process, including data export,
    compression, and updating the audit log status.
    """

    def __init__(
        self, audit_repository: Any, archive_service: Any, event_publisher: Any
    ):
        """
        Initialize handler.

        Args:
            audit_repository: Repository for audit log persistence
            archive_service: Service for handling archive operations
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self.audit_repository = audit_repository
        self.archive_service = archive_service
        self.event_publisher = event_publisher

    async def handle(self, command: ArchiveAuditLogCommand) -> None:
        """
        Handle the archive audit log command.

        Args:
            command: Command containing archive details

        Raises:
            NotFoundError: If audit log not found
            DomainError: If archive operation fails
        """
        logger.info(
            "Archiving audit log",
            audit_log_id=command.audit_log_id,
            archive_location=command.archive_location,
        )

        # Retrieve audit log
        audit_log = await self.audit_repository.find_by_id(command.audit_log_id)
        if not audit_log:
            raise NotFoundError(f"Audit log not found: {command.audit_log_id}")

        # Check if log can be archived
        if not command.force_archive and not audit_log.is_expired():
            raise DomainError("Audit log has not reached retention expiry")

        # Prepare for archive
        audit_log.prepare_for_archive()
        await self.audit_repository.save(audit_log)

        try:
            # Export audit data
            export_data = await self._export_audit_data(audit_log)

            # Validate integrity if requested
            if command.validate_integrity:
                await self._validate_data_integrity(export_data, audit_log)

            # Compress if requested
            archive_data = export_data
            compressed_size = None
            if command.compress:
                (
                    archive_data,
                    compressed_size,
                ) = await self.archive_service.compress_data(
                    export_data, f"audit_log_{audit_log.id}"
                )

            # Store archive
            final_location = await self.archive_service.store_archive(
                archive_data,
                command.archive_location,
                metadata={
                    "audit_log_id": str(audit_log.id),
                    "entry_count": audit_log.entry_count,
                    "date_range": {
                        "start": audit_log.created_at.isoformat(),
                        "end": audit_log.last_entry_at.isoformat()
                        if audit_log.last_entry_at
                        else None,
                    },
                    "compressed": command.compress,
                    "archived_at": datetime.utcnow().isoformat(),
                },
            )

            # Complete archive
            audit_log.complete_archive(final_location, compressed_size)
            await self.audit_repository.save(audit_log)

            # Publish domain events
            for event in audit_log.collect_events():
                await self.event_publisher.publish(event)

            logger.info(
                "Audit log archived successfully",
                audit_log_id=audit_log.id,
                archive_location=final_location,
                entry_count=audit_log.entry_count,
                compressed_size=compressed_size,
            )

        except Exception as e:
            # Revert archive status on failure
            audit_log.status = audit_log.status.ACTIVE
            audit_log.mark_modified()
            await self.audit_repository.save(audit_log)

            logger.exception(
                "Failed to archive audit log", audit_log_id=audit_log.id, error=str(e)
            )
            raise DomainError(f"Archive operation failed: {e!s}")

    async def _export_audit_data(self, audit_log: AuditLog) -> bytes:
        """
        Export audit log data for archival.

        Args:
            audit_log: Audit log to export

        Returns:
            Exported data as bytes
        """
        # In a real implementation, this would:
        # 1. Fetch all entries for the audit log
        # 2. Serialize to a standard format (JSON, CSV, etc.)
        # 3. Include metadata and checksums

        import json

        entries = await self.audit_repository.get_entries(audit_log.id)

        export_data = {
            "audit_log": audit_log.to_dict(),
            "entries": [entry.to_dict() for entry in entries],
            "metadata": {
                "export_version": "1.0",
                "export_date": datetime.utcnow().isoformat(),
                "entry_count": len(entries),
                "checksum": "sha256:placeholder",  # Would calculate real checksum
            },
        }

        return json.dumps(export_data, indent=2).encode("utf-8")

    async def _validate_data_integrity(
        self, export_data: bytes, audit_log: AuditLog
    ) -> None:
        """
        Validate integrity of exported data.

        Args:
            export_data: Exported data to validate
            audit_log: Original audit log

        Raises:
            DomainError: If integrity validation fails
        """
        # In a real implementation, this would:
        # 1. Verify checksums
        # 2. Validate entry count matches
        # 3. Check for data corruption
        # 4. Verify all required fields are present

        import json

        try:
            data = json.loads(export_data)

            # Verify entry count
            if data["metadata"]["entry_count"] != audit_log.entry_count:
                raise DomainError("Entry count mismatch in exported data")

            # Additional validation would go here

        except json.JSONDecodeError:
            raise DomainError("Invalid export data format")

    @property
    def command_type(self) -> type[ArchiveAuditLogCommand]:
        """Get command type this handler processes."""
        return ArchiveAuditLogCommand


__all__ = ["ArchiveAuditLogCommand", "ArchiveAuditLogCommandHandler"]
