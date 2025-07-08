"""Data sync completed event handler.

This module handles DataSyncCompletedEvent to create audit trails
for data synchronization activities and compliance tracking.
"""

from ddd_implementation.shared_contracts import DataSyncCompletedEvent

from app.core.logging import get_logger
from app.modules.audit.application.services.audit_service import AuditService

logger = get_logger(__name__)


class DataSyncCompletedEventHandler:
    """
    Event handler for data sync completed events.

    Creates audit trails when data synchronization operations complete,
    supporting data governance and compliance requirements.
    """

    def __init__(self, audit_service: AuditService):
        """
        Initialize handler.

        Args:
            audit_service: Audit service for creating audit trails
        """
        self.audit_service = audit_service

    async def handle(self, event: DataSyncCompletedEvent) -> None:
        """
        Handle data sync completed event.

        Args:
            event: DataSyncCompletedEvent instance
        """
        logger.info(
            "Handling data sync completed event",
            sync_id=event.sync_id,
            source_system=event.source_system,
            target_system=event.target_system,
            records_synced=event.records_synced,
            status=event.status,
            event_id=event.metadata.event_id,
        )

        try:
            # Extract sync details
            sync_type = f"{event.source_system}_to_{event.target_system}"
            records_processed = event.records_synced
            sync_status = event.status
            error_count = len(event.error_details) if event.error_details else 0

            # Create audit trail for data sync completion
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action for data sync
                action_type="data_sync_completed",
                operation="sync",
                description=f"Data synchronization completed: {sync_type} ({event.records_synced} records in {event.duration_ms}ms)",
                resource_type="data_sync",
                resource_id=str(event.sync_id),
                resource_name=f"Data sync {event.sync_id}",
                context={
                    "event_id": str(event.metadata.event_id),
                    "correlation_id": str(event.metadata.correlation_id)
                    if event.metadata.correlation_id
                    else None,
                    "source_system": event.source_system,
                    "target_system": event.target_system,
                    "sync_type": sync_type,
                    "records_synced": event.records_synced,
                    "duration_ms": event.duration_ms,
                    "sync_status": sync_status,
                },
                outcome=self._map_sync_status_to_outcome(sync_status, error_count),
                severity=self._calculate_severity(
                    sync_status, error_count, records_processed
                ),
                category="data_management",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["data_sync", "integration", "data_transfer"],
                custom_fields={
                    "sync_id": str(event.sync_id),
                    "source_system": event.source_system,
                    "target_system": event.target_system,
                    "sync_type": sync_type,
                    "records_synced": event.records_synced,
                    "duration_ms": event.duration_ms,
                    "sync_status": sync_status,
                    "error_count": error_count,
                    "error_details": event.error_details,
                    "data_volume": self._calculate_data_volume(event.records_synced),
                },
                compliance_tags=[
                    "data_processing",
                    "system_integration",
                    "data_governance",
                ],
            )

            # Create data governance audit trail
            await self._create_data_governance_audit_trail(
                event, event.records_synced, sync_type
            )

            # Create compliance audit trail for personal data processing
            if self._involves_personal_data(sync_type):
                await self._create_personal_data_audit_trail(
                    event, event.records_synced, sync_type
                )

            # Create error audit trail if sync had errors
            if error_count > 0:
                await self._create_error_audit_trail(event, error_count)

            logger.info(
                "Data sync completed audit trail created successfully",
                sync_id=event.sync_id,
                source_system=event.source_system,
                target_system=event.target_system,
                records_synced=event.records_synced,
            )

        except Exception as e:
            logger.exception(
                "Failed to create audit trail for data sync completed",
                sync_id=event.sync_id,
                source_system=event.source_system,
                target_system=event.target_system,
                error=str(e),
            )
            # Don't re-raise to avoid disrupting the sync completion process

    def _map_sync_status_to_outcome(self, sync_status: str, error_count: int) -> str:
        """
        Map sync status to audit outcome.

        Args:
            sync_status: Synchronization status
            error_count: Number of errors during sync

        Returns:
            Audit outcome
        """
        if sync_status.lower() == "completed":
            return "success" if error_count == 0 else "partial_success"
        if sync_status.lower() in ["failed", "error"]:
            return "failure"
        return "unknown"

    def _calculate_severity(
        self, sync_status: str, error_count: int, records_processed: int
    ) -> str:
        """
        Calculate severity based on sync results.

        Args:
            sync_status: Synchronization status
            error_count: Number of errors
            records_processed: Number of records processed

        Returns:
            Severity level
        """
        if sync_status.lower() == "failed" or error_count > records_processed * 0.1:
            return "high"  # Failed sync or >10% error rate
        if error_count > 0:
            return "medium"  # Some errors occurred
        if records_processed > 10000:
            return "medium"  # Large data volume
        return "low"  # Normal successful sync

    def _calculate_data_volume(self, records_processed: int) -> str:
        """
        Calculate data volume category.

        Args:
            records_processed: Number of records processed

        Returns:
            Data volume category
        """
        if records_processed > 100000:
            return "very_large"
        if records_processed > 10000:
            return "large"
        if records_processed > 1000:
            return "medium"
        if records_processed > 0:
            return "small"
        return "empty"

    def _involves_personal_data(self, sync_type: str) -> bool:
        """
        Check if sync involves personal data.

        Args:
            sync_type: Type of synchronization

        Returns:
            True if involves personal data
        """
        personal_data_types = [
            "user",
            "customer",
            "contact",
            "profile",
            "account",
            "person",
            "individual",
            "subscriber",
            "member",
        ]
        sync_type_lower = sync_type.lower()
        return any(data_type in sync_type_lower for data_type in personal_data_types)

    async def _create_data_governance_audit_trail(
        self, event: DataSyncCompletedEvent, records_processed: int, sync_type: str
    ) -> None:
        """
        Create data governance audit trail.

        Args:
            event: DataSyncCompletedEvent instance
            records_processed: Number of records processed
            sync_type: Type of synchronization
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action
                action_type="data_governance_sync",
                operation="govern",
                description=f"Data governance tracking for sync operation: {sync_type}",
                resource_type="data_governance",
                resource_id=str(event.sync_id),
                resource_name=f"Data governance for sync {event.sync_id}",
                outcome="success",
                severity="low",
                category="governance",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["data_governance", "sync_monitoring", "data_quality"],
                custom_fields={
                    "governance_activity": "data_synchronization",
                    "data_source": event.source_system,
                    "data_destination": event.target_system,
                    "records_affected": records_processed,
                    "sync_operation_type": sync_type,
                    "data_quality_check": "applied",
                    "retention_policy_applied": True,
                },
                compliance_tags=["data_governance", "data_quality", "sync_monitoring"],
            )

            logger.debug(
                "Data governance audit trail created for sync",
                sync_id=event.sync_id,
                sync_type=sync_type,
            )

        except Exception as e:
            logger.warning(
                "Failed to create data governance audit trail",
                sync_id=event.sync_id,
                error=str(e),
            )

    async def _create_personal_data_audit_trail(
        self, event: DataSyncCompletedEvent, records_processed: int, sync_type: str
    ) -> None:
        """
        Create personal data processing audit trail.

        Args:
            event: DataSyncCompletedEvent instance
            records_processed: Number of records processed
            sync_type: Type of synchronization
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action
                action_type="personal_data_sync",
                operation="process",
                description=f"Personal data synchronization completed: {records_processed} records",
                resource_type="personal_data",
                resource_id=str(event.sync_id),
                resource_name=f"Personal data sync {event.sync_id}",
                outcome="success",
                severity="medium",
                category="privacy",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["personal_data", "privacy", "data_subject"],
                custom_fields={
                    "data_subjects_affected": records_processed,
                    "personal_data_types": sync_type,
                    "processing_purpose": "data_synchronization",
                    "legal_basis": "legitimate_interest",
                    "data_minimization_applied": True,
                    "privacy_controls_applied": True,
                },
                compliance_tags=[
                    "GDPR_Article_6",
                    "personal_data_processing",
                    "data_subject_rights",
                ],
            )

            logger.debug(
                "Personal data audit trail created for sync",
                sync_id=event.sync_id,
                records_processed=records_processed,
            )

        except Exception as e:
            logger.warning(
                "Failed to create personal data audit trail",
                sync_id=event.sync_id,
                error=str(e),
            )

    async def _create_error_audit_trail(
        self, event: DataSyncCompletedEvent, error_count: int
    ) -> None:
        """
        Create error audit trail for sync errors.

        Args:
            event: DataSyncCompletedEvent instance
            error_count: Number of errors during sync
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action
                action_type="data_sync_errors",
                operation="error",
                description=f"Data sync completed with {error_count} errors requiring attention",
                resource_type="sync_errors",
                resource_id=str(event.sync_id),
                resource_name=f"Sync errors for {event.sync_id}",
                outcome="warning",
                severity="medium",
                category="data_management",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["sync_errors", "data_quality", "error_tracking"],
                custom_fields={
                    "error_count": error_count,
                    "sync_completion_status": "partial",
                    "data_integrity_impact": "potential",
                    "manual_review_required": error_count > 10,
                    "error_threshold_exceeded": error_count > 100,
                },
                compliance_tags=["data_quality", "error_monitoring", "sync_integrity"],
            )

            logger.warning(
                "Error audit trail created for sync with errors",
                sync_id=event.sync_id,
                error_count=error_count,
            )

        except Exception as e:
            logger.exception(
                "Failed to create error audit trail",
                sync_id=event.sync_id,
                error=str(e),
            )


__all__ = ["DataSyncCompletedEventHandler"]
