"""
Data Synchronization Mutations for GraphQL API

This module provides comprehensive data synchronization mutations including
sync job management, batch operations, and synchronization control.
"""

from typing import Any
from uuid import UUID

import strawberry

from app.core.errors import DomainError, ValidationError
from app.core.logging import get_logger
from app.core.middleware.auth import require_auth, require_permission
from app.modules.identity.presentation.graphql.decorators import (
    audit_operation,
    rate_limit,
    track_metrics,
)

from ...schemas.inputs.sync_inputs import (
    BatchSyncInput,
    StartSyncJobInput,
    SyncConfigurationInput,
    SyncScheduleInput,
)
from ...schemas.types.sync_type import BatchSyncResult, SyncConfiguration, SyncJob

logger = get_logger(__name__)


@strawberry.type
class SyncMutations:
    """Data synchronization GraphQL mutations."""

    @strawberry.field(description="Start a new synchronization job")
    @require_auth()
    @require_permission("sync.job.start")
    @audit_operation("sync.start_job")
    @rate_limit(requests=20, window=60)
    @track_metrics("start_sync_job")
    async def start_sync_job(
        self, info: strawberry.Info, integration_id: UUID, input: StartSyncJobInput
    ) -> SyncJob:
        """
        Start a new data synchronization job.

        Args:
            integration_id: UUID of the integration
            input: Sync job configuration parameters

        Returns:
            Started sync job details
        """
        try:
            # Validate sync type
            if not input.sync_type:
                raise ValidationError("Sync type is required")

            # Validate direction
            valid_directions = ["inbound", "outbound", "bidirectional"]
            if input.sync_direction not in valid_directions:
                raise ValidationError(
                    f"Sync direction must be one of: {valid_directions}"
                )

            info.context["container"].resolve("SyncService")
            command = info.context["container"].resolve("StartSyncJobCommand")

            # Check if integration supports sync
            integration_service = info.context["container"].resolve(
                "IntegrationService"
            )
            integration = await integration_service.get_integration(integration_id)
            if not integration or not integration.can_sync:
                raise ValidationError("Integration does not support synchronization")

            # Execute sync start
            result = await command.execute(
                integration_id=integration_id,
                sync_type=input.sync_type,
                sync_direction=input.sync_direction,
                filters=input.filters,
                options=input.options or {},
                priority=input.priority,
                started_by=info.context["user_id"],
            )

            logger.info(
                "Sync job started successfully",
                job_id=str(result.job_id),
                integration_id=str(integration_id),
                sync_type=input.sync_type,
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("SyncMapper")
            return mapper.sync_job_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error starting sync job",
                integration_id=str(integration_id),
                sync_type=input.sync_type,
                error=str(e),
            )
            raise DomainError("Failed to start sync job")

    @strawberry.field(description="Cancel a running synchronization job")
    @require_auth()
    @require_permission("sync.job.cancel")
    @audit_operation("sync.cancel_job")
    @rate_limit(requests=30, window=60)
    @track_metrics("cancel_sync_job")
    async def cancel_sync_job(
        self, info: strawberry.Info, job_id: UUID, reason: str | None = None
    ) -> SyncJob:
        """
        Cancel a running synchronization job.

        Args:
            job_id: UUID of the sync job to cancel
            reason: Optional reason for cancellation

        Returns:
            Cancelled sync job details
        """
        try:
            service = info.context["container"].resolve("SyncService")
            command = info.context["container"].resolve("CancelSyncJobCommand")

            # Check if job exists and can be cancelled
            existing = await service.get_sync_job(job_id)
            if not existing:
                raise ValidationError("Sync job not found")

            if existing.status not in ["running", "queued", "paused"]:
                raise ValidationError(
                    f"Cannot cancel job with status: {existing.status}"
                )

            # Execute cancellation
            result = await command.execute(
                job_id=job_id, reason=reason, cancelled_by=info.context["user_id"]
            )

            logger.info(
                "Sync job cancelled successfully",
                job_id=str(job_id),
                reason=reason,
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("SyncMapper")
            return mapper.sync_job_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error cancelling sync job", job_id=str(job_id), error=str(e)
            )
            raise DomainError("Failed to cancel sync job")

    @strawberry.field(description="Pause a running synchronization job")
    @require_auth()
    @require_permission("sync.job.pause")
    @audit_operation("sync.pause_job")
    @rate_limit(requests=30, window=60)
    @track_metrics("pause_sync_job")
    async def pause_sync_job(
        self, info: strawberry.Info, job_id: UUID, reason: str | None = None
    ) -> SyncJob:
        """
        Pause a running synchronization job.

        Args:
            job_id: UUID of the sync job to pause
            reason: Optional reason for pausing

        Returns:
            Paused sync job details
        """
        try:
            service = info.context["container"].resolve("SyncService")
            command = info.context["container"].resolve("PauseSyncJobCommand")

            # Check if job exists and can be paused
            existing = await service.get_sync_job(job_id)
            if not existing:
                raise ValidationError("Sync job not found")

            if existing.status != "running":
                raise ValidationError(
                    f"Cannot pause job with status: {existing.status}"
                )

            # Execute pause
            result = await command.execute(
                job_id=job_id, reason=reason, paused_by=info.context["user_id"]
            )

            logger.info(
                "Sync job paused successfully",
                job_id=str(job_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("SyncMapper")
            return mapper.sync_job_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error pausing sync job", job_id=str(job_id), error=str(e))
            raise DomainError("Failed to pause sync job")

    @strawberry.field(description="Resume a paused synchronization job")
    @require_auth()
    @require_permission("sync.job.resume")
    @audit_operation("sync.resume_job")
    @rate_limit(requests=30, window=60)
    @track_metrics("resume_sync_job")
    async def resume_sync_job(self, info: strawberry.Info, job_id: UUID) -> SyncJob:
        """
        Resume a paused synchronization job.

        Args:
            job_id: UUID of the sync job to resume

        Returns:
            Resumed sync job details
        """
        try:
            service = info.context["container"].resolve("SyncService")
            command = info.context["container"].resolve("ResumeSyncJobCommand")

            # Check if job exists and can be resumed
            existing = await service.get_sync_job(job_id)
            if not existing:
                raise ValidationError("Sync job not found")

            if existing.status != "paused":
                raise ValidationError(
                    f"Cannot resume job with status: {existing.status}"
                )

            # Execute resume
            result = await command.execute(
                job_id=job_id, resumed_by=info.context["user_id"]
            )

            logger.info(
                "Sync job resumed successfully",
                job_id=str(job_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("SyncMapper")
            return mapper.sync_job_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error resuming sync job", job_id=str(job_id), error=str(e)
            )
            raise DomainError("Failed to resume sync job")

    @strawberry.field(description="Retry a failed synchronization job")
    @require_auth()
    @require_permission("sync.job.retry")
    @audit_operation("sync.retry_job")
    @rate_limit(requests=20, window=60)
    @track_metrics("retry_sync_job")
    async def retry_sync_job(
        self, info: strawberry.Info, job_id: UUID, retry_from_checkpoint: bool = True
    ) -> SyncJob:
        """
        Retry a failed synchronization job.

        Args:
            job_id: UUID of the sync job to retry
            retry_from_checkpoint: Whether to retry from last checkpoint

        Returns:
            New retry sync job details
        """
        try:
            service = info.context["container"].resolve("SyncService")
            command = info.context["container"].resolve("RetrySyncJobCommand")

            # Check if job exists and can be retried
            existing = await service.get_sync_job(job_id)
            if not existing:
                raise ValidationError("Sync job not found")

            if existing.status not in ["failed", "cancelled"]:
                raise ValidationError(
                    f"Cannot retry job with status: {existing.status}"
                )

            # Execute retry
            result = await command.execute(
                original_job_id=job_id,
                retry_from_checkpoint=retry_from_checkpoint,
                retried_by=info.context["user_id"],
            )

            logger.info(
                "Sync job retry started",
                original_job_id=str(job_id),
                new_job_id=str(result.job_id),
                retry_from_checkpoint=retry_from_checkpoint,
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("SyncMapper")
            return mapper.sync_job_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrying sync job", job_id=str(job_id), error=str(e)
            )
            raise DomainError("Failed to retry sync job")

    @strawberry.field(description="Execute batch synchronization operation")
    @require_auth()
    @require_permission("sync.batch.execute")
    @audit_operation("sync.execute_batch")
    @rate_limit(requests=10, window=60)
    @track_metrics("execute_batch_sync")
    async def execute_batch_sync(
        self, info: strawberry.Info, input: BatchSyncInput
    ) -> BatchSyncResult:
        """
        Execute a batch synchronization operation across multiple integrations.

        Args:
            input: Batch sync configuration parameters

        Returns:
            Batch sync execution results
        """
        try:
            # Validate integration IDs
            if not input.integration_ids or len(input.integration_ids) == 0:
                raise ValidationError("At least one integration ID is required")

            if len(input.integration_ids) > 10:
                raise ValidationError("Maximum 10 integrations allowed per batch")

            info.context["container"].resolve("BatchSyncService")
            command = info.context["container"].resolve("ExecuteBatchSyncCommand")

            # Execute batch sync
            result = await command.execute(
                integration_ids=input.integration_ids,
                sync_type=input.sync_type,
                sync_direction=input.sync_direction,
                filters=input.filters,
                options=input.options or {},
                parallel_execution=input.parallel_execution,
                executed_by=info.context["user_id"],
            )

            logger.info(
                "Batch sync executed successfully",
                batch_id=str(result.batch_id),
                integration_count=len(input.integration_ids),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("SyncMapper")
            return mapper.batch_sync_result_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error executing batch sync",
                integration_count=len(input.integration_ids),
                error=str(e),
            )
            raise DomainError("Failed to execute batch sync")

    @strawberry.field(description="Update synchronization configuration")
    @require_auth()
    @require_permission("sync.configuration.update")
    @audit_operation("sync.update_configuration")
    @rate_limit(requests=15, window=60)
    @track_metrics("update_sync_configuration")
    async def update_sync_configuration(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        configuration: SyncConfigurationInput,
    ) -> SyncConfiguration:
        """
        Update synchronization configuration for an integration.

        Args:
            integration_id: UUID of the integration
            configuration: New sync configuration parameters

        Returns:
            Updated sync configuration details
        """
        try:
            # Validate configuration
            if (
                configuration.sync_interval_minutes
                and configuration.sync_interval_minutes < 5
            ):
                raise ValidationError("Sync interval must be at least 5 minutes")

            if configuration.batch_size and (
                configuration.batch_size < 1 or configuration.batch_size > 1000
            ):
                raise ValidationError("Batch size must be between 1 and 1000")

            info.context["container"].resolve("SyncConfigurationService")
            command = info.context["container"].resolve(
                "UpdateSyncConfigurationCommand"
            )

            # Execute configuration update
            result = await command.execute(
                integration_id=integration_id,
                configuration=configuration,
                updated_by=info.context["user_id"],
            )

            logger.info(
                "Sync configuration updated",
                integration_id=str(integration_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("SyncMapper")
            return mapper.sync_configuration_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error updating sync configuration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise DomainError("Failed to update sync configuration")

    @strawberry.field(description="Schedule recurring synchronization")
    @require_auth()
    @require_permission("sync.schedule.create")
    @audit_operation("sync.schedule_recurring")
    @rate_limit(requests=10, window=60)
    @track_metrics("schedule_recurring_sync")
    async def schedule_recurring_sync(
        self, info: strawberry.Info, integration_id: UUID, schedule: SyncScheduleInput
    ) -> dict[str, Any]:
        """
        Schedule recurring synchronization for an integration.

        Args:
            integration_id: UUID of the integration
            schedule: Sync schedule configuration

        Returns:
            Schedule creation results
        """
        try:
            # Validate schedule
            if not schedule.cron_expression and not schedule.interval_minutes:
                raise ValidationError(
                    "Either cron expression or interval must be specified"
                )

            if schedule.interval_minutes and schedule.interval_minutes < 15:
                raise ValidationError("Minimum interval is 15 minutes")

            info.context["container"].resolve("SyncSchedulerService")
            command = info.context["container"].resolve("ScheduleRecurringSyncCommand")

            # Execute schedule creation
            result = await command.execute(
                integration_id=integration_id,
                schedule=schedule,
                scheduled_by=info.context["user_id"],
            )

            logger.info(
                "Recurring sync scheduled",
                integration_id=str(integration_id),
                schedule_id=str(result.schedule_id),
                user_id=str(info.context["user_id"]),
            )

            return {
                "success": True,
                "schedule_id": str(result.schedule_id),
                "next_run_time": result.next_run_time,
                "cron_expression": result.cron_expression,
                "is_active": result.is_active,
                "created_at": result.created_at,
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error scheduling recurring sync",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise DomainError("Failed to schedule recurring sync")

    @strawberry.field(description="Update sync schedule")
    @require_auth()
    @require_permission("sync.schedule.update")
    @audit_operation("sync.update_schedule")
    @rate_limit(requests=15, window=60)
    @track_metrics("update_sync_schedule")
    async def update_sync_schedule(
        self, info: strawberry.Info, schedule_id: UUID, schedule: SyncScheduleInput
    ) -> dict[str, Any]:
        """
        Update an existing sync schedule.

        Args:
            schedule_id: UUID of the schedule to update
            schedule: Updated schedule configuration

        Returns:
            Schedule update results
        """
        try:
            info.context["container"].resolve("SyncSchedulerService")
            command = info.context["container"].resolve("UpdateSyncScheduleCommand")

            # Execute schedule update
            result = await command.execute(
                schedule_id=schedule_id,
                schedule=schedule,
                updated_by=info.context["user_id"],
            )

            logger.info(
                "Sync schedule updated",
                schedule_id=str(schedule_id),
                user_id=str(info.context["user_id"]),
            )

            return {
                "success": True,
                "schedule_id": str(schedule_id),
                "next_run_time": result.next_run_time,
                "cron_expression": result.cron_expression,
                "is_active": result.is_active,
                "updated_at": result.updated_at,
            }

        except Exception as e:
            logger.exception(
                "Error updating sync schedule",
                schedule_id=str(schedule_id),
                error=str(e),
            )
            raise DomainError("Failed to update sync schedule")

    @strawberry.field(description="Delete sync schedule")
    @require_auth()
    @require_permission("sync.schedule.delete")
    @audit_operation("sync.delete_schedule")
    @rate_limit(requests=15, window=60)
    @track_metrics("delete_sync_schedule")
    async def delete_sync_schedule(
        self, info: strawberry.Info, schedule_id: UUID
    ) -> bool:
        """
        Delete a sync schedule.

        Args:
            schedule_id: UUID of the schedule to delete

        Returns:
            True if deletion was successful
        """
        try:
            info.context["container"].resolve("SyncSchedulerService")
            command = info.context["container"].resolve("DeleteSyncScheduleCommand")

            # Execute schedule deletion
            await command.execute(
                schedule_id=schedule_id, deleted_by=info.context["user_id"]
            )

            logger.info(
                "Sync schedule deleted",
                schedule_id=str(schedule_id),
                user_id=str(info.context["user_id"]),
            )

            return True

        except Exception as e:
            logger.exception(
                "Error deleting sync schedule",
                schedule_id=str(schedule_id),
                error=str(e),
            )
            raise DomainError("Failed to delete sync schedule")

    @strawberry.field(description="Force sync checkpoint")
    @require_auth()
    @require_permission("sync.checkpoint.force")
    @audit_operation("sync.force_checkpoint")
    @rate_limit(requests=20, window=60)
    @track_metrics("force_sync_checkpoint")
    async def force_sync_checkpoint(
        self, info: strawberry.Info, job_id: UUID
    ) -> dict[str, Any]:
        """
        Force a checkpoint for a running sync job.

        Args:
            job_id: UUID of the sync job

        Returns:
            Checkpoint creation results
        """
        try:
            service = info.context["container"].resolve("SyncService")
            command = info.context["container"].resolve("ForceSyncCheckpointCommand")

            # Check if job exists and is running
            existing = await service.get_sync_job(job_id)
            if not existing:
                raise ValidationError("Sync job not found")

            if existing.status != "running":
                raise ValidationError(
                    f"Cannot checkpoint job with status: {existing.status}"
                )

            # Execute checkpoint
            result = await command.execute(
                job_id=job_id, forced_by=info.context["user_id"]
            )

            logger.info(
                "Sync checkpoint forced",
                job_id=str(job_id),
                checkpoint_id=str(result.checkpoint_id),
                user_id=str(info.context["user_id"]),
            )

            return {
                "success": True,
                "checkpoint_id": str(result.checkpoint_id),
                "checkpoint_time": result.checkpoint_time,
                "records_processed": result.records_processed,
                "checkpoint_data": result.checkpoint_data,
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error forcing sync checkpoint", job_id=str(job_id), error=str(e)
            )
            raise DomainError("Failed to force sync checkpoint")


__all__ = ["SyncMutations"]
