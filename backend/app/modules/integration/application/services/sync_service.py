"""Sync application service.

This module provides the application service for data synchronization,
including job management, progress tracking, and error handling.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import ApplicationError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import SyncResultDTO, SyncStatusDTO
from app.modules.integration.domain.entities import IntegrationMapping, SyncJob
from app.modules.integration.domain.enums import SyncDirection, SyncStatus

logger = get_logger(__name__)


class SyncService:
    """Application service for data synchronization."""

    def __init__(
        self,
        sync_job_repository: Any,
        integration_repository: Any,
        mapping_repository: Any,
        data_transformer: Any,
        external_api_client: Any,
        event_publisher: Any,
        scheduler: Any,
    ):
        """Initialize sync service.

        Args:
            sync_job_repository: Repository for sync jobs
            integration_repository: Repository for integrations
            mapping_repository: Repository for mappings
            data_transformer: Service for data transformation
            external_api_client: Client for external API calls
            event_publisher: Event publisher for domain events
            scheduler: Service for job scheduling
        """
        self._sync_job_repository = sync_job_repository
        self._integration_repository = integration_repository
        self._mapping_repository = mapping_repository
        self._data_transformer = data_transformer
        self._external_api_client = external_api_client
        self._event_publisher = event_publisher
        self._scheduler = scheduler

    async def start_sync(self, sync_job: SyncJob) -> None:
        """Start a synchronization job.

        Args:
            sync_job: Sync job to start

        Raises:
            ValidationError: If sync cannot be started
            ApplicationError: If sync startup fails
        """
        logger.info(
            "Starting sync job",
            sync_job_id=sync_job.id,
            direction=sync_job.direction.value,
        )

        try:
            # Get integration and mapping
            integration = await self._integration_repository.get_by_id(
                sync_job.integration_id
            )
            if not integration or not integration.can_sync:
                raise ValidationError("Integration cannot perform sync operations")

            mapping = await self._mapping_repository.get_by_id(sync_job.mapping_id)
            if not mapping or not mapping.is_active:
                raise ValidationError("Mapping is not active")

            # Start sync job
            sync_job.start()
            await self._sync_job_repository.save(sync_job)

            # Schedule sync execution
            await self._scheduler.schedule_sync_execution(sync_job.id)

            logger.info("Sync job started", sync_job_id=sync_job.id)

        except Exception as e:
            logger.exception(
                "Failed to start sync job", sync_job_id=sync_job.id, error=str(e)
            )
            sync_job.fail(str(e))
            await self._sync_job_repository.save(sync_job)
            raise

    async def execute_sync(self, sync_job_id: UUID) -> SyncResultDTO:
        """Execute synchronization job.

        Args:
            sync_job_id: Sync job ID

        Returns:
            SyncResultDTO: Sync execution results

        Raises:
            NotFoundError: If sync job not found
            ApplicationError: If sync execution fails
        """
        logger.info("Executing sync job", sync_job_id=sync_job_id)

        # Get sync job
        sync_job = await self._sync_job_repository.get_by_id(sync_job_id)
        if not sync_job:
            raise NotFoundError(f"Sync job not found: {sync_job_id}")

        # Get dependencies
        integration = await self._integration_repository.get_by_id(
            sync_job.integration_id
        )
        mapping = await self._mapping_repository.get_by_id(sync_job.mapping_id)

        if not integration or not mapping:
            raise ApplicationError("Missing integration or mapping")

        start_time = datetime.utcnow()

        try:
            # Execute sync based on direction
            if sync_job.direction == SyncDirection.IMPORT:
                result = await self._execute_import(sync_job, integration, mapping)
            elif sync_job.direction == SyncDirection.EXPORT:
                result = await self._execute_export(sync_job, integration, mapping)
            else:  # BIDIRECTIONAL
                import_result = await self._execute_import(
                    sync_job, integration, mapping
                )
                export_result = await self._execute_export(
                    sync_job, integration, mapping
                )
                result = self._merge_sync_results(import_result, export_result)

            # Complete sync job
            sync_job.complete(
                total_records=result["total_records"],
                processed_records=result["processed_records"],
                failed_records=result["failed_records"],
            )

            # Calculate duration
            duration = (datetime.utcnow() - start_time).total_seconds()

            # Create result DTO
            sync_result = SyncResultDTO(
                sync_job_id=sync_job.id,
                integration_id=integration.id,
                status=sync_job.status,
                total_records=result["total_records"],
                processed_records=result["processed_records"],
                created_records=result.get("created_records", 0),
                updated_records=result.get("updated_records", 0),
                deleted_records=result.get("deleted_records", 0),
                failed_records=result["failed_records"],
                skipped_records=result.get("skipped_records", 0),
                duration_seconds=duration,
                error_details=result.get("errors", []),
                summary=result.get("summary", {}),
            )

            await self._sync_job_repository.save(sync_job)

            # Publish sync completed event
            await self._publish_sync_completed_event(sync_job, sync_result)

            logger.info(
                "Sync job completed successfully",
                sync_job_id=sync_job.id,
                duration_seconds=duration,
                processed_records=result["processed_records"],
            )

            return sync_result

        except Exception as e:
            logger.exception(
                "Sync job execution failed", sync_job_id=sync_job.id, error=str(e)
            )

            sync_job.fail(str(e))
            await self._sync_job_repository.save(sync_job)

            # Create failed result
            duration = (datetime.utcnow() - start_time).total_seconds()
            return SyncResultDTO(
                sync_job_id=sync_job.id,
                integration_id=integration.id,
                status=SyncStatus.FAILED,
                total_records=0,
                processed_records=0,
                created_records=0,
                updated_records=0,
                deleted_records=0,
                failed_records=0,
                skipped_records=0,
                duration_seconds=duration,
                error_details=[
                    {"error": str(e), "timestamp": datetime.utcnow().isoformat()}
                ],
                summary={"error": str(e)},
            )

    async def cancel_sync(self, sync_job_id: UUID, reason: str = "Cancelled") -> None:
        """Cancel a running sync job.

        Args:
            sync_job_id: Sync job ID
            reason: Cancellation reason

        Raises:
            NotFoundError: If sync job not found
            ValidationError: If sync cannot be cancelled
        """
        logger.info("Cancelling sync job", sync_job_id=sync_job_id)

        sync_job = await self._sync_job_repository.get_by_id(sync_job_id)
        if not sync_job:
            raise NotFoundError(f"Sync job not found: {sync_job_id}")

        if not sync_job.can_cancel:
            raise ValidationError("Sync job cannot be cancelled")

        sync_job.cancel(reason)
        await self._sync_job_repository.save(sync_job)

        # Cancel scheduled execution
        await self._scheduler.cancel_sync_execution(sync_job_id)

        logger.info("Sync job cancelled", sync_job_id=sync_job_id)

    async def get_sync_progress(self, sync_job_id: UUID) -> SyncStatusDTO:
        """Get sync job progress.

        Args:
            sync_job_id: Sync job ID

        Returns:
            SyncStatusDTO: Current sync status

        Raises:
            NotFoundError: If sync job not found
        """
        sync_job = await self._sync_job_repository.get_by_id(sync_job_id)
        if not sync_job:
            raise NotFoundError(f"Sync job not found: {sync_job_id}")

        return SyncStatusDTO.from_domain(sync_job)

    async def _execute_import(
        self, sync_job: SyncJob, integration: Any, mapping: IntegrationMapping
    ) -> dict[str, Any]:
        """Execute data import from external system.

        Args:
            sync_job: Sync job
            integration: Integration
            mapping: Data mapping

        Returns:
            dict[str, Any]: Import results
        """
        logger.info("Executing import", sync_job_id=sync_job.id)

        results = {
            "total_records": 0,
            "processed_records": 0,
            "created_records": 0,
            "updated_records": 0,
            "failed_records": 0,
            "errors": [],
        }

        try:
            # Get data from external system
            external_data = await self._external_api_client.fetch_data(
                integration=integration,
                entity=mapping.source_entity,
                filters=sync_job.filters,
                batch_size=sync_job.batch_size,
            )

            results["total_records"] = len(external_data)

            # Process data in batches
            for batch in self._batch_data(external_data, sync_job.batch_size):
                batch_result = await self._process_import_batch(
                    batch, mapping, sync_job
                )

                # Update results
                results["processed_records"] += batch_result["processed"]
                results["created_records"] += batch_result["created"]
                results["updated_records"] += batch_result["updated"]
                results["failed_records"] += batch_result["failed"]
                results["errors"].extend(batch_result["errors"])

                # Update sync job progress
                sync_job.update_progress(
                    total_records=results["total_records"],
                    processed_records=results["processed_records"],
                    failed_records=results["failed_records"],
                )
                await self._sync_job_repository.save(sync_job)

        except Exception as e:
            logger.exception("Import execution failed", error=str(e))
            results["errors"].append(
                {"error": str(e), "timestamp": datetime.utcnow().isoformat()}
            )

        return results

    async def _execute_export(
        self, sync_job: SyncJob, integration: Any, mapping: IntegrationMapping
    ) -> dict[str, Any]:
        """Execute data export to external system.

        Args:
            sync_job: Sync job
            integration: Integration
            mapping: Data mapping

        Returns:
            dict[str, Any]: Export results
        """
        logger.info("Executing export", sync_job_id=sync_job.id)

        results = {
            "total_records": 0,
            "processed_records": 0,
            "created_records": 0,
            "updated_records": 0,
            "failed_records": 0,
            "errors": [],
        }

        try:
            # Get data from internal system
            internal_data = await self._get_internal_data(
                mapping.target_entity, sync_job.filters
            )

            results["total_records"] = len(internal_data)

            # Process data in batches
            for batch in self._batch_data(internal_data, sync_job.batch_size):
                batch_result = await self._process_export_batch(
                    batch, mapping, integration, sync_job
                )

                # Update results
                results["processed_records"] += batch_result["processed"]
                results["created_records"] += batch_result["created"]
                results["updated_records"] += batch_result["updated"]
                results["failed_records"] += batch_result["failed"]
                results["errors"].extend(batch_result["errors"])

                # Update sync job progress
                sync_job.update_progress(
                    total_records=results["total_records"],
                    processed_records=results["processed_records"],
                    failed_records=results["failed_records"],
                )
                await self._sync_job_repository.save(sync_job)

        except Exception as e:
            logger.exception("Export execution failed", error=str(e))
            results["errors"].append(
                {"error": str(e), "timestamp": datetime.utcnow().isoformat()}
            )

        return results

    async def _process_import_batch(
        self,
        batch: list[dict[str, Any]],
        mapping: IntegrationMapping,
        sync_job: SyncJob,
    ) -> dict[str, Any]:
        """Process import batch.

        Args:
            batch: Data batch
            mapping: Field mapping
            sync_job: Sync job

        Returns:
            dict[str, Any]: Batch results
        """
        results = {
            "processed": 0,
            "created": 0,
            "updated": 0,
            "failed": 0,
            "errors": [],
        }

        for record in batch:
            try:
                # Transform data using mapping
                transformed_data = await self._data_transformer.transform(
                    data=record, mapping=mapping.field_mappings, direction="import"
                )

                # Save to internal system
                save_result = await self._save_internal_record(
                    entity=mapping.target_entity, data=transformed_data
                )

                if save_result["created"]:
                    results["created"] += 1
                else:
                    results["updated"] += 1

                results["processed"] += 1

            except Exception as e:
                logger.warning(
                    "Failed to process import record",
                    sync_job_id=sync_job.id,
                    error=str(e),
                )
                results["failed"] += 1
                results["errors"].append(
                    {
                        "record": record,
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

        return results

    async def _process_export_batch(
        self,
        batch: list[dict[str, Any]],
        mapping: IntegrationMapping,
        integration: Any,
        sync_job: SyncJob,
    ) -> dict[str, Any]:
        """Process export batch.

        Args:
            batch: Data batch
            mapping: Field mapping
            integration: Integration
            sync_job: Sync job

        Returns:
            dict[str, Any]: Batch results
        """
        results = {
            "processed": 0,
            "created": 0,
            "updated": 0,
            "failed": 0,
            "errors": [],
        }

        for record in batch:
            try:
                # Transform data using mapping
                transformed_data = await self._data_transformer.transform(
                    data=record, mapping=mapping.field_mappings, direction="export"
                )

                # Send to external system
                send_result = await self._external_api_client.send_data(
                    integration=integration,
                    entity=mapping.source_entity,
                    data=transformed_data,
                )

                if send_result["created"]:
                    results["created"] += 1
                else:
                    results["updated"] += 1

                results["processed"] += 1

            except Exception as e:
                logger.warning(
                    "Failed to process export record",
                    sync_job_id=sync_job.id,
                    error=str(e),
                )
                results["failed"] += 1
                results["errors"].append(
                    {
                        "record": record,
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

        return results

    def _batch_data(self, data: list[Any], batch_size: int) -> list[list[Any]]:
        """Split data into batches.

        Args:
            data: Data to batch
            batch_size: Size of each batch

        Returns:
            list[list[Any]]: Batched data
        """
        for i in range(0, len(data), batch_size):
            yield data[i : i + batch_size]

    def _merge_sync_results(
        self, import_result: dict[str, Any], export_result: dict[str, Any]
    ) -> dict[str, Any]:
        """Merge import and export results.

        Args:
            import_result: Import results
            export_result: Export results

        Returns:
            dict[str, Any]: Merged results
        """
        return {
            "total_records": import_result["total_records"]
            + export_result["total_records"],
            "processed_records": import_result["processed_records"]
            + export_result["processed_records"],
            "created_records": import_result["created_records"]
            + export_result["created_records"],
            "updated_records": import_result["updated_records"]
            + export_result["updated_records"],
            "failed_records": import_result["failed_records"]
            + export_result["failed_records"],
            "errors": import_result["errors"] + export_result["errors"],
            "summary": {"import": import_result, "export": export_result},
        }

    async def _get_internal_data(
        self, entity: str, filters: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Get data from internal system.

        Args:
            entity: Entity name
            filters: Data filters

        Returns:
            list[dict[str, Any]]: Internal data
        """
        # Implementation would depend on internal data source
        # This is a placeholder
        return []

    async def _save_internal_record(
        self, entity: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        """Save record to internal system.

        Args:
            entity: Entity name
            data: Record data

        Returns:
            dict[str, Any]: Save result
        """
        # Implementation would depend on internal data store
        # This is a placeholder
        return {"created": True}

    async def _publish_sync_completed_event(
        self, sync_job: SyncJob, result: SyncResultDTO
    ) -> None:
        """Publish sync completed event.

        Args:
            sync_job: Completed sync job
            result: Sync results
        """
        from app.core.events.types import EventMetadata
        from app.modules.integration.domain.events import DataSyncCompletedEvent

        await self._event_publisher.publish(
            DataSyncCompletedEvent(
                sync_id=sync_job.id,
                integration_id=sync_job.integration_id,
                direction=sync_job.direction.value,
                records_processed=result.processed_records,
                records_failed=result.failed_records,
                duration_seconds=result.duration_seconds,
                metadata=EventMetadata(
                    event_id=UUID.uuid4(),
                    aggregate_id=sync_job.id,
                    aggregate_type="SyncJob",
                    event_type="DataSyncCompletedEvent",
                    event_version=1,
                    occurred_at=datetime.utcnow(),
                ),
            )
        )
