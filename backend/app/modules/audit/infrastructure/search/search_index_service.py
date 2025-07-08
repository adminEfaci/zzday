"""Search index service for managing audit search indices.

This module provides high-level management of search indices including
creation, maintenance, and optimization.
"""

import asyncio
import contextlib
from datetime import datetime, timedelta
from typing import Any

from app.core.errors import InfrastructureError
from app.core.logging import get_logger
from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.infrastructure.search.elasticsearch_adapter import (
    ElasticsearchAdapter,
)

logger = get_logger(__name__)


class SearchIndexService:
    """
    Service for managing search indices.

    Provides high-level operations for index lifecycle management,
    data synchronization, and optimization.
    """

    def __init__(self, elasticsearch_adapter: ElasticsearchAdapter):
        """
        Initialize search index service.

        Args:
            elasticsearch_adapter: Elasticsearch adapter instance
        """
        self.es_adapter = elasticsearch_adapter
        self._indexing_queue: list[AuditEntry] = []
        self._queue_lock = asyncio.Lock()
        self._background_task: asyncio.Task | None = None

    async def initialize(self) -> None:
        """Initialize search indices and start background tasks."""
        try:
            # Initialize Elasticsearch
            await self.es_adapter.initialize()

            # Start background indexing task
            self._background_task = asyncio.create_task(self._background_indexer())

            logger.info("Search index service initialized")

        except Exception as e:
            logger.exception("Failed to initialize search index service", error=str(e))
            raise InfrastructureError(f"Search index initialization failed: {e!s}")

    async def shutdown(self) -> None:
        """Shutdown the service and cleanup resources."""
        try:
            # Cancel background task
            if self._background_task:
                self._background_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._background_task

            # Process remaining items in queue
            if self._indexing_queue:
                await self._flush_indexing_queue()

            # Close Elasticsearch connection
            await self.es_adapter.close()

            logger.info("Search index service shut down")

        except Exception as e:
            logger.exception("Error during search index service shutdown", error=str(e))

    async def index_entry(self, entry: AuditEntry) -> None:
        """
        Index a single audit entry.

        Uses queuing for better performance with automatic batching.
        """
        async with self._queue_lock:
            self._indexing_queue.append(entry)

            # Flush immediately if queue is large
            if len(self._indexing_queue) >= 100:
                await self._flush_indexing_queue()

    async def index_entries_bulk(self, entries: list[AuditEntry]) -> None:
        """
        Index multiple entries in bulk.

        For large batches, uses direct bulk indexing for efficiency.
        """
        if len(entries) > 1000:
            # Large batch - index directly
            success, failures = await self.es_adapter.bulk_index_entries(entries)

            if failures > 0:
                logger.warning(
                    "Some entries failed to index",
                    total=len(entries),
                    failures=failures,
                )
        else:
            # Small batch - use queue
            async with self._queue_lock:
                self._indexing_queue.extend(entries)

                if len(self._indexing_queue) >= 100:
                    await self._flush_indexing_queue()

    async def reindex_time_range(
        self, start_time: datetime, end_time: datetime, batch_callback: Any
    ) -> dict[str, Any]:
        """
        Reindex entries for a specific time range.

        Args:
            start_time: Start of time range
            end_time: End of time range
            batch_callback: Async function to fetch entries in batches

        Returns:
            Reindexing statistics
        """
        logger.info(
            "Starting reindexing",
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
        )

        stats = {
            "total_processed": 0,
            "success_count": 0,
            "failure_count": 0,
            "start_time": datetime.utcnow(),
            "end_time": None,
        }

        try:
            current_time = start_time
            batch_size = timedelta(hours=1)  # Process in hourly batches

            while current_time < end_time:
                batch_end = min(current_time + batch_size, end_time)

                # Fetch entries for this time window
                entries = await batch_callback(current_time, batch_end)

                if entries:
                    # Index the batch
                    success, failures = await self.es_adapter.bulk_index_entries(
                        entries
                    )

                    stats["total_processed"] += len(entries)
                    stats["success_count"] += success
                    stats["failure_count"] += failures

                    logger.debug(
                        "Reindexed batch",
                        time_range=f"{current_time} to {batch_end}",
                        count=len(entries),
                    )

                current_time = batch_end

                # Small delay to avoid overwhelming the system
                await asyncio.sleep(0.1)

            stats["end_time"] = datetime.utcnow()
            stats["duration_seconds"] = (
                stats["end_time"] - stats["start_time"]
            ).total_seconds()

            logger.info("Reindexing completed", stats=stats)

            return stats

        except Exception as e:
            stats["end_time"] = datetime.utcnow()
            stats["error"] = str(e)

            logger.exception("Reindexing failed", error=str(e), stats=stats)

            raise InfrastructureError(f"Reindexing failed: {e!s}")

    async def optimize_indices(self, older_than_days: int = 7) -> dict[str, Any]:
        """
        Optimize older indices for better search performance.

        Args:
            older_than_days: Optimize indices older than this many days

        Returns:
            Optimization statistics
        """
        logger.info("Starting index optimization", older_than_days=older_than_days)

        stats = {
            "indices_optimized": 0,
            "start_time": datetime.utcnow(),
            "end_time": None,
        }

        try:
            # Get list of indices
            cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)

            # Get all audit indices
            indices_response = await self.es_adapter.client.indices.get_alias(
                name=self.es_adapter.read_alias
            )

            for index_name in indices_response:
                # Parse date from index name
                try:
                    # Expected format: audit_entries-YYYY.MM
                    date_part = index_name.split("-")[-1]
                    year, month = date_part.split(".")
                    index_date = datetime(int(year), int(month), 1)

                    if index_date < cutoff_date:
                        # Optimize this index
                        await self.es_adapter.client.indices.forcemerge(
                            index=index_name, max_num_segments=1
                        )

                        # Update settings for read-only
                        await self.es_adapter.client.indices.put_settings(
                            index=index_name,
                            body={
                                "index": {
                                    "blocks.write": True,
                                    "refresh_interval": "-1",
                                }
                            },
                        )

                        stats["indices_optimized"] += 1

                        logger.debug("Optimized index", index_name=index_name)

                except (ValueError, IndexError):
                    # Skip indices that don't match expected format
                    continue

            stats["end_time"] = datetime.utcnow()
            stats["duration_seconds"] = (
                stats["end_time"] - stats["start_time"]
            ).total_seconds()

            logger.info("Index optimization completed", stats=stats)

            return stats

        except Exception as e:
            stats["end_time"] = datetime.utcnow()
            stats["error"] = str(e)

            logger.exception("Index optimization failed", error=str(e), stats=stats)

            raise InfrastructureError(f"Index optimization failed: {e!s}")

    async def cleanup_old_indices(self, retention_days: int) -> int:
        """
        Clean up indices older than retention period.

        Args:
            retention_days: Keep indices for this many days

        Returns:
            Number of indices deleted
        """
        logger.info("Starting index cleanup", retention_days=retention_days)

        deleted_count = 0

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            # Get all audit indices
            indices_response = await self.es_adapter.client.indices.get_alias(
                name=self.es_adapter.read_alias
            )

            for index_name in indices_response:
                # Parse date from index name
                try:
                    date_part = index_name.split("-")[-1]
                    year, month = date_part.split(".")
                    index_date = datetime(int(year), int(month), 1)

                    if index_date < cutoff_date:
                        # Delete this index
                        await self.es_adapter.client.indices.delete(index=index_name)
                        deleted_count += 1

                        logger.info("Deleted old index", index_name=index_name)

                except (ValueError, IndexError):
                    continue

            logger.info("Index cleanup completed", deleted_count=deleted_count)

            return deleted_count

        except Exception as e:
            logger.exception("Index cleanup failed", error=str(e))
            raise InfrastructureError(f"Index cleanup failed: {e!s}")

    async def get_index_statistics(self) -> dict[str, Any]:
        """Get statistics about search indices."""
        try:
            # Get index stats
            stats_response = await self.es_adapter.client.indices.stats(
                index=f"{self.es_adapter.index_prefix}-*"
            )

            total_stats = stats_response["_all"]["total"]

            # Get individual index information
            indices_info = []
            for index_name, index_stats in stats_response["indices"].items():
                indices_info.append(
                    {
                        "name": index_name,
                        "document_count": index_stats["total"]["docs"]["count"],
                        "size_bytes": index_stats["total"]["store"]["size_in_bytes"],
                        "size_mb": index_stats["total"]["store"]["size_in_bytes"]
                        / (1024 * 1024),
                    }
                )

            # Sort by name (which includes date)
            indices_info.sort(key=lambda x: x["name"])

            return {
                "total_indices": len(indices_info),
                "total_documents": total_stats["docs"]["count"],
                "total_size_bytes": total_stats["store"]["size_in_bytes"],
                "total_size_gb": total_stats["store"]["size_in_bytes"]
                / (1024 * 1024 * 1024),
                "indices": indices_info,
                "queue_size": len(self._indexing_queue),
            }

        except Exception as e:
            logger.exception("Failed to get index statistics", error=str(e))
            raise InfrastructureError(f"Failed to get statistics: {e!s}")

    async def _background_indexer(self) -> None:
        """Background task to process indexing queue."""
        logger.info("Background indexer started")

        try:
            while True:
                # Wait a bit to batch entries
                await asyncio.sleep(5)

                # Flush the queue
                if self._indexing_queue:
                    await self._flush_indexing_queue()

        except asyncio.CancelledError:
            logger.info("Background indexer stopped")
            raise
        except Exception as e:
            logger.exception("Background indexer error", error=str(e))

    async def _flush_indexing_queue(self) -> None:
        """Flush the indexing queue."""
        async with self._queue_lock:
            if not self._indexing_queue:
                return

            entries = self._indexing_queue.copy()
            self._indexing_queue.clear()

        # Index the entries
        try:
            success, failures = await self.es_adapter.bulk_index_entries(entries)

            if failures > 0:
                logger.warning(
                    "Some queued entries failed to index",
                    total=len(entries),
                    failures=failures,
                )

        except Exception as e:
            logger.exception(
                "Failed to flush indexing queue", count=len(entries), error=str(e)
            )

            # Re-add entries to queue on failure
            async with self._queue_lock:
                self._indexing_queue.extend(entries)


__all__ = ["SearchIndexService"]
