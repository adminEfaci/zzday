"""Queue service for asynchronous notification processing."""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import aioredis
from celery import Celery, Task
from kombu import Exchange, Queue

from app.core.infrastructure.config import settings
from app.modules.notification.domain.enums import (
    NotificationChannel,
    NotificationPriority,
)


class NotificationTask(Task):
    """Custom Celery task for notification processing."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure."""
        notification_id = kwargs.get("notification_id")
        if notification_id:
            # Log failure
            print(f"Notification {notification_id} failed: {exc}")

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Handle task retry."""
        notification_id = kwargs.get("notification_id")
        retry_count = self.request.retries
        if notification_id:
            # Log retry
            print(f"Notification {notification_id} retry #{retry_count}: {exc}")

    def on_success(self, retval, task_id, args, kwargs):
        """Handle task success."""
        notification_id = kwargs.get("notification_id")
        if notification_id:
            # Log success
            print(f"Notification {notification_id} processed successfully")


class QueueService:
    """Service for managing notification queues."""

    def __init__(
        self,
        redis_url: str | None = None,
        celery_app: Celery | None = None,
        max_workers: int = 10,
    ):
        """Initialize queue service.

        Args:
            redis_url: Redis connection URL
            celery_app: Celery application instance
            max_workers: Maximum number of worker threads
        """
        self.redis_url = redis_url or settings.REDIS_URL
        self.max_workers = max_workers
        self._redis_client: aioredis.Redis | None = None
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

        # Initialize Celery
        if celery_app:
            self.celery = celery_app
        else:
            self.celery = self._create_celery_app()

        # Queue names by priority and channel
        self._queue_names = {
            NotificationPriority.URGENT: "notifications.urgent",
            NotificationPriority.HIGH: "notifications.high",
            NotificationPriority.NORMAL: "notifications.normal",
            NotificationPriority.LOW: "notifications.low",
        }

        # Channel-specific queues
        self._channel_queues = {
            NotificationChannel.EMAIL: "notifications.email",
            NotificationChannel.SMS: "notifications.sms",
            NotificationChannel.PUSH: "notifications.push",
            NotificationChannel.IN_APP: "notifications.in_app",
        }

    def _create_celery_app(self) -> Celery:
        """Create and configure Celery application."""
        app = Celery("notifications")

        # Configure Celery
        app.conf.update(
            broker_url=self.redis_url,
            result_backend=self.redis_url,
            task_serializer="json",
            accept_content=["json"],
            result_serializer="json",
            timezone="UTC",
            enable_utc=True,
            task_routes={
                "notifications.send_notification": {
                    "queue": "notifications.normal",
                    "routing_key": "notification.send",
                },
                "notifications.process_batch": {
                    "queue": "notifications.batch",
                    "routing_key": "notification.batch",
                },
            },
            task_queues=(
                Queue(
                    "notifications.urgent",
                    Exchange("notifications"),
                    routing_key="notification.urgent",
                ),
                Queue(
                    "notifications.high",
                    Exchange("notifications"),
                    routing_key="notification.high",
                ),
                Queue(
                    "notifications.normal",
                    Exchange("notifications"),
                    routing_key="notification.normal",
                ),
                Queue(
                    "notifications.low",
                    Exchange("notifications"),
                    routing_key="notification.low",
                ),
                Queue(
                    "notifications.batch",
                    Exchange("notifications"),
                    routing_key="notification.batch",
                ),
                Queue(
                    "notifications.email",
                    Exchange("notifications"),
                    routing_key="notification.email",
                ),
                Queue(
                    "notifications.sms",
                    Exchange("notifications"),
                    routing_key="notification.sms",
                ),
                Queue(
                    "notifications.push",
                    Exchange("notifications"),
                    routing_key="notification.push",
                ),
                Queue(
                    "notifications.in_app",
                    Exchange("notifications"),
                    routing_key="notification.in_app",
                ),
            ),
            task_annotations={
                "notifications.send_notification": {
                    "rate_limit": "100/s",
                    "time_limit": 300,  # 5 minutes
                    "soft_time_limit": 240,  # 4 minutes
                }
            },
        )

        return app

    async def connect(self) -> None:
        """Connect to Redis."""
        if not self._redis_client:
            self._redis_client = await aioredis.create_redis_pool(self.redis_url)

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._redis_client:
            self._redis_client.close()
            await self._redis_client.wait_closed()
            self._redis_client = None

    async def enqueue_notification(
        self,
        notification_id: UUID,
        channel: NotificationChannel,
        priority: NotificationPriority,
        scheduled_for: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Enqueue a notification for processing.

        Args:
            notification_id: Notification ID
            channel: Notification channel
            priority: Notification priority
            scheduled_for: When to process the notification
            metadata: Additional metadata

        Returns:
            Task ID
        """
        # Prepare task data
        task_data = {
            "notification_id": str(notification_id),
            "channel": channel.value,
            "priority": priority.value,
            "metadata": metadata or {},
        }

        # Determine queue
        queue_name = self._get_queue_name(priority, channel)

        # Calculate delay
        eta = None
        if scheduled_for and scheduled_for > datetime.utcnow():
            eta = scheduled_for

        # Enqueue task
        task = self.celery.send_task(
            "notifications.send_notification",
            kwargs=task_data,
            queue=queue_name,
            eta=eta,
            priority=priority.processing_weight(),
            retry=True,
            retry_policy={
                "max_retries": priority.max_retry_attempts(),
                "interval_start": 0,
                "interval_step": priority.retry_delay_seconds(),
                "interval_max": 3600,  # Max 1 hour between retries
            },
        )

        # Store task mapping in Redis
        await self._store_task_mapping(notification_id, task.id)

        return task.id

    async def enqueue_batch(
        self,
        batch_id: UUID,
        notification_ids: list[UUID],
        channel: NotificationChannel,
        scheduled_for: datetime | None = None,
        batch_size: int = 100,
    ) -> list[str]:
        """Enqueue a batch of notifications.

        Args:
            batch_id: Batch ID
            notification_ids: List of notification IDs
            channel: Notification channel
            scheduled_for: When to process the batch
            batch_size: Size of each sub-batch

        Returns:
            List of task IDs
        """
        task_ids = []

        # Split into sub-batches
        for i in range(0, len(notification_ids), batch_size):
            sub_batch = notification_ids[i : i + batch_size]

            task_data = {
                "batch_id": str(batch_id),
                "notification_ids": [str(nid) for nid in sub_batch],
                "channel": channel.value,
                "batch_index": i // batch_size,
            }

            # Enqueue batch task
            task = self.celery.send_task(
                "notifications.process_batch",
                kwargs=task_data,
                queue="notifications.batch",
                eta=scheduled_for,
                retry=True,
                retry_policy={
                    "max_retries": 3,
                    "interval_start": 60,
                    "interval_step": 120,
                    "interval_max": 600,
                },
            )

            task_ids.append(task.id)

        return task_ids

    async def cancel_notification(self, notification_id: UUID) -> bool:
        """Cancel a queued notification.

        Args:
            notification_id: Notification ID

        Returns:
            True if cancelled successfully
        """
        # Get task ID from Redis
        task_id = await self._get_task_id(notification_id)
        if not task_id:
            return False

        # Revoke task
        self.celery.control.revoke(task_id, terminate=True)

        # Remove mapping
        await self._remove_task_mapping(notification_id)

        return True

    async def get_queue_stats(self) -> dict[str, Any]:
        """Get queue statistics.

        Returns:
            Dictionary with queue statistics
        """
        stats = {}

        # Get queue lengths
        if self._redis_client:
            for priority, queue_name in self._queue_names.items():
                key = f"celery:{queue_name}"
                length = await self._redis_client.llen(key)
                stats[f"{priority.value}_queue_length"] = length

            for channel, queue_name in self._channel_queues.items():
                key = f"celery:{queue_name}"
                length = await self._redis_client.llen(key)
                stats[f"{channel.value}_queue_length"] = length

        # Get active tasks
        inspect = self.celery.control.inspect()
        active = inspect.active()
        if active:
            total_active = sum(len(tasks) for tasks in active.values())
            stats["active_tasks"] = total_active

        # Get scheduled tasks
        scheduled = inspect.scheduled()
        if scheduled:
            total_scheduled = sum(len(tasks) for tasks in scheduled.values())
            stats["scheduled_tasks"] = total_scheduled

        return stats

    async def retry_failed_notifications(
        self,
        since: datetime,
        channel: NotificationChannel | None = None,
        limit: int = 100,
    ) -> int:
        """Retry failed notifications.

        Args:
            since: Retry notifications failed since this time
            channel: Optional channel filter
            limit: Maximum number to retry

        Returns:
            Number of notifications retried
        """
        # This would typically query failed notifications from the database
        # and re-enqueue them
        return 0

        # Implementation would go here

    def _get_queue_name(
        self, priority: NotificationPriority, channel: NotificationChannel
    ) -> str:
        """Get queue name based on priority and channel.

        Args:
            priority: Notification priority
            channel: Notification channel

        Returns:
            Queue name
        """
        # Use priority queue for urgent notifications
        if priority == NotificationPriority.URGENT:
            return self._queue_names[priority]

        # Use channel-specific queue if available
        if channel in self._channel_queues:
            return self._channel_queues[channel]

        # Default to priority queue
        return self._queue_names[priority]

    async def _store_task_mapping(self, notification_id: UUID, task_id: str) -> None:
        """Store notification to task ID mapping.

        Args:
            notification_id: Notification ID
            task_id: Celery task ID
        """
        if self._redis_client:
            key = f"notification:task:{notification_id}"
            await self._redis_client.setex(
                key, timedelta(days=7), task_id  # Expire after 7 days
            )

    async def _get_task_id(self, notification_id: UUID) -> str | None:
        """Get task ID for a notification.

        Args:
            notification_id: Notification ID

        Returns:
            Task ID if found
        """
        if self._redis_client:
            key = f"notification:task:{notification_id}"
            task_id = await self._redis_client.get(key)
            return task_id.decode() if task_id else None
        return None

    async def _remove_task_mapping(self, notification_id: UUID) -> None:
        """Remove notification to task ID mapping.

        Args:
            notification_id: Notification ID
        """
        if self._redis_client:
            key = f"notification:task:{notification_id}"
            await self._redis_client.delete(key)

    def register_task(self, name: str, func: Callable, **options) -> Task:
        """Register a Celery task.

        Args:
            name: Task name
            func: Task function
            **options: Task options

        Returns:
            Registered task
        """
        return self.celery.task(name=name, base=NotificationTask, **options)(func)
