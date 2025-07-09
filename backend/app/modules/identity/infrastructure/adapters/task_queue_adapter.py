"""
Task Queue Service Adapter

Production-ready implementation for asynchronous task queue operations.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.infrastructure.task_queue_port import (
    ITaskQueuePort,
)


class TaskQueueAdapter(ITaskQueuePort):
    """Production task queue adapter."""

    def __init__(
        self,
        celery_app=None,
        redis_client=None,
        rabbitmq_client=None,
        task_timeout=300,
        max_retries=3,
    ):
<<<<<<< HEAD
        """Initialize task queue adapter."""
=======
        """Initialize task queue adapter.

        Args:
            celery_app: Celery application instance
            redis_client: Redis client for simple queuing
            rabbitmq_client: RabbitMQ client for messaging
            task_timeout: Task execution timeout in seconds
            max_retries: Maximum number of task retries
        """
>>>>>>> analysis/coordination
        self._celery = celery_app
        self._redis = redis_client
        self._rabbitmq = rabbitmq_client
        self._task_timeout = task_timeout
        self._max_retries = max_retries
<<<<<<< HEAD
        self._task_registry = {}
=======
        self._task_registry = {}  # In-memory task tracking for testing
>>>>>>> analysis/coordination

    async def queue_email_verification(
        self, user_id: UUID, email: str, token: str
    ) -> str:
        """Queue email verification task."""
        try:
            task_id = str(uuid4())
            task_data = {
                "task_id": task_id,
                "task_type": "email_verification",
                "user_id": str(user_id),
                "email": email,
                "token": token,
                "created_at": datetime.now(UTC).isoformat(),
                "retry_count": 0,
                "max_retries": self._max_retries,
                "timeout": self._task_timeout,
            }

<<<<<<< HEAD
=======
            # Queue the task
>>>>>>> analysis/coordination
            await self._enqueue_task("email_verification", task_data)

            logger.info(f"Queued email verification task {task_id} for user {user_id}")
            return task_id

        except Exception as e:
            logger.error(f"Error queuing email verification task: {e}")
            raise

    async def queue_welcome_email(self, user_id: UUID) -> str:
        """Queue welcome email task."""
        try:
            task_id = str(uuid4())
            task_data = {
                "task_id": task_id,
                "task_type": "welcome_email",
                "user_id": str(user_id),
                "created_at": datetime.now(UTC).isoformat(),
                "retry_count": 0,
                "max_retries": self._max_retries,
                "timeout": self._task_timeout,
            }

<<<<<<< HEAD
=======
            # Queue the task
>>>>>>> analysis/coordination
            await self._enqueue_task("welcome_email", task_data)

            logger.info(f"Queued welcome email task {task_id} for user {user_id}")
            return task_id

        except Exception as e:
            logger.error(f"Error queuing welcome email task: {e}")
            raise

    async def queue_password_reset_email(
        self, user_id: UUID, reset_token: str
    ) -> str:
        """Queue password reset email."""
        try:
            task_id = str(uuid4())
            task_data = {
                "task_id": task_id,
                "task_type": "password_reset_email",
                "user_id": str(user_id),
                "reset_token": reset_token,
                "created_at": datetime.now(UTC).isoformat(),
                "retry_count": 0,
                "max_retries": self._max_retries,
                "timeout": self._task_timeout,
            }

<<<<<<< HEAD
=======
            # Queue the task
>>>>>>> analysis/coordination
            await self._enqueue_task("password_reset_email", task_data)

            logger.info(f"Queued password reset email task {task_id} for user {user_id}")
            return task_id

        except Exception as e:
            logger.error(f"Error queuing password reset email task: {e}")
            raise

    async def queue_security_alert(
        self, user_id: UUID, alert_type: str, context: dict[str, Any]
    ) -> str:
        """Queue security alert."""
        try:
            task_id = str(uuid4())
            task_data = {
                "task_id": task_id,
                "task_type": "security_alert",
                "user_id": str(user_id),
                "alert_type": alert_type,
                "context": context,
                "created_at": datetime.now(UTC).isoformat(),
                "retry_count": 0,
                "max_retries": self._max_retries,
                "timeout": self._task_timeout,
<<<<<<< HEAD
                "priority": "high",
            }

=======
                "priority": "high",  # Security alerts are high priority
            }

            # Queue the task with high priority
>>>>>>> analysis/coordination
            await self._enqueue_task("security_alert", task_data, priority="high")

            logger.info(f"Queued security alert task {task_id} for user {user_id}: {alert_type}")
            return task_id

        except Exception as e:
            logger.error(f"Error queuing security alert task: {e}")
            raise

    async def queue_profile_completion_check(self, user_id: UUID) -> str:
        """Queue profile completion check."""
        try:
            task_id = str(uuid4())
            task_data = {
                "task_id": task_id,
                "task_type": "profile_completion_check",
                "user_id": str(user_id),
                "created_at": datetime.now(UTC).isoformat(),
                "retry_count": 0,
                "max_retries": self._max_retries,
                "timeout": self._task_timeout,
<<<<<<< HEAD
                "priority": "low",
            }

=======
                "priority": "low",  # Profile checks are low priority
            }

            # Queue the task
>>>>>>> analysis/coordination
            await self._enqueue_task("profile_completion_check", task_data, priority="low")

            logger.info(f"Queued profile completion check task {task_id} for user {user_id}")
            return task_id

        except Exception as e:
            logger.error(f"Error queuing profile completion check task: {e}")
            raise

    async def queue_avatar_processing(self, user_id: UUID, file_path: str) -> str:
        """Queue avatar processing task."""
        try:
            task_id = str(uuid4())
            task_data = {
                "task_id": task_id,
                "task_type": "avatar_processing",
                "user_id": str(user_id),
                "file_path": file_path,
                "created_at": datetime.now(UTC).isoformat(),
                "retry_count": 0,
                "max_retries": self._max_retries,
<<<<<<< HEAD
                "timeout": self._task_timeout * 2,
                "priority": "medium",
            }

=======
                "timeout": self._task_timeout * 2,  # Longer timeout for image processing
                "priority": "medium",
            }

            # Queue the task
>>>>>>> analysis/coordination
            await self._enqueue_task("avatar_processing", task_data, priority="medium")

            logger.info(f"Queued avatar processing task {task_id} for user {user_id}")
            return task_id

        except Exception as e:
            logger.error(f"Error queuing avatar processing task: {e}")
            raise

    async def get_task_status(self, task_id: str) -> dict[str, Any]:
        """Get task execution status."""
        try:
<<<<<<< HEAD
=======
            # Check Celery first
>>>>>>> analysis/coordination
            if self._celery:
                result = await self._get_celery_task_status(task_id)
                if result:
                    return result

<<<<<<< HEAD
=======
            # Check Redis
>>>>>>> analysis/coordination
            if self._redis:
                result = await self._get_redis_task_status(task_id)
                if result:
                    return result

<<<<<<< HEAD
            if task_id in self._task_registry:
                return self._task_registry[task_id]

=======
            # Check local registry
            if task_id in self._task_registry:
                return self._task_registry[task_id]

            # Task not found
>>>>>>> analysis/coordination
            return {
                "task_id": task_id,
                "status": "not_found",
                "error": "Task not found in any queue",
                "checked_at": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting task status for {task_id}: {e}")
            return {
                "task_id": task_id,
                "status": "error",
                "error": str(e),
                "checked_at": datetime.now(UTC).isoformat(),
            }

    async def _enqueue_task(self, task_type: str, task_data: dict[str, Any], priority: str = "medium") -> None:
        """Enqueue task using available queue backend."""
        try:
            if self._celery:
                await self._enqueue_celery_task(task_type, task_data, priority)
            elif self._rabbitmq:
                await self._enqueue_rabbitmq_task(task_type, task_data, priority)
            elif self._redis:
                await self._enqueue_redis_task(task_type, task_data, priority)
            else:
<<<<<<< HEAD
=======
                # Fallback to in-memory registry for testing
>>>>>>> analysis/coordination
                await self._enqueue_local_task(task_type, task_data)

        except Exception as e:
            logger.error(f"Error enqueuing task {task_type}: {e}")
            raise

    async def _enqueue_celery_task(self, task_type: str, task_data: dict[str, Any], priority: str) -> None:
        """Enqueue task using Celery."""
        try:
<<<<<<< HEAD
=======
            # Map task types to Celery task names
>>>>>>> analysis/coordination
            celery_task_names = {
                "email_verification": "identity.tasks.send_verification_email",
                "welcome_email": "identity.tasks.send_welcome_email",
                "password_reset_email": "identity.tasks.send_password_reset_email",
                "security_alert": "identity.tasks.send_security_alert",
                "profile_completion_check": "identity.tasks.check_profile_completion",
                "avatar_processing": "identity.tasks.process_avatar",
            }

            task_name = celery_task_names.get(task_type)
            if not task_name:
                raise ValueError(f"Unknown task type: {task_type}")

<<<<<<< HEAD
            priority_map = {"high": 9, "medium": 5, "low": 1}
            celery_priority = priority_map.get(priority, 5)

=======
            # Set priority
            priority_map = {"high": 9, "medium": 5, "low": 1}
            celery_priority = priority_map.get(priority, 5)

            # Apply the task
>>>>>>> analysis/coordination
            result = self._celery.send_task(
                task_name,
                args=[task_data],
                task_id=task_data["task_id"],
                priority=celery_priority,
                countdown=0,
                expires=datetime.now(UTC) + timedelta(seconds=task_data["timeout"]),
            )

            logger.info(f"Enqueued Celery task {task_type} with ID {task_data['task_id']}")

        except Exception as e:
            logger.error(f"Error enqueuing Celery task {task_type}: {e}")
            raise

    async def _enqueue_rabbitmq_task(self, task_type: str, task_data: dict[str, Any], priority: str) -> None:
        """Enqueue task using RabbitMQ."""
        try:
<<<<<<< HEAD
            queue_name = f"identity.tasks.{priority}"
            
=======
            # Determine queue name based on priority
            queue_name = f"identity.tasks.{priority}"
            
            # Create message
>>>>>>> analysis/coordination
            message = {
                "task_type": task_type,
                "task_data": task_data,
                "routing_key": task_type,
                "priority": priority,
            }

<<<<<<< HEAD
=======
            # Publish message
>>>>>>> analysis/coordination
            await self._rabbitmq.publish(
                message=json.dumps(message),
                routing_key=queue_name,
                properties={
                    "message_id": task_data["task_id"],
                    "priority": {"high": 9, "medium": 5, "low": 1}.get(priority, 5),
<<<<<<< HEAD
                    "expiration": str(task_data["timeout"] * 1000),
=======
                    "expiration": str(task_data["timeout"] * 1000),  # milliseconds
>>>>>>> analysis/coordination
                },
            )

            logger.info(f"Enqueued RabbitMQ task {task_type} with ID {task_data['task_id']}")

        except Exception as e:
            logger.error(f"Error enqueuing RabbitMQ task {task_type}: {e}")
            raise

    async def _enqueue_redis_task(self, task_type: str, task_data: dict[str, Any], priority: str) -> None:
        """Enqueue task using Redis."""
        try:
<<<<<<< HEAD
            queue_key = f"identity:tasks:{priority}"
            
            await self._redis.lpush(queue_key, json.dumps(task_data))
            
=======
            # Create queue key based on priority
            queue_key = f"identity:tasks:{priority}"
            
            # Add task to Redis queue
            await self._redis.lpush(queue_key, json.dumps(task_data))
            
            # Store task status
>>>>>>> analysis/coordination
            status_key = f"identity:task_status:{task_data['task_id']}"
            await self._redis.setex(
                status_key,
                task_data["timeout"],
                json.dumps({
                    "task_id": task_data["task_id"],
                    "status": "queued",
                    "task_type": task_type,
                    "priority": priority,
                    "queued_at": datetime.now(UTC).isoformat(),
                }),
            )

            logger.info(f"Enqueued Redis task {task_type} with ID {task_data['task_id']}")

        except Exception as e:
            logger.error(f"Error enqueuing Redis task {task_type}: {e}")
            raise

    async def _enqueue_local_task(self, task_type: str, task_data: dict[str, Any]) -> None:
        """Enqueue task in local registry (for testing)."""
        try:
            task_id = task_data["task_id"]
            
<<<<<<< HEAD
=======
            # Store in local registry
>>>>>>> analysis/coordination
            self._task_registry[task_id] = {
                "task_id": task_id,
                "status": "queued",
                "task_type": task_type,
                "task_data": task_data,
                "queued_at": datetime.now(UTC).isoformat(),
                "updated_at": datetime.now(UTC).isoformat(),
            }

            logger.info(f"Enqueued local task {task_type} with ID {task_id}")

        except Exception as e:
            logger.error(f"Error enqueuing local task {task_type}: {e}")
            raise

    async def _get_celery_task_status(self, task_id: str) -> dict[str, Any] | None:
        """Get task status from Celery."""
        try:
            result = self._celery.AsyncResult(task_id)
            
            status_map = {
                "PENDING": "queued",
                "STARTED": "running",
                "SUCCESS": "completed",
                "FAILURE": "failed",
                "RETRY": "retrying",
                "REVOKED": "cancelled",
            }

            celery_status = result.status
            status = status_map.get(celery_status, "unknown")

            task_info = {
                "task_id": task_id,
                "status": status,
                "backend": "celery",
                "result": result.result if status == "completed" else None,
                "error": str(result.result) if status == "failed" else None,
                "checked_at": datetime.now(UTC).isoformat(),
            }

<<<<<<< HEAD
=======
            # Add additional info if available
>>>>>>> analysis/coordination
            if hasattr(result, "info") and result.info:
                task_info["info"] = result.info

            return task_info

        except Exception as e:
            logger.error(f"Error getting Celery task status for {task_id}: {e}")
            return None

    async def _get_redis_task_status(self, task_id: str) -> dict[str, Any] | None:
        """Get task status from Redis."""
        try:
            status_key = f"identity:task_status:{task_id}"
            status_data = await self._redis.get(status_key)
            
            if status_data:
                status_info = json.loads(status_data)
                status_info["backend"] = "redis"
                status_info["checked_at"] = datetime.now(UTC).isoformat()
                return status_info
            
            return None

        except Exception as e:
            logger.error(f"Error getting Redis task status for {task_id}: {e}")
<<<<<<< HEAD
            return None
=======
            return None

    async def queue_custom_task(
        self, 
        task_type: str, 
        task_data: dict[str, Any], 
        priority: str = "medium",
        timeout: int | None = None
    ) -> str:
        """Queue a custom task (extension method)."""
        try:
            task_id = str(uuid4())
            
            full_task_data = {
                "task_id": task_id,
                "task_type": task_type,
                "created_at": datetime.now(UTC).isoformat(),
                "retry_count": 0,
                "max_retries": self._max_retries,
                "timeout": timeout or self._task_timeout,
                "priority": priority,
                **task_data,
            }

            # Queue the task
            await self._enqueue_task(task_type, full_task_data, priority)

            logger.info(f"Queued custom task {task_type} with ID {task_id}")
            return task_id

        except Exception as e:
            logger.error(f"Error queuing custom task {task_type}: {e}")
            raise

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a queued or running task."""
        try:
            cancelled = False
            
            # Try to cancel in Celery
            if self._celery:
                result = self._celery.AsyncResult(task_id)
                result.revoke(terminate=True)
                cancelled = True
                logger.info(f"Cancelled Celery task {task_id}")
            
            # Update status in Redis
            if self._redis:
                status_key = f"identity:task_status:{task_id}"
                await self._redis.setex(
                    status_key,
                    3600,  # Keep cancelled status for 1 hour
                    json.dumps({
                        "task_id": task_id,
                        "status": "cancelled",
                        "cancelled_at": datetime.now(UTC).isoformat(),
                    }),
                )
            
            # Update local registry
            if task_id in self._task_registry:
                self._task_registry[task_id]["status"] = "cancelled"
                self._task_registry[task_id]["cancelled_at"] = datetime.now(UTC).isoformat()
                cancelled = True
            
            return cancelled

        except Exception as e:
            logger.error(f"Error cancelling task {task_id}: {e}")
            return False

    async def get_queue_stats(self) -> dict[str, Any]:
        """Get queue statistics."""
        try:
            stats = {
                "backend": self._get_backend_type(),
                "queues": {},
                "collected_at": datetime.now(UTC).isoformat(),
            }

            if self._redis:
                # Get Redis queue lengths
                for priority in ["high", "medium", "low"]:
                    queue_key = f"identity:tasks:{priority}"
                    queue_length = await self._redis.llen(queue_key)
                    stats["queues"][priority] = {"length": queue_length}

            elif self._celery:
                # Get Celery queue stats (if available)
                try:
                    inspect = self._celery.control.inspect()
                    active_tasks = inspect.active()
                    stats["active_tasks"] = len(active_tasks) if active_tasks else 0
                except:
                    stats["active_tasks"] = 0

            return stats

        except Exception as e:
            logger.error(f"Error getting queue stats: {e}")
            return {
                "backend": self._get_backend_type(),
                "error": str(e),
                "collected_at": datetime.now(UTC).isoformat(),
            }

    def _get_backend_type(self) -> str:
        """Get the current backend type."""
        if self._celery:
            return "celery"
        if self._rabbitmq:
            return "rabbitmq"
        if self._redis:
            return "redis"
        return "local"
>>>>>>> analysis/coordination
