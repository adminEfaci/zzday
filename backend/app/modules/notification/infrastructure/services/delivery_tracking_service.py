"""Delivery tracking service for monitoring notification delivery."""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import aioredis
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.notification.domain.enums import DeliveryStatus, NotificationChannel
from app.modules.notification.infrastructure.models.delivery_log import DeliveryLogModel


class DeliveryTrackingService:
    """Service for tracking and monitoring notification delivery."""

    def __init__(
        self, session: AsyncSession, redis_client: aioredis.Redis | None = None
    ):
        """Initialize delivery tracking service.

        Args:
            session: Database session
            redis_client: Optional Redis client for real-time metrics
        """
        self.session = session
        self.redis_client = redis_client

        # Metric keys
        self.METRIC_KEYS = {
            "sent": "delivery:sent",
            "delivered": "delivery:delivered",
            "failed": "delivery:failed",
            "bounced": "delivery:bounced",
            "read": "delivery:read",
        }

    async def log_delivery_attempt(
        self,
        notification_id: UUID,
        channel: NotificationChannel,
        provider: str,
        status: DeliveryStatus,
        provider_message_id: str | None = None,
        request_data: dict[str, Any] | None = None,
        response_data: dict[str, Any] | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        duration_ms: int | None = None,
        cost_amount: int | None = None,
        cost_currency: str | None = None,
    ) -> UUID:
        """Log a delivery attempt.

        Args:
            notification_id: Notification ID
            channel: Delivery channel
            provider: Provider name
            status: Delivery status
            provider_message_id: Provider's message ID
            request_data: Sanitized request data
            response_data: Provider response
            error_code: Error code if failed
            error_message: Error message if failed
            duration_ms: Request duration in milliseconds
            cost_amount: Cost in cents
            cost_currency: Cost currency

        Returns:
            Delivery log ID
        """
        # Create delivery log
        log = DeliveryLogModel(
            notification_id=notification_id,
            channel=channel,
            provider=provider,
            provider_message_id=provider_message_id,
            status=status,
            status_details=error_message,
            request_data=self._sanitize_data(request_data) if request_data else None,
            response_data=self._sanitize_data(response_data) if response_data else None,
            error_code=error_code,
            error_message=error_message,
            is_retryable=status
            not in [DeliveryStatus.DELIVERED, DeliveryStatus.BOUNCED],
            request_duration_ms=duration_ms,
            cost_amount=cost_amount,
            cost_currency=cost_currency,
        )

        self.session.add(log)
        await self.session.commit()

        # Update real-time metrics
        await self._update_metrics(channel, provider, status, cost_amount)

        return log.id

    async def update_delivery_status(
        self,
        provider_message_id: str,
        new_status: DeliveryStatus,
        webhook_data: dict[str, Any] | None = None,
    ) -> bool:
        """Update delivery status from webhook.

        Args:
            provider_message_id: Provider's message ID
            new_status: New delivery status
            webhook_data: Webhook payload

        Returns:
            True if updated successfully
        """
        # Find delivery log
        stmt = (
            select(DeliveryLogModel)
            .where(DeliveryLogModel.provider_message_id == provider_message_id)
            .order_by(DeliveryLogModel.created_at.desc())
            .limit(1)
        )

        result = await self.session.execute(stmt)
        log = result.scalar_one_or_none()

        if not log:
            return False

        # Create new log entry for status update
        new_log = DeliveryLogModel(
            notification_id=log.notification_id,
            channel=log.channel,
            provider=log.provider,
            provider_message_id=provider_message_id,
            status=new_status,
            status_details="Status updated via webhook",
            webhook_received_at=datetime.utcnow(),
            webhook_data=self._sanitize_data(webhook_data) if webhook_data else None,
        )

        self.session.add(new_log)
        await self.session.commit()

        # Update metrics
        await self._update_metrics(log.channel, log.provider, new_status)

        return True

    async def get_delivery_history(
        self, notification_id: UUID, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Get delivery history for a notification.

        Args:
            notification_id: Notification ID
            limit: Maximum number of logs

        Returns:
            List of delivery logs
        """
        stmt = (
            select(DeliveryLogModel)
            .where(DeliveryLogModel.notification_id == notification_id)
            .order_by(DeliveryLogModel.created_at.desc())
            .limit(limit)
        )

        result = await self.session.execute(stmt)
        logs = result.scalars().all()

        return [log.to_dict() for log in logs]

    async def get_provider_statistics(
        self,
        provider: str,
        channel: NotificationChannel | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Get delivery statistics for a provider.

        Args:
            provider: Provider name
            channel: Optional channel filter
            start_date: Start of date range
            end_date: End of date range

        Returns:
            Provider statistics
        """
        # Base query
        query = select(
            func.count(DeliveryLogModel.id).label("total"),
            func.count(
                func.nullif(DeliveryLogModel.status == DeliveryStatus.DELIVERED, False)
            ).label("delivered"),
            func.count(
                func.nullif(DeliveryLogModel.status == DeliveryStatus.FAILED, False)
            ).label("failed"),
            func.count(
                func.nullif(DeliveryLogModel.status == DeliveryStatus.BOUNCED, False)
            ).label("bounced"),
            func.avg(DeliveryLogModel.request_duration_ms).label("avg_duration_ms"),
            func.sum(DeliveryLogModel.cost_amount).label("total_cost_cents"),
        ).where(DeliveryLogModel.provider == provider)

        # Apply filters
        if channel:
            query = query.where(DeliveryLogModel.channel == channel)

        if start_date:
            query = query.where(DeliveryLogModel.created_at >= start_date)

        if end_date:
            query = query.where(DeliveryLogModel.created_at <= end_date)

        result = await self.session.execute(query)
        stats = result.one()

        # Get error breakdown
        error_query = (
            select(
                DeliveryLogModel.error_code,
                func.count(DeliveryLogModel.id).label("count"),
            )
            .where(
                and_(
                    DeliveryLogModel.provider == provider,
                    DeliveryLogModel.error_code.isnot(None),
                )
            )
            .group_by(DeliveryLogModel.error_code)
            .limit(10)
        )

        if channel:
            error_query = error_query.where(DeliveryLogModel.channel == channel)

        error_result = await self.session.execute(error_query)
        error_breakdown = {row.error_code: row.count for row in error_result}

        return {
            "provider": provider,
            "channel": channel.value if channel else "all",
            "total_attempts": stats.total or 0,
            "delivered": stats.delivered or 0,
            "failed": stats.failed or 0,
            "bounced": stats.bounced or 0,
            "delivery_rate": (
                (stats.delivered / stats.total * 100)
                if stats.total and stats.total > 0
                else 0
            ),
            "avg_duration_ms": float(stats.avg_duration_ms or 0),
            "total_cost_cents": stats.total_cost_cents or 0,
            "error_breakdown": error_breakdown,
        }

    async def get_real_time_metrics(
        self,
        channel: NotificationChannel | None = None,
        provider: str | None = None,
        window_minutes: int = 60,
    ) -> dict[str, Any]:
        """Get real-time delivery metrics.

        Args:
            channel: Optional channel filter
            provider: Optional provider filter
            window_minutes: Time window in minutes

        Returns:
            Real-time metrics
        """
        if not self.redis_client:
            # Fallback to database query
            return await self._get_db_metrics(channel, provider, window_minutes)

        metrics = {
            "window_minutes": window_minutes,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Get metrics from Redis
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=window_minutes)

        for status_name, key_prefix in self.METRIC_KEYS.items():
            count = 0

            if channel:
                key = f"{key_prefix}:{channel.value}"
                if provider:
                    key = f"{key}:{provider}"

                count = await self._get_redis_count(key, window_start)
            else:
                # Aggregate all channels
                for ch in NotificationChannel:
                    key = f"{key_prefix}:{ch.value}"
                    if provider:
                        key = f"{key}:{provider}"

                    count += await self._get_redis_count(key, window_start)

            metrics[status_name] = count

        # Calculate rates
        metrics["delivery_rate"] = (
            (metrics["delivered"] / metrics["sent"] * 100)
            if metrics.get("sent", 0) > 0
            else 0
        )

        return metrics

    async def _update_metrics(
        self,
        channel: NotificationChannel,
        provider: str,
        status: DeliveryStatus,
        cost_amount: int | None = None,
    ) -> None:
        """Update real-time metrics in Redis.

        Args:
            channel: Notification channel
            provider: Provider name
            status: Delivery status
            cost_amount: Cost in cents
        """
        if not self.redis_client:
            return

        now = datetime.utcnow()
        timestamp = now.timestamp()

        # Map status to metric key
        status_map = {
            DeliveryStatus.SENT: "sent",
            DeliveryStatus.DELIVERED: "delivered",
            DeliveryStatus.FAILED: "failed",
            DeliveryStatus.BOUNCED: "bounced",
            DeliveryStatus.READ: "read",
        }

        metric_name = status_map.get(status)
        if not metric_name:
            return

        # Update counters
        key = f"{self.METRIC_KEYS[metric_name]}:{channel.value}:{provider}"

        # Add to time series
        await self.redis_client.zadd(key, {f"{timestamp}": timestamp})

        # Clean old entries (keep 24 hours)
        cutoff = (now - timedelta(hours=24)).timestamp()
        await self.redis_client.zremrangebyscore(key, 0, cutoff)

        # Update cost metrics if provided
        if cost_amount:
            cost_key = f"delivery:cost:{channel.value}:{provider}"
            await self.redis_client.hincrby(
                cost_key, now.strftime("%Y-%m-%d"), cost_amount
            )

    async def _get_redis_count(self, key: str, start_time: datetime) -> int:
        """Get count from Redis time series.

        Args:
            key: Redis key
            start_time: Start time for counting

        Returns:
            Count of entries since start_time
        """
        if not self.redis_client:
            return 0

        start_timestamp = start_time.timestamp()
        return await self.redis_client.zcount(key, start_timestamp, "+inf")

    async def _get_db_metrics(
        self,
        channel: NotificationChannel | None,
        provider: str | None,
        window_minutes: int,
    ) -> dict[str, Any]:
        """Get metrics from database.

        Args:
            channel: Optional channel filter
            provider: Optional provider filter
            window_minutes: Time window in minutes

        Returns:
            Metrics from database
        """
        start_time = datetime.utcnow() - timedelta(minutes=window_minutes)

        # Build query
        query = (
            select(
                DeliveryLogModel.status, func.count(DeliveryLogModel.id).label("count")
            )
            .where(DeliveryLogModel.created_at >= start_time)
            .group_by(DeliveryLogModel.status)
        )

        if channel:
            query = query.where(DeliveryLogModel.channel == channel)

        if provider:
            query = query.where(DeliveryLogModel.provider == provider)

        result = await self.session.execute(query)

        metrics = {
            "window_minutes": window_minutes,
            "timestamp": datetime.utcnow().isoformat(),
            "sent": 0,
            "delivered": 0,
            "failed": 0,
            "bounced": 0,
            "read": 0,
        }

        status_map = {
            DeliveryStatus.SENT: "sent",
            DeliveryStatus.DELIVERED: "delivered",
            DeliveryStatus.FAILED: "failed",
            DeliveryStatus.BOUNCED: "bounced",
            DeliveryStatus.READ: "read",
        }

        for row in result:
            metric_name = status_map.get(row.status)
            if metric_name:
                metrics[metric_name] = row.count

        return metrics

    def _sanitize_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Sanitize sensitive data before logging.

        Args:
            data: Data to sanitize

        Returns:
            Sanitized data
        """
        if not data:
            return data

        sanitized = data.copy()
        sensitive_fields = [
            "password",
            "token",
            "secret",
            "api_key",
            "auth",
            "authorization",
            "credential",
            "private",
        ]

        def sanitize_dict(d: dict) -> dict:
            for key in list(d.keys()):
                if any(field in key.lower() for field in sensitive_fields):
                    d[key] = "[REDACTED]"
                elif isinstance(d[key], dict):
                    d[key] = sanitize_dict(d[key])
                elif isinstance(d[key], list):
                    d[key] = [
                        sanitize_dict(item) if isinstance(item, dict) else item
                        for item in d[key]
                    ]
            return d

        return sanitize_dict(sanitized)
