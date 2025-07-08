"""Repository implementation for Notification entity."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.infrastructure.repository import BaseRepository
from app.modules.notification.domain.entities.notification import Notification
from app.modules.notification.domain.enums import DeliveryStatus, NotificationChannel
from app.modules.notification.domain.value_objects import (
    DeliveryStatusValue,
    NotificationContent,
    NotificationPriorityValue,
    RecipientAddress,
)
from app.modules.notification.infrastructure.models.notification import (
    NotificationModel,
)


class NotificationRepository(BaseRepository[Notification, NotificationModel]):
    """Repository for managing notification persistence."""

    def __init__(self, session: AsyncSession):
        """Initialize repository with database session."""
        super().__init__(session, NotificationModel)

    async def find_by_idempotency_key(
        self, idempotency_key: str
    ) -> Notification | None:
        """Find notification by idempotency key.

        Args:
            idempotency_key: Idempotency key to search for

        Returns:
            Notification if found, None otherwise
        """
        stmt = select(self.model_class).where(
            self.model_class.idempotency_key == idempotency_key
        )
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_entity(model) if model else None

    async def find_by_recipient_and_status(
        self,
        recipient_id: UUID,
        statuses: list[DeliveryStatus] | None = None,
        channel: NotificationChannel | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Notification]:
        """Find notifications by recipient and status.

        Args:
            recipient_id: Recipient ID
            statuses: Optional list of statuses to filter by
            channel: Optional channel to filter by
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of notifications
        """
        stmt = select(self.model_class).where(
            self.model_class.recipient_id == recipient_id
        )

        if statuses:
            stmt = stmt.where(self.model_class.current_status.in_(statuses))

        if channel:
            stmt = stmt.where(self.model_class.channel == channel)

        stmt = stmt.order_by(self.model_class.created_at.desc())
        stmt = stmt.limit(limit).offset(offset)

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def find_pending_for_delivery(
        self, channel: NotificationChannel | None = None, limit: int = 100
    ) -> list[Notification]:
        """Find notifications pending for delivery.

        Args:
            channel: Optional channel to filter by
            limit: Maximum number of results

        Returns:
            List of notifications ready for delivery
        """
        now = datetime.utcnow()

        stmt = select(self.model_class).where(
            and_(
                self.model_class.current_status.in_(
                    [DeliveryStatus.PENDING, DeliveryStatus.QUEUED]
                ),
                or_(
                    self.model_class.scheduled_for.is_(None),
                    self.model_class.scheduled_for <= now,
                ),
                or_(
                    self.model_class.expires_at.is_(None),
                    self.model_class.expires_at > now,
                ),
            )
        )

        if channel:
            stmt = stmt.where(self.model_class.channel == channel)

        # Order by priority and creation time
        stmt = stmt.order_by(
            self.model_class.priority.desc(), self.model_class.created_at.asc()
        )
        stmt = stmt.limit(limit)

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def find_for_retry(
        self, channel: NotificationChannel | None = None, limit: int = 100
    ) -> list[Notification]:
        """Find notifications ready for retry.

        Args:
            channel: Optional channel to filter by
            limit: Maximum number of results

        Returns:
            List of notifications ready for retry
        """
        now = datetime.utcnow()

        stmt = select(self.model_class).where(
            and_(
                self.model_class.current_status.in_(
                    [DeliveryStatus.FAILED, DeliveryStatus.BOUNCED]
                ),
                self.model_class.retry_count < self.model_class.max_retries,
                self.model_class.next_retry_at <= now,
                or_(
                    self.model_class.expires_at.is_(None),
                    self.model_class.expires_at > now,
                ),
            )
        )

        if channel:
            stmt = stmt.where(self.model_class.channel == channel)

        stmt = stmt.order_by(
            self.model_class.priority.desc(), self.model_class.next_retry_at.asc()
        )
        stmt = stmt.limit(limit)

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def get_delivery_statistics(
        self,
        start_date: datetime,
        end_date: datetime,
        channel: NotificationChannel | None = None,
        recipient_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Get delivery statistics for a date range.

        Args:
            start_date: Start of date range
            end_date: End of date range
            channel: Optional channel to filter by
            recipient_id: Optional recipient to filter by

        Returns:
            Dictionary with delivery statistics
        """
        base_query = select(
            func.count(self.model_class.id).label("total"),
            func.count(
                func.nullif(
                    self.model_class.current_status == DeliveryStatus.DELIVERED, False
                )
            ).label("delivered"),
            func.count(
                func.nullif(
                    self.model_class.current_status == DeliveryStatus.FAILED, False
                )
            ).label("failed"),
            func.count(
                func.nullif(
                    self.model_class.current_status == DeliveryStatus.BOUNCED, False
                )
            ).label("bounced"),
            func.count(
                func.nullif(
                    self.model_class.current_status == DeliveryStatus.READ, False
                )
            ).label("read"),
            func.avg(
                func.extract(
                    "epoch", self.model_class.delivered_at - self.model_class.sent_at
                )
            ).label("avg_delivery_time_seconds"),
        ).where(
            and_(
                self.model_class.created_at >= start_date,
                self.model_class.created_at <= end_date,
            )
        )

        if channel:
            base_query = base_query.where(self.model_class.channel == channel)

        if recipient_id:
            base_query = base_query.where(self.model_class.recipient_id == recipient_id)

        result = await self.session.execute(base_query)
        stats = result.one()

        return {
            "total": stats.total or 0,
            "delivered": stats.delivered or 0,
            "failed": stats.failed or 0,
            "bounced": stats.bounced or 0,
            "read": stats.read or 0,
            "delivery_rate": (
                (stats.delivered / stats.total * 100) if stats.total > 0 else 0
            ),
            "avg_delivery_time_seconds": float(stats.avg_delivery_time_seconds or 0),
        }

    async def mark_expired_notifications(self) -> int:
        """Mark expired notifications as failed.

        Returns:
            Number of notifications marked as expired
        """
        now = datetime.utcnow()

        stmt = (
            update(self.model_class)
            .where(
                and_(
                    self.model_class.expires_at <= now,
                    ~self.model_class.current_status.in_(
                        [
                            DeliveryStatus.DELIVERED,
                            DeliveryStatus.READ,
                            DeliveryStatus.FAILED,
                            DeliveryStatus.CANCELLED,
                        ]
                    ),
                )
            )
            .values(current_status=DeliveryStatus.FAILED, failed_at=now, updated_at=now)
        )

        result = await self.session.execute(stmt)
        await self.session.commit()

        return result.rowcount

    def _to_entity(self, model: NotificationModel) -> Notification:
        """Convert database model to domain entity.

        Args:
            model: Database model

        Returns:
            Domain entity
        """
        if not model:
            return None

        # Reconstruct value objects
        content = NotificationContent(
            subject=model.subject,
            body=model.body,
            html_body=model.html_body,
            variables=model.variables,
            attachments=model.attachments,
            metadata=model.metadata.get("content_metadata", {})
            if model.metadata
            else {},
        )

        recipient_address = RecipientAddress(
            channel=model.channel,
            address=model.recipient_address,
            display_name=model.recipient_display_name,
        )

        priority = NotificationPriorityValue(
            level=model.priority,
            reason=model.metadata.get("priority_reason") if model.metadata else None,
            expires_at=model.metadata.get("priority_expires_at")
            if model.metadata
            else None,
            escalation_rules=model.metadata.get("escalation_rules")
            if model.metadata
            else None,
        )

        # Create entity
        notification = Notification(
            recipient_id=model.recipient_id,
            channel=model.channel,
            content=content,
            recipient_address=recipient_address,
            template_id=model.template_id,
            priority=priority,
            expires_at=model.expires_at,
            idempotency_key=model.idempotency_key,
            metadata=model.metadata,
            entity_id=model.id,
        )

        # Set timestamps
        notification.created_at = model.created_at
        notification.updated_at = model.updated_at
        notification.scheduled_for = model.scheduled_for
        notification.sent_at = model.sent_at
        notification.delivered_at = model.delivered_at
        notification.read_at = model.read_at
        notification.failed_at = model.failed_at

        # Set provider info
        notification.provider = model.provider
        notification.provider_message_id = model.provider_message_id
        notification.provider_response = model.provider_response

        # Set retry info
        notification.retry_count = model.retry_count
        notification.max_retries = model.max_retries
        notification.next_retry_at = model.next_retry_at

        # Reconstruct status history
        if model.status_history:
            notification.status_history = [
                DeliveryStatusValue(
                    status=DeliveryStatus(item["status"]),
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    details=item.get("details"),
                    provider_message_id=item.get("provider_message_id"),
                    provider_status=item.get("provider_status"),
                    error_code=item.get("error_code"),
                    retry_count=item.get("retry_count", 0),
                )
                for item in model.status_history
            ]

        return notification

    def _to_model(self, entity: Notification) -> NotificationModel:
        """Convert domain entity to database model.

        Args:
            entity: Domain entity

        Returns:
            Database model
        """
        # Serialize status history
        status_history = [
            {
                "status": status.status.value,
                "timestamp": status.timestamp.isoformat(),
                "details": status.details,
                "provider_message_id": status.provider_message_id,
                "provider_status": status.provider_status,
                "error_code": status.error_code,
                "retry_count": status.retry_count,
            }
            for status in entity.status_history
        ]

        # Prepare metadata
        metadata = entity.metadata or {}
        if entity.priority.reason:
            metadata["priority_reason"] = entity.priority.reason
        if entity.priority.expires_at:
            metadata["priority_expires_at"] = entity.priority.expires_at.isoformat()
        if entity.priority.escalation_rules:
            metadata["escalation_rules"] = entity.priority.escalation_rules
        if entity.content.metadata:
            metadata["content_metadata"] = entity.content.metadata

        return NotificationModel(
            id=entity.id,
            recipient_id=entity.recipient_id,
            channel=entity.channel,
            priority=entity.priority.level,
            subject=entity.content.subject,
            body=entity.content.body,
            html_body=entity.content.html_body,
            variables=entity.content.variables,
            attachments=entity.content.attachments,
            recipient_address=entity.recipient_address.address,
            recipient_display_name=entity.recipient_address.display_name,
            template_id=entity.template_id,
            current_status=entity.current_status,
            status_history=status_history,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
            scheduled_for=entity.scheduled_for,
            sent_at=entity.sent_at,
            delivered_at=entity.delivered_at,
            read_at=entity.read_at,
            failed_at=entity.failed_at,
            expires_at=entity.expires_at,
            provider=entity.provider,
            provider_message_id=entity.provider_message_id,
            provider_response=entity.provider_response,
            retry_count=entity.retry_count,
            max_retries=entity.max_retries,
            next_retry_at=entity.next_retry_at,
            idempotency_key=entity.idempotency_key,
            metadata=metadata,
        )
