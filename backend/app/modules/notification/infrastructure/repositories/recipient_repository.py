"""Repository implementation for notification recipients."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.infrastructure.repository import BaseRepository
from app.modules.notification.domain.entities.notification_recipient import (
    NotificationRecipient,
)
from app.modules.notification.domain.enums import NotificationChannel, RecipientStatus
from app.modules.notification.domain.value_objects import RecipientAddress
from app.modules.notification.infrastructure.models.recipient import RecipientModel


class RecipientRepository(BaseRepository[NotificationRecipient, RecipientModel]):
    """Repository for managing notification recipients."""

    def __init__(self, session: AsyncSession):
        """Initialize repository with database session."""
        super().__init__(session, RecipientModel)

    async def find_by_user_and_channel(
        self, user_id: UUID, channel: NotificationChannel
    ) -> list[NotificationRecipient]:
        """Find recipients for a user and channel.

        Args:
            user_id: User ID
            channel: Notification channel

        Returns:
            List of recipients
        """
        stmt = select(self.model_class).where(
            and_(
                self.model_class.user_id == user_id,
                self.model_class.channel == channel,
                self.model_class.status == RecipientStatus.ACTIVE,
            )
        )

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def find_by_address(
        self, channel: NotificationChannel, address: str
    ) -> NotificationRecipient | None:
        """Find recipient by channel and address.

        Args:
            channel: Notification channel
            address: Recipient address

        Returns:
            Recipient if found
        """
        stmt = select(self.model_class).where(
            and_(
                self.model_class.channel == channel, self.model_class.address == address
            )
        )

        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_entity(model) if model else None

    async def find_active_by_user(
        self, user_id: UUID, channel: NotificationChannel | None = None
    ) -> list[NotificationRecipient]:
        """Find all active recipients for a user.

        Args:
            user_id: User ID
            channel: Optional channel filter

        Returns:
            List of active recipients
        """
        stmt = select(self.model_class).where(
            and_(
                self.model_class.user_id == user_id,
                self.model_class.status == RecipientStatus.ACTIVE,
                self.model_class.is_verified is True,
            )
        )

        if channel:
            stmt = stmt.where(self.model_class.channel == channel)

        result = await self.session.execute(stmt)
        models = result.scalars().all()

        return [self._to_entity(model) for model in models]

    async def find_by_verification_token(
        self, token: str
    ) -> NotificationRecipient | None:
        """Find recipient by verification token.

        Args:
            token: Verification token

        Returns:
            Recipient if found
        """
        stmt = select(self.model_class).where(
            self.model_class.verification_token == token
        )

        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_entity(model) if model else None

    async def update_bounce_count(self, recipient_id: UUID, increment: int = 1) -> None:
        """Update recipient bounce count.

        Args:
            recipient_id: Recipient ID
            increment: Amount to increment
        """
        stmt = (
            update(self.model_class)
            .where(self.model_class.id == recipient_id)
            .values(
                bounce_count=self.model_class.bounce_count + increment,
                last_bounce_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        )

        await self.session.execute(stmt)
        await self.session.commit()

    async def update_complaint_count(
        self, recipient_id: UUID, increment: int = 1
    ) -> None:
        """Update recipient complaint count.

        Args:
            recipient_id: Recipient ID
            increment: Amount to increment
        """
        stmt = (
            update(self.model_class)
            .where(self.model_class.id == recipient_id)
            .values(
                complaint_count=self.model_class.complaint_count + increment,
                last_complaint_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        )

        await self.session.execute(stmt)
        await self.session.commit()

    async def mark_recipients_bounced(
        self, addresses: list[str], channel: NotificationChannel
    ) -> int:
        """Mark multiple recipients as bounced.

        Args:
            addresses: List of addresses
            channel: Notification channel

        Returns:
            Number of recipients updated
        """
        stmt = (
            update(self.model_class)
            .where(
                and_(
                    self.model_class.channel == channel,
                    self.model_class.address.in_(addresses),
                )
            )
            .values(status=RecipientStatus.BOUNCED, updated_at=datetime.utcnow())
        )

        result = await self.session.execute(stmt)
        await self.session.commit()

        return result.rowcount

    async def clean_expired_verifications(self) -> int:
        """Clean up expired verification tokens.

        Returns:
            Number of tokens cleaned
        """
        now = datetime.utcnow()

        stmt = (
            update(self.model_class)
            .where(
                and_(
                    self.model_class.is_verified is False,
                    self.model_class.verification_expires_at <= now,
                )
            )
            .values(
                verification_token=None, verification_expires_at=None, updated_at=now
            )
        )

        result = await self.session.execute(stmt)
        await self.session.commit()

        return result.rowcount

    async def get_recipient_statistics(
        self, user_id: UUID, channel: NotificationChannel | None = None
    ) -> dict[str, Any]:
        """Get recipient statistics for a user.

        Args:
            user_id: User ID
            channel: Optional channel filter

        Returns:
            Dictionary with recipient statistics
        """
        base_query = select(
            func.count(self.model_class.id).label("total"),
            func.count(
                func.nullif(self.model_class.status == RecipientStatus.ACTIVE, False)
            ).label("active"),
            func.count(func.nullif(self.model_class.is_verified is True, False)).label(
                "verified"
            ),
            func.count(
                func.nullif(self.model_class.status == RecipientStatus.BOUNCED, False)
            ).label("bounced"),
            func.count(
                func.nullif(
                    self.model_class.status == RecipientStatus.UNSUBSCRIBED, False
                )
            ).label("unsubscribed"),
        ).where(self.model_class.user_id == user_id)

        if channel:
            base_query = base_query.where(self.model_class.channel == channel)

        result = await self.session.execute(base_query)
        stats = result.one()

        return {
            "total": stats.total or 0,
            "active": stats.active or 0,
            "verified": stats.verified or 0,
            "bounced": stats.bounced or 0,
            "unsubscribed": stats.unsubscribed or 0,
        }

    def _to_entity(self, model: RecipientModel) -> NotificationRecipient:
        """Convert database model to domain entity.

        Args:
            model: Database model

        Returns:
            Domain entity
        """
        if not model:
            return None

        # Reconstruct recipient address
        address = RecipientAddress(
            channel=model.channel,
            address=model.address,
            display_name=model.display_name,
        )

        # Create entity
        recipient = NotificationRecipient(
            user_id=model.user_id,
            address=address,
            preferences=model.preferences,
            timezone=model.timezone,
            language=model.language,
            entity_id=model.id,
        )

        # Set timestamps
        recipient.created_at = model.created_at
        recipient.updated_at = model.updated_at

        # Set status
        recipient.status = model.status

        # Set verification info
        recipient.is_verified = model.is_verified
        recipient.verified_at = model.verified_at
        recipient.verification_token = model.verification_token
        recipient.verification_expires_at = model.verification_expires_at

        # Set bounce/complaint info
        recipient.bounce_count = model.bounce_count
        recipient.complaint_count = model.complaint_count
        recipient.last_bounce_at = model.last_bounce_at
        recipient.last_complaint_at = model.last_complaint_at

        # Set usage info
        recipient.last_notification_at = model.last_notification_at
        recipient.notification_count = model.notification_count

        # Set metadata
        if model.metadata:
            recipient.metadata = model.metadata

        return recipient

    def _to_model(self, entity: NotificationRecipient) -> RecipientModel:
        """Convert domain entity to database model.

        Args:
            entity: Domain entity

        Returns:
            Database model
        """
        return RecipientModel(
            id=entity.id,
            user_id=entity.user_id,
            channel=entity.address.channel,
            address=entity.address.address,
            display_name=entity.address.display_name,
            status=entity.status,
            is_verified=entity.is_verified,
            verified_at=entity.verified_at,
            verification_token=entity.verification_token,
            verification_expires_at=entity.verification_expires_at,
            preferences=entity.preferences,
            timezone=entity.timezone,
            language=entity.language,
            bounce_count=entity.bounce_count,
            complaint_count=entity.complaint_count,
            last_bounce_at=entity.last_bounce_at,
            last_complaint_at=entity.last_complaint_at,
            last_notification_at=entity.last_notification_at,
            notification_count=entity.notification_count,
            metadata=getattr(entity, "metadata", None),
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )
