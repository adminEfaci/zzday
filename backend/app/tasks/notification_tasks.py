"""Notification-related background tasks."""
from datetime import datetime, timedelta
from typing import Any

from celery import Task
from sqlalchemy import and_, or_

from app.core.database import get_db
from app.core.logging import get_logger
from app.models.notification import (
    Notification,
    NotificationTemplate,
    ScheduledNotification,
)
from app.models.user import User
from app.services.email import EmailService
from app.services.push import PushNotificationService
from app.services.sms import SMSService
from app.tasks import celery_app

logger = get_logger(__name__)


class NotificationTask(Task):
    """Base class for notification tasks with common functionality."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when task fails."""
        logger.error(f"Notification task {task_id} failed: {exc}")

        # Update notification status if applicable
        notification_id = kwargs.get("notification_id")
        if notification_id:
            try:
                db = next(get_db())
                notification = (
                    db.query(Notification)
                    .filter(Notification.id == notification_id)
                    .first()
                )
                if notification:
                    notification.status = "failed"
                    notification.error_message = str(exc)
                    notification.updated_at = datetime.utcnow()
                    db.commit()
            except Exception as e:
                logger.exception(f"Failed to update notification status: {e}")

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Called when task is retried."""
        logger.warning(f"Notification task {task_id} retrying: {exc}")

        notification_id = kwargs.get("notification_id")
        if notification_id:
            try:
                db = next(get_db())
                notification = (
                    db.query(Notification)
                    .filter(Notification.id == notification_id)
                    .first()
                )
                if notification:
                    notification.retry_count = (notification.retry_count or 0) + 1
                    notification.updated_at = datetime.utcnow()
                    db.commit()
            except Exception as e:
                logger.exception(f"Failed to update retry count: {e}")


@celery_app.task(
    bind=True,
    base=NotificationTask,
    name="app.tasks.notification_tasks.send_email",
    max_retries=5,
    default_retry_delay=120,
)
def send_email(
    self,
    notification_id: int,
    recipient_email: str,
    subject: str,
    content: str,
    html_content: str | None = None,
    template_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send email notification."""
    try:
        db = next(get_db())
        notification = (
            db.query(Notification).filter(Notification.id == notification_id).first()
        )

        if not notification:
            logger.error(f"Notification {notification_id} not found")
            return {"status": "failed", "reason": "notification_not_found"}

        # Update status to sending
        notification.status = "sending"
        notification.sent_at = datetime.utcnow()
        db.commit()

        # Send email
        email_service = EmailService()
        result = email_service.send_notification_email(
            email=recipient_email,
            subject=subject,
            content=content,
            html_content=html_content,
            template_data=template_data,
        )

        if result.get("success"):
            # Update notification status
            notification.status = "sent"
            notification.external_id = result.get("message_id")
            notification.delivered_at = datetime.utcnow()
            db.commit()

            logger.info(f"Email notification {notification_id} sent successfully")
            return {
                "status": "success",
                "notification_id": notification_id,
                "message_id": result.get("message_id"),
            }
        raise Exception(f"Email sending failed: {result.get('error')}")

    except Exception as exc:
        logger.exception(f"Failed to send email notification {notification_id}: {exc}")

        # Update notification status
        try:
            db = next(get_db())
            notification = (
                db.query(Notification)
                .filter(Notification.id == notification_id)
                .first()
            )
            if notification:
                notification.status = "failed"
                notification.error_message = str(exc)
                db.commit()
        except Exception:
            pass

        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    base=NotificationTask,
    name="app.tasks.notification_tasks.send_sms",
    max_retries=3,
    default_retry_delay=60,
)
def send_sms(
    self, notification_id: int, recipient_phone: str, message: str
) -> dict[str, Any]:
    """Send SMS notification."""
    try:
        db = next(get_db())
        notification = (
            db.query(Notification).filter(Notification.id == notification_id).first()
        )

        if not notification:
            logger.error(f"Notification {notification_id} not found")
            return {"status": "failed", "reason": "notification_not_found"}

        # Update status to sending
        notification.status = "sending"
        notification.sent_at = datetime.utcnow()
        db.commit()

        # Send SMS
        sms_service = SMSService()
        result = sms_service.send_notification_sms(
            phone_number=recipient_phone, message=message
        )

        if result.get("success"):
            # Update notification status
            notification.status = "sent"
            notification.external_id = result.get("message_id")
            notification.delivered_at = datetime.utcnow()
            db.commit()

            logger.info(f"SMS notification {notification_id} sent successfully")
            return {
                "status": "success",
                "notification_id": notification_id,
                "message_id": result.get("message_id"),
            }
        raise Exception(f"SMS sending failed: {result.get('error')}")

    except Exception as exc:
        logger.exception(f"Failed to send SMS notification {notification_id}: {exc}")

        # Update notification status
        try:
            db = next(get_db())
            notification = (
                db.query(Notification)
                .filter(Notification.id == notification_id)
                .first()
            )
            if notification:
                notification.status = "failed"
                notification.error_message = str(exc)
                db.commit()
        except Exception:
            pass

        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    base=NotificationTask,
    name="app.tasks.notification_tasks.send_push_notification",
    max_retries=3,
    default_retry_delay=30,
)
def send_push_notification(
    self,
    notification_id: int,
    user_id: int,
    title: str,
    body: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send push notification."""
    try:
        db = next(get_db())
        notification = (
            db.query(Notification).filter(Notification.id == notification_id).first()
        )

        if not notification:
            logger.error(f"Notification {notification_id} not found")
            return {"status": "failed", "reason": "notification_not_found"}

        # Update status to sending
        notification.status = "sending"
        notification.sent_at = datetime.utcnow()
        db.commit()

        # Send push notification
        push_service = PushNotificationService()
        result = push_service.send_notification(
            user_id=user_id, title=title, body=body, data=data
        )

        if result.get("success"):
            # Update notification status
            notification.status = "sent"
            notification.external_id = result.get("message_id")
            notification.delivered_at = datetime.utcnow()
            db.commit()

            logger.info(f"Push notification {notification_id} sent successfully")
            return {
                "status": "success",
                "notification_id": notification_id,
                "message_id": result.get("message_id"),
            }
        raise Exception(f"Push notification failed: {result.get('error')}")

    except Exception as exc:
        logger.exception(f"Failed to send push notification {notification_id}: {exc}")

        # Update notification status
        try:
            db = next(get_db())
            notification = (
                db.query(Notification)
                .filter(Notification.id == notification_id)
                .first()
            )
            if notification:
                notification.status = "failed"
                notification.error_message = str(exc)
                db.commit()
        except Exception:
            pass

        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    base=NotificationTask,
    name="app.tasks.notification_tasks.process_scheduled",
)
def process_scheduled_notifications(self) -> dict[str, Any]:
    """Process scheduled notifications that are due."""
    try:
        db = next(get_db())

        # Get scheduled notifications that are due
        now = datetime.utcnow()
        scheduled_notifications = (
            db.query(ScheduledNotification)
            .filter(
                and_(
                    ScheduledNotification.scheduled_time <= now,
                    ScheduledNotification.status == "pending",
                )
            )
            .all()
        )

        processed_count = 0
        failed_count = 0

        for scheduled in scheduled_notifications:
            try:
                # Create notification record
                notification = Notification(
                    user_id=scheduled.user_id,
                    type=scheduled.notification_type,
                    title=scheduled.title,
                    content=scheduled.content,
                    channel=scheduled.channel,
                    status="pending",
                    metadata=scheduled.metadata,
                    created_at=datetime.utcnow(),
                )
                db.add(notification)
                db.flush()  # Get the ID

                # Send based on channel
                if scheduled.channel == "email":
                    user = db.query(User).filter(User.id == scheduled.user_id).first()
                    if user and user.email:
                        send_email.delay(
                            notification_id=notification.id,
                            recipient_email=user.email,
                            subject=scheduled.title,
                            content=scheduled.content,
                            html_content=scheduled.metadata.get("html_content"),
                            template_data=scheduled.metadata.get("template_data"),
                        )

                elif scheduled.channel == "sms":
                    user = db.query(User).filter(User.id == scheduled.user_id).first()
                    if user and user.phone_number:
                        send_sms.delay(
                            notification_id=notification.id,
                            recipient_phone=user.phone_number,
                            message=scheduled.content,
                        )

                elif scheduled.channel == "push":
                    send_push_notification.delay(
                        notification_id=notification.id,
                        user_id=scheduled.user_id,
                        title=scheduled.title,
                        body=scheduled.content,
                        data=scheduled.metadata.get("push_data"),
                    )

                # Update scheduled notification status
                scheduled.status = "processed"
                scheduled.processed_at = datetime.utcnow()
                processed_count += 1

            except Exception as e:
                logger.exception(
                    f"Failed to process scheduled notification {scheduled.id}: {e}"
                )
                scheduled.status = "failed"
                scheduled.error_message = str(e)
                failed_count += 1

        db.commit()

        logger.info(
            f"Processed {processed_count} scheduled notifications, {failed_count} failed"
        )
        return {
            "status": "success",
            "processed_count": processed_count,
            "failed_count": failed_count,
        }

    except Exception as exc:
        logger.exception(f"Failed to process scheduled notifications: {exc}")
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=NotificationTask,
    name="app.tasks.notification_tasks.cleanup_old_notifications",
)
def cleanup_old_notifications(self, days_to_keep: int = 30) -> dict[str, Any]:
    """Clean up old notification records."""
    try:
        db = next(get_db())

        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

        # Delete old notifications
        deleted_notifications = (
            db.query(Notification)
            .filter(
                and_(
                    Notification.created_at < cutoff_date,
                    Notification.status.in_(["sent", "failed", "cancelled"]),
                )
            )
            .delete()
        )

        # Delete old scheduled notifications
        deleted_scheduled = (
            db.query(ScheduledNotification)
            .filter(
                and_(
                    ScheduledNotification.created_at < cutoff_date,
                    ScheduledNotification.status.in_(
                        ["processed", "failed", "cancelled"]
                    ),
                )
            )
            .delete()
        )

        db.commit()

        logger.info(
            f"Cleaned up {deleted_notifications} notifications and {deleted_scheduled} scheduled notifications"
        )
        return {
            "status": "success",
            "deleted_notifications": deleted_notifications,
            "deleted_scheduled": deleted_scheduled,
        }

    except Exception as exc:
        logger.exception(f"Failed to cleanup old notifications: {exc}")
        db.rollback()
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=NotificationTask,
    name="app.tasks.notification_tasks.send_bulk_notification",
    max_retries=3,
    default_retry_delay=300,
)
def send_bulk_notification(
    self,
    user_ids: list[int],
    notification_type: str,
    title: str,
    content: str,
    channel: str,
    template_id: int | None = None,
    template_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send bulk notification to multiple users."""
    try:
        db = next(get_db())

        # Get template if provided
        template = None
        if template_id:
            template = (
                db.query(NotificationTemplate)
                .filter(NotificationTemplate.id == template_id)
                .first()
            )

        sent_count = 0
        failed_count = 0

        for user_id in user_ids:
            try:
                user = db.query(User).filter(User.id == user_id).first()
                if not user or not user.is_active:
                    failed_count += 1
                    continue

                # Create notification record
                notification = Notification(
                    user_id=user_id,
                    type=notification_type,
                    title=title,
                    content=content,
                    channel=channel,
                    status="pending",
                    template_id=template_id,
                    metadata=template_data or {},
                    created_at=datetime.utcnow(),
                )
                db.add(notification)
                db.flush()

                # Send notification based on channel
                if channel == "email" and user.email:
                    final_content = content
                    final_title = title

                    # Apply template if provided
                    if template and template_data:
                        final_content = template.render_content(template_data)
                        final_title = template.render_subject(template_data)

                    send_email.delay(
                        notification_id=notification.id,
                        recipient_email=user.email,
                        subject=final_title,
                        content=final_content,
                        html_content=template.html_template if template else None,
                        template_data=template_data,
                    )
                    sent_count += 1

                elif channel == "sms" and user.phone_number:
                    send_sms.delay(
                        notification_id=notification.id,
                        recipient_phone=user.phone_number,
                        message=content,
                    )
                    sent_count += 1

                elif channel == "push":
                    send_push_notification.delay(
                        notification_id=notification.id,
                        user_id=user_id,
                        title=title,
                        body=content,
                        data=template_data,
                    )
                    sent_count += 1

                else:
                    failed_count += 1
                    notification.status = "failed"
                    notification.error_message = f"No {channel} address available"

            except Exception as e:
                logger.exception(
                    f"Failed to send bulk notification to user {user_id}: {e}"
                )
                failed_count += 1

        db.commit()

        logger.info(
            f"Bulk notification sent: {sent_count} successful, {failed_count} failed"
        )
        return {
            "status": "success",
            "sent_count": sent_count,
            "failed_count": failed_count,
            "total_users": len(user_ids),
        }

    except Exception as exc:
        logger.exception(f"Failed to send bulk notification: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    base=NotificationTask,
    name="app.tasks.notification_tasks.retry_failed_notifications",
)
def retry_failed_notifications(self, max_age_hours: int = 24) -> dict[str, Any]:
    """Retry failed notifications that are eligible for retry."""
    try:
        db = next(get_db())

        # Get failed notifications that are within retry window
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)

        failed_notifications = (
            db.query(Notification)
            .filter(
                and_(
                    Notification.status == "failed",
                    Notification.created_at >= cutoff_time,
                    or_(Notification.retry_count is None, Notification.retry_count < 3),
                )
            )
            .all()
        )

        retried_count = 0

        for notification in failed_notifications:
            try:
                user = db.query(User).filter(User.id == notification.user_id).first()
                if not user or not user.is_active:
                    continue

                # Reset notification status
                notification.status = "pending"
                notification.error_message = None
                notification.retry_count = (notification.retry_count or 0) + 1

                # Retry based on channel
                if notification.channel == "email" and user.email:
                    send_email.delay(
                        notification_id=notification.id,
                        recipient_email=user.email,
                        subject=notification.title,
                        content=notification.content,
                        html_content=notification.metadata.get("html_content"),
                        template_data=notification.metadata.get("template_data"),
                    )
                    retried_count += 1

                elif notification.channel == "sms" and user.phone_number:
                    send_sms.delay(
                        notification_id=notification.id,
                        recipient_phone=user.phone_number,
                        message=notification.content,
                    )
                    retried_count += 1

                elif notification.channel == "push":
                    send_push_notification.delay(
                        notification_id=notification.id,
                        user_id=user.id,
                        title=notification.title,
                        body=notification.content,
                        data=notification.metadata.get("push_data"),
                    )
                    retried_count += 1

            except Exception as e:
                logger.exception(f"Failed to retry notification {notification.id}: {e}")

        db.commit()

        logger.info(f"Retried {retried_count} failed notifications")
        return {
            "status": "success",
            "retried_count": retried_count,
            "total_failed": len(failed_notifications),
        }

    except Exception as exc:
        logger.exception(f"Failed to retry notifications: {exc}")
        return {"status": "failed", "error": str(exc)}
