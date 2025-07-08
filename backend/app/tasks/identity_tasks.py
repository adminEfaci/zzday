"""Identity-related background tasks."""
from datetime import datetime, timedelta
from typing import Any

from celery import Task

from app.core.config import settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.core.security import create_password_reset_token
from app.models.audit import AuditLog
from app.models.user import User
from app.services.email import EmailService
from app.services.sms import SMSService
from app.tasks import celery_app

logger = get_logger(__name__)


class IdentityTask(Task):
    """Base class for identity tasks with common functionality."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when task fails."""
        logger.error(f"Identity task {task_id} failed: {exc}")
        # Log to audit system
        self.log_task_failure(task_id, str(exc), args, kwargs)

    def log_task_failure(self, task_id: str, error: str, args: tuple, kwargs: dict):
        """Log task failure to audit system."""
        try:
            db = next(get_db())
            audit_log = AuditLog(
                action="TASK_FAILURE",
                resource_type="IDENTITY_TASK",
                resource_id=task_id,
                details={"error": error, "args": args, "kwargs": kwargs},
                timestamp=datetime.utcnow(),
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            logger.exception(f"Failed to log task failure: {e}")


@celery_app.task(
    bind=True,
    base=IdentityTask,
    name="app.tasks.identity_tasks.send_password_reset_email",
    max_retries=5,
    default_retry_delay=60,
)
def send_password_reset_email(self, user_id: int, email: str) -> dict[str, Any]:
    """Send password reset email to user."""
    try:
        db = next(get_db())
        user = db.query(User).filter(User.id == user_id).first()

        if not user or user.email != email:
            logger.warning(f"Password reset requested for invalid user: {user_id}")
            return {"status": "failed", "reason": "user_not_found"}

        # Generate reset token
        reset_token = create_password_reset_token(user.email)

        # Create reset URL
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"

        # Send email
        email_service = EmailService()
        result = email_service.send_password_reset_email(
            email=user.email, name=user.full_name, reset_url=reset_url
        )

        if result.get("success"):
            # Log successful password reset request
            audit_log = AuditLog(
                user_id=user.id,
                action="PASSWORD_RESET_REQUESTED",
                resource_type="USER",
                resource_id=str(user.id),
                details={"email": email},
                ip_address=None,  # Task doesn't have IP context
                timestamp=datetime.utcnow(),
            )
            db.add(audit_log)
            db.commit()

            logger.info(f"Password reset email sent to user {user_id}")
            return {"status": "success", "message_id": result.get("message_id")}
        raise Exception(f"Email sending failed: {result.get('error')}")

    except Exception as exc:
        logger.exception(f"Failed to send password reset email: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    base=IdentityTask,
    name="app.tasks.identity_tasks.send_mfa_code",
    max_retries=3,
    default_retry_delay=30,
)
def send_mfa_code(self, user_id: int, phone_number: str, code: str) -> dict[str, Any]:
    """Send MFA code via SMS."""
    try:
        db = next(get_db())
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            logger.warning(f"MFA code requested for invalid user: {user_id}")
            return {"status": "failed", "reason": "user_not_found"}

        # Send SMS
        sms_service = SMSService()
        result = sms_service.send_mfa_code(phone_number=phone_number, code=code)

        if result.get("success"):
            # Log MFA code sent
            audit_log = AuditLog(
                user_id=user.id,
                action="MFA_CODE_SENT",
                resource_type="USER",
                resource_id=str(user.id),
                details={"phone_number": phone_number[-4:]},  # Only last 4 digits
                timestamp=datetime.utcnow(),
            )
            db.add(audit_log)
            db.commit()

            logger.info(f"MFA code sent to user {user_id}")
            return {"status": "success", "message_id": result.get("message_id")}
        raise Exception(f"SMS sending failed: {result.get('error')}")

    except Exception as exc:
        logger.exception(f"Failed to send MFA code: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    base=IdentityTask,
    name="app.tasks.identity_tasks.cleanup_expired_sessions",
)
def cleanup_expired_sessions(self) -> dict[str, Any]:
    """Clean up expired user sessions."""
    try:
        next(get_db())

        # Calculate expiry time
        datetime.utcnow() - timedelta(seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)

        # Delete expired sessions (assuming we have a Session model)
        # This is a placeholder - implement based on your session storage
        deleted_count = 0

        logger.info(f"Cleaned up {deleted_count} expired sessions")
        return {"status": "success", "deleted_count": deleted_count}

    except Exception as exc:
        logger.exception(f"Failed to cleanup expired sessions: {exc}")
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True, base=IdentityTask, name="app.tasks.identity_tasks.cleanup_expired_tokens"
)
def cleanup_expired_tokens(self) -> dict[str, Any]:
    """Clean up expired password reset tokens and other tokens."""
    try:
        next(get_db())

        # This would depend on how you store tokens
        # For now, we'll assume tokens are self-contained (JWT)
        # and don't need database cleanup

        logger.info("Token cleanup completed")
        return {"status": "success", "message": "Token cleanup completed"}

    except Exception as exc:
        logger.exception(f"Failed to cleanup expired tokens: {exc}")
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=IdentityTask,
    name="app.tasks.identity_tasks.send_account_verification_email",
    max_retries=5,
    default_retry_delay=60,
)
def send_account_verification_email(self, user_id: int) -> dict[str, Any]:
    """Send account verification email to new user."""
    try:
        db = next(get_db())
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            logger.warning(f"Verification email requested for invalid user: {user_id}")
            return {"status": "failed", "reason": "user_not_found"}

        if user.is_verified:
            logger.info(f"User {user_id} is already verified")
            return {"status": "success", "reason": "already_verified"}

        # Generate verification token
        verification_token = create_password_reset_token(
            user.email
        )  # Reuse token creation

        # Create verification URL
        verification_url = (
            f"{settings.FRONTEND_URL}/verify-account?token={verification_token}"
        )

        # Send email
        email_service = EmailService()
        result = email_service.send_verification_email(
            email=user.email, name=user.full_name, verification_url=verification_url
        )

        if result.get("success"):
            logger.info(f"Verification email sent to user {user_id}")
            return {"status": "success", "message_id": result.get("message_id")}
        raise Exception(f"Email sending failed: {result.get('error')}")

    except Exception as exc:
        logger.exception(f"Failed to send verification email: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    base=IdentityTask,
    name="app.tasks.identity_tasks.send_security_alert",
    max_retries=3,
    default_retry_delay=30,
)
def send_security_alert(
    self, user_id: int, alert_type: str, details: dict[str, Any]
) -> dict[str, Any]:
    """Send security alert to user."""
    try:
        db = next(get_db())
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            logger.warning(f"Security alert for invalid user: {user_id}")
            return {"status": "failed", "reason": "user_not_found"}

        # Send email alert
        email_service = EmailService()
        result = email_service.send_security_alert(
            email=user.email,
            name=user.full_name,
            alert_type=alert_type,
            details=details,
        )

        if result.get("success"):
            # Log security alert sent
            audit_log = AuditLog(
                user_id=user.id,
                action="SECURITY_ALERT_SENT",
                resource_type="USER",
                resource_id=str(user.id),
                details={"alert_type": alert_type, "details": details},
                timestamp=datetime.utcnow(),
            )
            db.add(audit_log)
            db.commit()

            logger.info(f"Security alert sent to user {user_id}: {alert_type}")
            return {"status": "success", "message_id": result.get("message_id")}
        raise Exception(f"Email sending failed: {result.get('error')}")

    except Exception as exc:
        logger.exception(f"Failed to send security alert: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    base=IdentityTask,
    name="app.tasks.identity_tasks.cleanup_failed_login_attempts",
)
def cleanup_failed_login_attempts(self) -> dict[str, Any]:
    """Clean up old failed login attempt records."""
    try:
        next(get_db())

        # Remove failed login attempts older than 24 hours
        datetime.utcnow() - timedelta(hours=24)

        # This would depend on how you track failed login attempts
        # Placeholder implementation
        deleted_count = 0

        logger.info(f"Cleaned up {deleted_count} old failed login attempts")
        return {"status": "success", "deleted_count": deleted_count}

    except Exception as exc:
        logger.exception(f"Failed to cleanup failed login attempts: {exc}")
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=IdentityTask,
    name="app.tasks.identity_tasks.process_user_deactivation",
    max_retries=3,
    default_retry_delay=60,
)
def process_user_deactivation(self, user_id: int, reason: str) -> dict[str, Any]:
    """Process user account deactivation."""
    try:
        db = next(get_db())
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            logger.warning(f"Deactivation requested for invalid user: {user_id}")
            return {"status": "failed", "reason": "user_not_found"}

        # Deactivate user
        user.is_active = False
        user.deactivated_at = datetime.utcnow()
        user.deactivation_reason = reason

        # Log deactivation
        audit_log = AuditLog(
            user_id=user.id,
            action="USER_DEACTIVATED",
            resource_type="USER",
            resource_id=str(user.id),
            details={"reason": reason},
            timestamp=datetime.utcnow(),
        )
        db.add(audit_log)

        # Send notification email
        email_service = EmailService()
        email_service.send_account_deactivation_notice(
            email=user.email, name=user.full_name, reason=reason
        )

        db.commit()

        logger.info(f"User {user_id} deactivated: {reason}")
        return {"status": "success", "user_id": user_id}

    except Exception as exc:
        logger.exception(f"Failed to process user deactivation: {exc}")
        db.rollback()
        raise self.retry(exc=exc)
