"""
Notification Event Handlers

Handles user notifications for various identity events including
email notifications, push notifications, SMS alerts, and in-app notifications.
"""

import asyncio
from typing import Any
from uuid import UUID

from app.core.logging import get_logger

from .base import (
    EventHandlerBase,
    HandlerExecutionContext,
    HandlerPriority,
    HandlerResult,
    event_handler,
)

logger = get_logger(__name__)


@event_handler(
    event_types=[
        # User lifecycle notifications
        "UserCreated", "UserActivated", "UserSuspended", "UserDeactivated",
        # Authentication notifications
        "LoginSuccessful", "LoginFailed", "AccountLockedOut", "AccountUnlocked",
        # Security notifications
        "PasswordChanged", "PasswordResetRequested", "MFAEnabled", "MFADisabled",
        # Profile notifications
        "EmailVerified", "ProfileUpdated", "DeviceRegistered",
        # Security alerts
        "SecurityAlertRaised", "SuspiciousActivityDetected",
    ],
    priority=HandlerPriority.NORMAL,
    category="notifications",
    timeout_seconds=45.0,
    tags=["notifications", "communication", "user_experience"]
)
class NotificationHandler(EventHandlerBase):
    """
    Handler for user notifications across all communication channels.
    
    Manages notifications for:
    - Welcome and onboarding messages
    - Security alerts and warnings
    - Account status changes
    - Authentication events
    - Profile and settings updates
    - Compliance and policy notifications
    
    Supports multiple notification channels:
    - Email notifications
    - Push notifications (mobile/web)
    - SMS alerts (for critical events)
    - In-app notifications
    - Webhook notifications (for integrations)
    """
    
    async def handle(self, event, context: HandlerExecutionContext) -> HandlerResult:
        """Handle notification events."""
        try:
            event_type = event.__class__.__name__
            notifications_sent = []
            
            # Determine notification strategy based on event type
            notification_config = self._get_notification_config(event_type, event)
            
            # Send notifications based on configuration
            for channel, settings in notification_config.items():
                if settings.get("enabled", False):
                    try:
                        await self._send_notification(channel, event, settings)
                        notifications_sent.append(f"{channel}_{settings.get('template', 'default')}")
                    except Exception:
                        logger.exception(
                            f"Failed to send {channel} notification for {event_type}",
                            channel=channel,
                            event_type=event_type
                        )
                        # Continue with other channels even if one fails
            
            # Update notification preferences if applicable
            if hasattr(event, 'user_id') and event.user_id:
                await self._update_notification_history(event.user_id, event_type, notifications_sent)
            
            # Handle notification analytics
            await self._track_notification_analytics(event_type, notifications_sent)
            
            logger.info(
                f"Notifications processed for {event_type}",
                event_type=event_type,
                event_id=str(event.event_id),
                notifications_sent=notifications_sent,
                user_id=str(event.user_id) if hasattr(event, 'user_id') and event.user_id else None
            )
            
            return HandlerResult(
                success=True,
                handler_id=self.metadata.handler_id,
                execution_id=context.execution_id,
                started_at=context.started_at,
                result_data={
                    "event_type": event_type,
                    "notifications_sent": notifications_sent,
                    "channels_used": list(notification_config.keys()),
                    "total_notifications": len(notifications_sent)
                }
            )
            
        except Exception as e:
            logger.exception(
                f"Failed to process notifications for {event.__class__.__name__}",
                event_type=event.__class__.__name__,
                event_id=str(event.event_id)
            )
            
            return HandlerResult(
                success=False,
                handler_id=self.metadata.handler_id,
                execution_id=context.execution_id,
                started_at=context.started_at,
                error=e,
                error_message=str(e),
                error_type=type(e).__name__
            )
    
    def _get_notification_config(self, event_type: str, event) -> dict[str, dict[str, Any]]:
        """Get notification configuration for event type."""
        # Configuration is defined per event type below
        # base_config serves as template for default values
        
        # Configure based on event type
        if event_type == "UserCreated":
            return {
                "email": {
                    "enabled": True,
                    "template": "welcome_email",
                    "priority": "high",
                    "data": {
                        "user_name": getattr(event, 'name', ''),
                        "email": getattr(event, 'email', ''),
                        "registration_method": getattr(event, 'registration_method', 'email')
                    }
                },
                "in_app": {
                    "enabled": True,
                    "template": "welcome_message",
                    "priority": "normal"
                }
            }
        
        if event_type == "LoginSuccessful":
            # Only notify for unusual or high-risk logins
            risk_score = getattr(event, 'risk_score', 0.0)
            trusted_device = getattr(event, 'trusted_device', True)
            
            if risk_score > 0.3 or not trusted_device:
                return {
                    "email": {
                        "enabled": True,
                        "template": "login_alert",
                        "priority": "high",
                        "data": {
                            "ip_address": getattr(event, 'ip_address', ''),
                            "location": "Unknown",  # TODO: Resolve IP to location
                            "device_info": getattr(event, 'user_agent', ''),
                            "login_time": event.occurred_at.isoformat(),
                            "risk_score": risk_score
                        }
                    },
                    "push": {
                        "enabled": True,
                        "template": "login_notification",
                        "priority": "high"
                    }
                }
        
        elif event_type == "PasswordChanged":
            return {
                "email": {
                    "enabled": True,
                    "template": "password_changed",
                    "priority": "high",
                    "data": {
                        "change_time": event.occurred_at.isoformat(),
                        "forced_change": getattr(event, 'force_password_change', False)
                    }
                },
                "push": {
                    "enabled": True,
                    "template": "security_update",
                    "priority": "high"
                },
                "in_app": {
                    "enabled": True,
                    "template": "password_changed_confirmation",
                    "priority": "normal"
                }
            }
        
        elif event_type == "UserSuspended":
            return {
                "email": {
                    "enabled": True,
                    "template": "account_suspended",
                    "priority": "critical",
                    "data": {
                        "reason": getattr(event, 'reason', ''),
                        "suspension_time": event.occurred_at.isoformat(),
                        "expires_at": (
                            event.suspension_expires_at.isoformat()
                            if event.suspension_expires_at else None
                        ),
                        "automatic": getattr(event, 'automatic_suspension', False)
                    }
                },
                "sms": {
                    "enabled": True,
                    "template": "account_suspended_sms",
                    "priority": "critical"
                },
                "push": {
                    "enabled": True,
                    "template": "account_suspended_push",
                    "priority": "critical"
                }
            }
        
        elif event_type == "SecurityAlertRaised":
            return {
                "email": {
                    "enabled": True,
                    "template": "security_alert",
                    "priority": "critical",
                    "data": {
                        "alert_type": getattr(event, 'alert_type', ''),
                        "risk_level": getattr(event, 'risk_level', ''),
                        "description": getattr(event, 'description', ''),
                        "source_ip": getattr(event, 'source_ip', ''),
                        "alert_time": event.occurred_at.isoformat()
                    }
                },
                "sms": {
                    "enabled": True,
                    "template": "security_alert_sms",
                    "priority": "critical"
                },
                "push": {
                    "enabled": True,
                    "template": "security_alert_push",
                    "priority": "critical"
                }
            }
        
        elif event_type == "MFAEnabled":
            return {
                "email": {
                    "enabled": True,
                    "template": "mfa_enabled",
                    "priority": "normal",
                    "data": {
                        "device_type": getattr(event, 'device_type', ''),
                        "device_name": getattr(event, 'device_name', ''),
                        "enabled_time": event.occurred_at.isoformat(),
                        "backup_codes": getattr(event, 'backup_codes_generated', False)
                    }
                },
                "in_app": {
                    "enabled": True,
                    "template": "mfa_enabled_confirmation",
                    "priority": "normal"
                }
            }
        
        elif event_type == "AccountLockedOut":
            return {
                "email": {
                    "enabled": True,
                    "template": "account_locked",
                    "priority": "high",
                    "data": {
                        "failed_attempts": getattr(event, 'failed_attempt_count', 0),
                        "lockout_duration": getattr(event, 'lockout_duration_minutes', 0),
                        "unlock_time": (
                            event.unlock_at.isoformat()
                            if event.unlock_at else None
                        ),
                        "last_attempt_ip": getattr(event, 'last_failed_ip', '')
                    }
                },
                "sms": {
                    "enabled": True,
                    "template": "account_locked_sms",
                    "priority": "high"
                }
            }
        
        # Return empty config for events that don't need notifications
        return {}
    
    async def _send_notification(
        self, 
        channel: str, 
        event, 
        settings: dict[str, Any]
    ) -> None:
        """Send notification via specified channel."""
        if channel == "email":
            await self._send_email_notification(event, settings)
        elif channel == "push":
            await self._send_push_notification(event, settings)
        elif channel == "sms":
            await self._send_sms_notification(event, settings)
        elif channel == "in_app":
            await self._send_in_app_notification(event, settings)
        elif channel == "webhook":
            await self._send_webhook_notification(event, settings)
    
    async def _send_email_notification(self, event, settings: dict[str, Any]) -> None:
        """Send email notification."""
        # TODO: Integrate with email service (SendGrid, AWS SES, etc.)
        await asyncio.sleep(0.1)  # Simulate email sending
        
        template = settings.get("template", "default")
        priority = settings.get("priority", "normal")
        
        logger.info(
            "Email notification sent",
            template=template,
            priority=priority,
            event_type=event.__class__.__name__,
            user_id=str(event.user_id) if hasattr(event, 'user_id') and event.user_id else None
        )
    
    async def _send_push_notification(self, event, settings: dict[str, Any]) -> None:
        """Send push notification."""
        # TODO: Integrate with push notification service (FCM, APNs)
        await asyncio.sleep(0.05)  # Simulate push sending
        
        template = settings.get("template", "default")
        priority = settings.get("priority", "normal")
        
        logger.info(
            "Push notification sent",
            template=template,
            priority=priority,
            event_type=event.__class__.__name__,
            user_id=str(event.user_id) if hasattr(event, 'user_id') and event.user_id else None
        )
    
    async def _send_sms_notification(self, event, settings: dict[str, Any]) -> None:
        """Send SMS notification."""
        # TODO: Integrate with SMS service (Twilio, AWS SNS)
        await asyncio.sleep(0.1)  # Simulate SMS sending
        
        template = settings.get("template", "default")
        priority = settings.get("priority", "normal")
        
        logger.warning(
            "SMS notification sent",
            template=template,
            priority=priority,
            event_type=event.__class__.__name__,
            user_id=str(event.user_id) if hasattr(event, 'user_id') and event.user_id else None
        )
    
    async def _send_in_app_notification(self, event, settings: dict[str, Any]) -> None:
        """Send in-app notification."""
        # TODO: Integrate with in-app notification system
        await asyncio.sleep(0.02)  # Simulate in-app notification
        
        template = settings.get("template", "default")
        priority = settings.get("priority", "normal")
        
        logger.info(
            "In-app notification sent",
            template=template,
            priority=priority,
            event_type=event.__class__.__name__,
            user_id=str(event.user_id) if hasattr(event, 'user_id') and event.user_id else None
        )
    
    async def _send_webhook_notification(self, event, settings: dict[str, Any]) -> None:
        """Send webhook notification."""
        # TODO: Integrate with webhook system
        await asyncio.sleep(0.05)  # Simulate webhook call
        
        template = settings.get("template", "default")
        priority = settings.get("priority", "normal")
        
        logger.info(
            "Webhook notification sent",
            template=template,
            priority=priority,
            event_type=event.__class__.__name__
        )
    
    async def _update_notification_history(
        self, 
        user_id: UUID, 
        event_type: str, 
        notifications_sent: list[str]
    ) -> None:
        """Update user's notification history."""
        # TODO: Integrate with notification history service
        await asyncio.sleep(0.02)  # Simulate history update
        
        logger.debug(
            "Notification history updated",
            user_id=str(user_id),
            event_type=event_type,
            notifications_count=len(notifications_sent)
        )
    
    async def _track_notification_analytics(
        self, 
        event_type: str, 
        notifications_sent: list[str]
    ) -> None:
        """Track notification analytics."""
        # TODO: Integrate with analytics service
        await asyncio.sleep(0.01)  # Simulate analytics tracking
        
        logger.debug(
            "Notification analytics tracked",
            event_type=event_type,
            notifications_sent=notifications_sent
        )


# Export handler
__all__ = [
    "NotificationHandler",
]