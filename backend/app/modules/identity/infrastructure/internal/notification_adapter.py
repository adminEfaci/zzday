"""
Notification Adapter for Identity Module

Internal adapter that allows the Identity module to send notifications
to users through the Notification module.
"""

from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from app.core.infrastructure.internal_adapter_base import BaseInternalAdapter
from app.core.logging import get_logger
from app.modules.notification.application.contracts.notification_contract import (
    INotificationContract,
    NotificationRequestDTO,
    NotificationType,
    NotificationPriority,
    NotificationDTO
)

logger = get_logger(__name__)


class NotificationAdapter(BaseInternalAdapter):
    """
    Adapter for sending notifications from Identity module.
    
    This adapter provides convenient methods for the Identity module
    to send various types of notifications to users.
    """
    
    def __init__(self, notification_service: INotificationContract):
        """
        Initialize Notification adapter.
        
        Args:
            notification_service: Notification service implementation
        """
        super().__init__(module_name="identity", target_module="notification")
        self._notification_service = notification_service
    
    async def health_check(self) -> bool:
        """Check if Notification module is healthy."""
        try:
            # Try to get templates as health check
            templates = await self._notification_service.list_templates(
                active_only=True
            )
            return True
        except Exception as e:
            logger.warning(
                "Notification module health check failed",
                error=str(e)
            )
            return False
    
    async def send_welcome_email(
        self,
        user_id: UUID,
        email: str,
        first_name: Optional[str] = None,
        verification_link: Optional[str] = None
    ) -> Optional[NotificationDTO]:
        """
        Send welcome email to new user.
        
        Args:
            user_id: New user ID
            email: User email address
            first_name: User's first name
            verification_link: Email verification link
            
        Returns:
            NotificationDTO if sent successfully
        """
        try:
            template_data = {
                "email": email,
                "first_name": first_name or "User",
                "verification_link": verification_link,
                "current_year": datetime.utcnow().year
            }
            
            request = NotificationRequestDTO(
                user_id=user_id,
                notification_type=NotificationType.WELCOME,
                priority=NotificationPriority.HIGH,
                template_name="welcome_email",
                template_data=template_data,
                metadata={
                    "source": "identity.registration",
                    "email": email
                }
            )
            
            return await self._execute_with_resilience(
                "send_welcome_email",
                self._notification_service.send_notification,
                request
            )
        except Exception as e:
            logger.error(
                "Failed to send welcome email",
                user_id=str(user_id),
                email=email,
                error=str(e)
            )
            return None
    
    async def send_email_verification(
        self,
        user_id: UUID,
        email: str,
        verification_code: str,
        verification_link: str
    ) -> Optional[NotificationDTO]:
        """
        Send email verification notification.
        
        Args:
            user_id: User ID
            email: Email to verify
            verification_code: Verification code
            verification_link: Verification link
            
        Returns:
            NotificationDTO if sent successfully
        """
        try:
            template_data = {
                "email": email,
                "verification_code": verification_code,
                "verification_link": verification_link,
                "expires_in_hours": 24
            }
            
            request = NotificationRequestDTO(
                user_id=user_id,
                notification_type=NotificationType.EMAIL_VERIFICATION,
                priority=NotificationPriority.HIGH,
                template_name="email_verification",
                template_data=template_data,
                metadata={
                    "source": "identity.email_verification",
                    "email": email
                }
            )
            
            return await self._execute_with_resilience(
                "send_email_verification",
                self._notification_service.send_notification,
                request
            )
        except Exception as e:
            logger.error(
                "Failed to send email verification",
                user_id=str(user_id),
                email=email,
                error=str(e)
            )
            return None
    
    async def send_password_reset(
        self,
        user_id: UUID,
        email: str,
        reset_code: str,
        reset_link: str,
        expires_in_minutes: int = 30
    ) -> Optional[NotificationDTO]:
        """
        Send password reset notification.
        
        Args:
            user_id: User ID
            email: User email
            reset_code: Reset code
            reset_link: Reset link
            expires_in_minutes: Code expiration time
            
        Returns:
            NotificationDTO if sent successfully
        """
        try:
            template_data = {
                "email": email,
                "reset_code": reset_code,
                "reset_link": reset_link,
                "expires_in_minutes": expires_in_minutes
            }
            
            request = NotificationRequestDTO(
                user_id=user_id,
                notification_type=NotificationType.PASSWORD_RESET,
                priority=NotificationPriority.URGENT,
                template_name="password_reset",
                template_data=template_data,
                metadata={
                    "source": "identity.password_reset",
                    "email": email
                }
            )
            
            return await self._execute_with_resilience(
                "send_password_reset",
                self._notification_service.send_notification,
                request
            )
        except Exception as e:
            logger.error(
                "Failed to send password reset",
                user_id=str(user_id),
                email=email,
                error=str(e)
            )
            return None
    
    async def send_security_alert(
        self,
        user_id: UUID,
        email: str,
        alert_type: str,
        description: str,
        ip_address: Optional[str] = None,
        device_info: Optional[str] = None,
        action_required: bool = False
    ) -> Optional[NotificationDTO]:
        """
        Send security alert notification.
        
        Args:
            user_id: User ID
            email: User email
            alert_type: Type of security alert
            description: Alert description
            ip_address: IP address of event
            device_info: Device information
            action_required: Whether user action is required
            
        Returns:
            NotificationDTO if sent successfully
        """
        try:
            template_data = {
                "email": email,
                "alert_type": alert_type,
                "description": description,
                "ip_address": ip_address or "Unknown",
                "device_info": device_info or "Unknown device",
                "timestamp": datetime.utcnow().isoformat(),
                "action_required": action_required
            }
            
            request = NotificationRequestDTO(
                user_id=user_id,
                notification_type=NotificationType.SECURITY_ALERT,
                priority=NotificationPriority.URGENT,
                template_name="security_alert",
                template_data=template_data,
                metadata={
                    "source": "identity.security",
                    "alert_type": alert_type,
                    "ip_address": ip_address
                }
            )
            
            return await self._execute_with_resilience(
                "send_security_alert",
                self._notification_service.send_notification,
                request
            )
        except Exception as e:
            logger.error(
                "Failed to send security alert",
                user_id=str(user_id),
                alert_type=alert_type,
                error=str(e)
            )
            return None
    
    async def send_mfa_code(
        self,
        user_id: UUID,
        channel: str,  # "email" or "sms"
        recipient: str,  # email or phone
        code: str,
        expires_in_minutes: int = 10
    ) -> Optional[NotificationDTO]:
        """
        Send MFA code notification.
        
        Args:
            user_id: User ID
            channel: Delivery channel
            recipient: Email or phone number
            code: MFA code
            expires_in_minutes: Code expiration
            
        Returns:
            NotificationDTO if sent successfully
        """
        try:
            template_data = {
                "code": code,
                "expires_in_minutes": expires_in_minutes
            }
            
            # Use custom notification type and specify channel
            request = NotificationRequestDTO(
                user_id=user_id,
                notification_type=NotificationType.CUSTOM,
                priority=NotificationPriority.URGENT,
                channels=[channel],
                template_name=f"mfa_code_{channel}",
                template_data=template_data,
                subject="Your verification code" if channel == "email" else None,
                metadata={
                    "source": "identity.mfa",
                    "channel": channel,
                    "recipient": recipient
                }
            )
            
            return await self._execute_with_resilience(
                "send_mfa_code",
                self._notification_service.send_notification,
                request
            )
        except Exception as e:
            logger.error(
                "Failed to send MFA code",
                user_id=str(user_id),
                channel=channel,
                error=str(e)
            )
            return None
    
    async def send_account_locked(
        self,
        user_id: UUID,
        email: str,
        reason: str,
        unlock_instructions: str
    ) -> Optional[NotificationDTO]:
        """
        Send account locked notification.
        
        Args:
            user_id: User ID
            email: User email
            reason: Lock reason
            unlock_instructions: How to unlock
            
        Returns:
            NotificationDTO if sent successfully
        """
        try:
            template_data = {
                "email": email,
                "reason": reason,
                "unlock_instructions": unlock_instructions,
                "support_email": "support@ezzday.com"
            }
            
            request = NotificationRequestDTO(
                user_id=user_id,
                notification_type=NotificationType.SECURITY_ALERT,
                priority=NotificationPriority.HIGH,
                template_name="account_locked",
                template_data=template_data,
                metadata={
                    "source": "identity.account_lock",
                    "reason": reason
                }
            )
            
            return await self._execute_with_resilience(
                "send_account_locked",
                self._notification_service.send_notification,
                request
            )
        except Exception as e:
            logger.error(
                "Failed to send account locked notification",
                user_id=str(user_id),
                email=email,
                error=str(e)
            )
            return None