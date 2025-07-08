"""
Notification Domain Service

Implements notification operations for the identity module using existing utilities.
"""

from datetime import datetime
from typing import Any

from app.core.security import generate_token
from app.utils.crypto import mask_sensitive_data
from app.utils.text import normalize_whitespace
from app.utils.validation import validate_email, validate_phone

from ...interfaces.contracts.audit_contract import IAuditContract
from ...interfaces.contracts.notification_contract import INotificationContract
from ...interfaces.services.communication.notification_service import (
    INotificationService,
)
from ...interfaces.services.infrastructure.cache_port import ICachePort
from ...interfaces.services.infrastructure.configuration_port import IConfigurationPort
from ...interfaces.services.infrastructure.task_queue_port import ITaskQueuePort


class NotificationService(INotificationService):
    """Domain service for notification operations."""
    
    def __init__(
        self,
        notification_contract: INotificationContract,
        audit_contract: IAuditContract,
        cache_port: ICachePort,
        configuration_port: IConfigurationPort,
        task_queue_port: ITaskQueuePort
    ) -> None:
        self._notification_contract = notification_contract
        self._audit_contract = audit_contract
        self._cache = cache_port
        self._config = configuration_port
        self._task_queue = task_queue_port
        self._rate_limits = self._initialize_rate_limits()
    
    async def send_email(
        self,
        to: str,
        subject: str,
        template: str,
        data: dict[str, Any],
        priority: str = "normal"
    ) -> str:
        """Send email notification."""
        
        # Validate inputs using utility
        if not validate_email(to):
            raise ValueError("Invalid email address")
        
        if not subject or not template:
            raise ValueError("Subject and template are required")
        
        # Check rate limits
        if not await self._check_rate_limit("email", to):
            raise ValueError("Rate limit exceeded for recipient")
        
        # Generate message ID
        message_id = generate_token(16)
        
        # Sanitize and prepare data
        sanitized_data = self._sanitize_template_data(data)
        
        # Prepare email payload
        {
            "message_id": message_id,
            "to": to,
            "subject": normalize_whitespace(subject),
            "template": template,
            "data": sanitized_data,
            "priority": priority,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Send via notification contract
        await self._notification_contract.send_email(
            email_address=to,
            subject=subject,
            template=template,
            data=sanitized_data
        )
        
        # Update rate limit counter
        await self._update_rate_limit("email", to)
        
        # Log email sent
        await self._audit_contract.log_event(
            event_type="email_notification_sent",
            user_id=data.get("user_id"),
            details={
                "message_id": message_id,
                "recipient_masked": mask_sensitive_data(to, 4),
                "template": template,
                "priority": priority
            }
        )
        
        return message_id
    
    async def send_sms(
        self,
        phone: str,
        message: str,
        template: str | None = None
    ) -> str:
        """Send SMS notification."""
        
        # Validate inputs
        if not validate_phone(phone):
            raise ValueError("Invalid phone number")
        
        if not message:
            raise ValueError("Message is required")
        
        # Check rate limits
        if not await self._check_rate_limit("sms", phone):
            raise ValueError("Rate limit exceeded for recipient")
        
        # Generate message ID
        message_id = generate_token(16)
        
        # Send via notification contract
        await self._notification_contract.send_sms(
            phone_number=phone,
            message=normalize_whitespace(message)
        )
        
        # Update rate limit counter
        await self._update_rate_limit("sms", phone)
        
        # Log SMS sent
        await self._audit_contract.log_event(
            event_type="sms_notification_sent",
            user_id=None,  # Would need to be passed in or looked up
            details={
                "message_id": message_id,
                "recipient_masked": mask_sensitive_data(phone, 4),
                "template": template,
                "message_length": len(message)
            }
        )
        
        return message_id
    
    async def send_push_notification(
        self,
        device_tokens: str | list[str],
        title: str,
        body: str,
        data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send push notification."""
        
        # Validate inputs
        if not device_tokens:
            raise ValueError("Device tokens are required")
        
        if not title or not body:
            raise ValueError("Title and body are required")
        
        # Normalize to list
        tokens = [device_tokens] if isinstance(device_tokens, str) else device_tokens
        
        # Generate message ID
        message_id = generate_token(16)
        
        # Prepare notification payload
        {
            "message_id": message_id,
            "device_tokens": tokens,
            "title": normalize_whitespace(title),
            "body": normalize_whitespace(body),
            "data": data or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Send via notification contract
        await self._notification_contract.send_push_notification(
            device_tokens=tokens,
            title=title,
            body=body,
            data=data
        )
        
        # Log push notification sent
        await self._audit_contract.log_event(
            event_type="push_notification_sent",
            user_id=data.get("user_id") if data else None,
            details={
                "message_id": message_id,
                "device_count": len(tokens),
                "title": title
            }
        )
        
        return {
            "message_id": message_id,
            "device_count": len(tokens),
            "sent_at": datetime.utcnow().isoformat(),
            "status": "sent"
        }
    
    async def send_bulk_email(
        self,
        recipients: list[dict[str, Any]],
        template: str,
        common_data: dict[str, Any] | None = None
    ) -> str:
        """Send bulk email."""
        
        # Validate inputs
        if not recipients or not template:
            raise ValueError("Recipients and template are required")
        
        # Validate all recipient emails
        for recipient in recipients:
            email = recipient.get("email")
            if not email or not validate_email(email):
                raise ValueError(f"Invalid email in recipient: {email}")
        
        # Generate batch ID
        batch_id = generate_token(16)
        
        # Prepare batch data
        batch_data = {
            "batch_id": batch_id,
            "template": template,
            "common_data": common_data or {},
            "recipients": recipients,
            "created_at": datetime.utcnow().isoformat(),
            "status": "queued"
        }
        
        # Queue bulk email task
        await self._task_queue.schedule_task(
            task_type="bulk_email",
            payload=batch_data
        )
        
        # Log bulk email queued
        await self._audit_contract.log_event(
            event_type="bulk_email_queued",
            user_id=None,
            details={
                "batch_id": batch_id,
                "template": template,
                "recipient_count": len(recipients)
            }
        )
        
        return batch_id
    
    async def get_delivery_status(self, message_id: str) -> dict[str, Any]:
        """Get message delivery status."""
        
        if not message_id:
            raise ValueError("Message ID is required")
        
        # Check cache for delivery status
        cache_key = f"delivery_status:{message_id}"
        status = await self._cache.get(cache_key)
        
        if status:
            return status
        
        # Default status if not found
        return {
            "message_id": message_id,
            "status": "unknown",
            "delivered_at": None,
            "error_message": None,
            "attempts": 0
        }
        
    
    async def handle_delivery_webhook(
        self,
        provider: str,
        webhook_data: dict[str, Any]
    ) -> bool:
        """Handle delivery status webhook."""
        
        if not provider or not webhook_data:
            return False
        
        try:
            # Extract message ID from webhook data
            message_id = webhook_data.get("message_id")
            if not message_id:
                return False
            
            # Update delivery status in cache
            status_data = {
                "message_id": message_id,
                "status": webhook_data.get("status", "unknown"),
                "delivered_at": webhook_data.get("delivered_at"),
                "error_message": webhook_data.get("error_message"),
                "provider": provider,
                "updated_at": datetime.utcnow().isoformat()
            }
            
            cache_key = f"delivery_status:{message_id}"
            await self._cache.set(cache_key, status_data, expiry_seconds=86400)  # 24 hours
            
            # Log webhook received
            await self._audit_contract.log_event(
                event_type="delivery_webhook_received",
                user_id=None,
                details={
                    "provider": provider,
                    "message_id": message_id,
                    "status": status_data["status"]
                }
            )
            
            return True
            
        except Exception:
            return False
    
    # Private helper methods
    
    async def _check_rate_limit(self, notification_type: str, recipient: str) -> bool:
        """Check if recipient is within rate limits."""
        limit_key = f"rate_limit:{notification_type}:{recipient}"
        current_count = await self._cache.get(limit_key) or 0
        
        limits = self._rate_limits.get(notification_type, {})
        max_per_hour = limits.get("max_per_hour", 60)
        
        return current_count < max_per_hour
    
    async def _update_rate_limit(self, notification_type: str, recipient: str) -> None:
        """Update rate limit counter for recipient."""
        limit_key = f"rate_limit:{notification_type}:{recipient}"
        current_count = await self._cache.get(limit_key) or 0
        
        await self._cache.set(
            limit_key, 
            current_count + 1, 
            expiry_seconds=3600  # 1 hour
        )
    
    def _sanitize_template_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Sanitize template data by removing/masking sensitive fields."""
        sanitized = {}
        
        for key, value in data.items():
            if key.lower() in ["password", "token", "secret", "api_key"]:
                sanitized[key] = "[REDACTED]"
            elif key.lower() in ["phone", "email"]:
                if isinstance(value, str):
                    sanitized[key] = mask_sensitive_data(value, 4)
                else:
                    sanitized[key] = value
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _initialize_rate_limits(self) -> dict[str, dict[str, int]]:
        """Initialize rate limit configurations."""
        return {
            "email": {
                "max_per_hour": 60,
                "max_per_day": 200
            },
            "sms": {
                "max_per_hour": 10,
                "max_per_day": 50
            },
            "push": {
                "max_per_hour": 100,
                "max_per_day": 500
            }
        }