"""
Integration Adapter for Notification Module

Internal adapter that allows the Notification module to send messages
through external services via the Integration module. This ensures
all external communication goes through the Integration module.
"""

from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from app.core.infrastructure.internal_adapter_base import (
    BaseInternalAdapter,
    InternalAdapterError
)
from app.core.logging import get_logger
from app.modules.integration.application.contracts.integration_contract import (
    IIntegrationContract,
    EmailMessageDTO,
    SMSMessageDTO,
    PushNotificationDTO,
    DeliveryResultDTO,
    DeliveryStatus,
    NotificationChannel
)

logger = get_logger(__name__)


class IntegrationAdapter(BaseInternalAdapter):
    """
    Adapter for sending notifications through Integration module.
    
    This adapter handles all external communication for the Notification
    module, ensuring proper module boundaries and centralized external
    service management.
    """
    
    def __init__(self, integration_service: IIntegrationContract):
        """
        Initialize Integration adapter.
        
        Args:
            integration_service: Integration service implementation
        """
        super().__init__(module_name="notification", target_module="integration")
        self._integration_service = integration_service
    
    async def health_check(self) -> bool:
        """Check if Integration module is healthy."""
        try:
            # Check if we can get available services
            services = await self._integration_service.get_available_services()
            return len(services) > 0
        except Exception as e:
            logger.warning(
                "Integration module health check failed",
                error=str(e)
            )
            return False
    
    async def send_email(
        self,
        to_addresses: List[str],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> DeliveryResultDTO:
        """
        Send email notification.
        
        Args:
            to_addresses: List of recipient email addresses
            subject: Email subject
            body_text: Plain text body
            body_html: Optional HTML body
            from_email: Sender email address
            from_name: Sender display name
            reply_to: Reply-to address
            attachments: Optional attachments
            tags: Optional tags for tracking
            metadata: Optional metadata
            
        Returns:
            DeliveryResultDTO with send result
        """
        message = EmailMessageDTO(
            to=to_addresses,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            from_email=from_email,
            from_name=from_name,
            reply_to=reply_to,
            attachments=attachments or [],
            tags=tags or [],
            metadata=metadata or {}
        )
        
        return await self._execute_with_resilience(
            "send_email",
            self._integration_service.send_email,
            message
        )
    
    async def send_bulk_emails(
        self,
        messages: List[Dict[str, Any]]
    ) -> List[DeliveryResultDTO]:
        """
        Send multiple emails in batch.
        
        Args:
            messages: List of email message dictionaries
            
        Returns:
            List of DeliveryResultDTO
        """
        # Convert to DTOs
        email_dtos = []
        for msg in messages:
            email_dto = EmailMessageDTO(
                to=msg["to"],
                subject=msg["subject"],
                body_text=msg["body_text"],
                body_html=msg.get("body_html"),
                from_email=msg.get("from_email"),
                from_name=msg.get("from_name"),
                reply_to=msg.get("reply_to"),
                attachments=msg.get("attachments", []),
                tags=msg.get("tags", []),
                metadata=msg.get("metadata", {})
            )
            email_dtos.append(email_dto)
        
        return await self._execute_with_resilience(
            "send_bulk_emails",
            self._integration_service.send_bulk_emails,
            email_dtos
        )
    
    async def send_sms(
        self,
        phone_number: str,
        message: str,
        from_number: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> DeliveryResultDTO:
        """
        Send SMS notification.
        
        Args:
            phone_number: Recipient phone number
            message: SMS message text
            from_number: Optional sender number
            metadata: Optional metadata
            
        Returns:
            DeliveryResultDTO with send result
        """
        sms_message = SMSMessageDTO(
            to=phone_number,
            body=message,
            from_number=from_number,
            metadata=metadata or {}
        )
        
        return await self._execute_with_resilience(
            "send_sms",
            self._integration_service.send_sms,
            sms_message
        )
    
    async def send_push_notification(
        self,
        device_tokens: List[str],
        title: str,
        body: str,
        data: Optional[Dict[str, Any]] = None,
        sound: Optional[str] = None,
        badge: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> DeliveryResultDTO:
        """
        Send push notification.
        
        Args:
            device_tokens: List of device tokens
            title: Notification title
            body: Notification body
            data: Optional data payload
            sound: Optional sound identifier
            badge: Optional badge number
            metadata: Optional metadata
            
        Returns:
            DeliveryResultDTO with send result
        """
        notification = PushNotificationDTO(
            device_tokens=device_tokens,
            title=title,
            body=body,
            data=data or {},
            sound=sound,
            badge=badge,
            metadata=metadata or {}
        )
        
        return await self._execute_with_resilience(
            "send_push_notification",
            self._integration_service.send_push_notification,
            notification
        )
    
    async def render_email_template(
        self,
        template_name: str,
        context: Dict[str, Any],
        language: str = "en"
    ) -> Dict[str, str]:
        """
        Render email template.
        
        Args:
            template_name: Template identifier
            context: Template context variables
            language: Language code
            
        Returns:
            Dict with 'subject' and 'body' keys
        """
        return await self._execute_with_resilience(
            "render_email_template",
            self._integration_service.render_email_template,
            template_name,
            context,
            language
        )
    
    async def check_delivery_status(
        self,
        delivery_id: UUID
    ) -> Optional[DeliveryResultDTO]:
        """
        Check status of previous delivery.
        
        Args:
            delivery_id: ID of delivery to check
            
        Returns:
            DeliveryResultDTO if found
        """
        return await self._execute_with_resilience(
            "check_delivery_status",
            self._integration_service.get_delivery_status,
            delivery_id
        )
    
    async def is_channel_available(
        self,
        channel: NotificationChannel
    ) -> bool:
        """
        Check if notification channel is available.
        
        Args:
            channel: Channel to check
            
        Returns:
            True if channel is available
        """
        try:
            # Map channels to service names
            service_map = {
                NotificationChannel.EMAIL: "email",
                NotificationChannel.SMS: "sms",
                NotificationChannel.PUSH: "push",
                NotificationChannel.WEBHOOK: "webhook"
            }
            
            service_name = service_map.get(channel, channel.value.lower())
            health = await self._integration_service.check_external_service_health(service_name)
            
            return health.is_healthy
        except Exception as e:
            logger.warning(
                "Failed to check channel availability",
                channel=channel.value,
                error=str(e)
            )
            return False
    
    async def send_notification(
        self,
        channel: NotificationChannel,
        recipient: str,
        content: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> DeliveryResultDTO:
        """
        Send notification through specified channel.
        
        This is a convenience method that routes to the appropriate
        channel-specific method.
        
        Args:
            channel: Notification channel
            recipient: Recipient identifier
            content: Channel-specific content
            metadata: Optional metadata
            
        Returns:
            DeliveryResultDTO with send result
        """
        if channel == NotificationChannel.EMAIL:
            return await self.send_email(
                to_addresses=[recipient],
                subject=content.get("subject", ""),
                body_text=content.get("body_text", ""),
                body_html=content.get("body_html"),
                metadata=metadata
            )
        
        elif channel == NotificationChannel.SMS:
            return await self.send_sms(
                phone_number=recipient,
                message=content.get("message", ""),
                metadata=metadata
            )
        
        elif channel == NotificationChannel.PUSH:
            return await self.send_push_notification(
                device_tokens=[recipient],
                title=content.get("title", ""),
                body=content.get("body", ""),
                data=content.get("data"),
                metadata=metadata
            )
        
        else:
            raise InternalAdapterError(
                f"Unsupported notification channel: {channel.value}"
            )