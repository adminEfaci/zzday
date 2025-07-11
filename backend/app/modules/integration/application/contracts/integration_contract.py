"""
Integration Module Public Contract

This module defines the public interface that other modules can use to interact
with external services through the Integration module. This ensures all external
communication goes through a single, controlled point.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field, EmailStr


class DeliveryStatus(str, Enum):
    """Delivery status for messages."""
    
    PENDING = "PENDING"
    SENT = "SENT"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    BOUNCED = "BOUNCED"


class NotificationChannel(str, Enum):
    """Supported notification channels."""
    
    EMAIL = "EMAIL"
    SMS = "SMS"
    PUSH = "PUSH"
    WEBHOOK = "WEBHOOK"


class EmailMessageDTO(BaseModel):
    """Email message DTO."""
    
    to: List[EmailStr]
    subject: str
    body_text: str
    body_html: Optional[str] = None
    from_email: Optional[EmailStr] = None
    from_name: Optional[str] = None
    reply_to: Optional[EmailStr] = None
    cc: List[EmailStr] = Field(default_factory=list)
    bcc: List[EmailStr] = Field(default_factory=list)
    attachments: List[Dict[str, Any]] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SMSMessageDTO(BaseModel):
    """SMS message DTO."""
    
    to: str  # Phone number
    body: str
    from_number: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PushNotificationDTO(BaseModel):
    """Push notification DTO."""
    
    device_tokens: List[str]
    title: str
    body: str
    data: Dict[str, Any] = Field(default_factory=dict)
    sound: Optional[str] = None
    badge: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class WebhookRequestDTO(BaseModel):
    """Webhook request DTO."""
    
    url: str
    method: str = "POST"
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 30
    retry_count: int = 3
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DeliveryResultDTO(BaseModel):
    """Result of message delivery."""
    
    id: UUID
    channel: NotificationChannel
    status: DeliveryStatus
    provider: str
    provider_message_id: Optional[str] = None
    delivered_at: Optional[datetime] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat()
        }


class ExternalServiceHealthDTO(BaseModel):
    """Health status of external service."""
    
    service_name: str
    is_healthy: bool
    last_check: datetime
    response_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GeocodeRequestDTO(BaseModel):
    """Geocoding request DTO."""
    
    address: str
    country: Optional[str] = None
    language: Optional[str] = None


class GeocodeResultDTO(BaseModel):
    """Geocoding result DTO."""
    
    formatted_address: str
    latitude: float
    longitude: float
    confidence: float
    place_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IIntegrationContract(ABC):
    """
    Public contract for Integration module.
    
    This interface defines all operations that other modules can perform
    to interact with external services through the Integration module.
    """
    
    # Email Operations
    @abstractmethod
    async def send_email(self, message: EmailMessageDTO) -> DeliveryResultDTO:
        """
        Send email through configured provider.
        
        Args:
            message: Email message to send
            
        Returns:
            DeliveryResultDTO with send result
        """
        pass
    
    @abstractmethod
    async def send_bulk_emails(
        self, 
        messages: List[EmailMessageDTO]
    ) -> List[DeliveryResultDTO]:
        """
        Send multiple emails in batch.
        
        Args:
            messages: List of email messages
            
        Returns:
            List of DeliveryResultDTO
        """
        pass
    
    # SMS Operations
    @abstractmethod
    async def send_sms(self, message: SMSMessageDTO) -> DeliveryResultDTO:
        """
        Send SMS through configured provider.
        
        Args:
            message: SMS message to send
            
        Returns:
            DeliveryResultDTO with send result
        """
        pass
    
    # Push Notification Operations
    @abstractmethod
    async def send_push_notification(
        self, 
        notification: PushNotificationDTO
    ) -> DeliveryResultDTO:
        """
        Send push notification through configured provider.
        
        Args:
            notification: Push notification to send
            
        Returns:
            DeliveryResultDTO with send result
        """
        pass
    
    # Webhook Operations
    @abstractmethod
    async def send_webhook(self, request: WebhookRequestDTO) -> DeliveryResultDTO:
        """
        Send webhook request to external endpoint.
        
        Args:
            request: Webhook request details
            
        Returns:
            DeliveryResultDTO with send result
        """
        pass
    
    # Geocoding Operations
    @abstractmethod
    async def geocode_address(
        self, 
        request: GeocodeRequestDTO
    ) -> Optional[GeocodeResultDTO]:
        """
        Geocode address to coordinates.
        
        Args:
            request: Geocoding request
            
        Returns:
            GeocodeResultDTO if successful, None otherwise
        """
        pass
    
    @abstractmethod
    async def reverse_geocode(
        self, 
        latitude: float, 
        longitude: float
    ) -> Optional[GeocodeResultDTO]:
        """
        Reverse geocode coordinates to address.
        
        Args:
            latitude: Latitude coordinate
            longitude: Longitude coordinate
            
        Returns:
            GeocodeResultDTO if successful, None otherwise
        """
        pass
    
    # Status and Health Operations
    @abstractmethod
    async def get_delivery_status(
        self, 
        delivery_id: UUID
    ) -> Optional[DeliveryResultDTO]:
        """
        Get status of previous delivery.
        
        Args:
            delivery_id: ID of delivery to check
            
        Returns:
            DeliveryResultDTO if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def check_external_service_health(
        self, 
        service_name: str
    ) -> ExternalServiceHealthDTO:
        """
        Check health of external service.
        
        Args:
            service_name: Name of service to check
            
        Returns:
            ExternalServiceHealthDTO with health status
        """
        pass
    
    @abstractmethod
    async def get_available_services(self) -> List[str]:
        """
        Get list of available external services.
        
        Returns:
            List of service names
        """
        pass
    
    # Template Operations
    @abstractmethod
    async def render_email_template(
        self,
        template_name: str,
        context: Dict[str, Any],
        language: str = "en"
    ) -> Dict[str, str]:
        """
        Render email template with context.
        
        Args:
            template_name: Name of template
            context: Template context variables
            language: Language code
            
        Returns:
            Dict with 'subject' and 'body' keys
        """
        pass